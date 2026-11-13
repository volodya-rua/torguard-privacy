#!/usr/bin/env python3
"""
tor ip rotator
==============
gives every site its own tor circuit and lets the extension get fresh ones.

tor never lets streams from different SocksPorts share a circuit, so this keeps SLOTS extra
SocksPorts open and the extension sends each site to one of them. rotating swaps in brand new
port numbers, so chrome (it pools connections per proxy port) and tor (new isolation groups)
both have to start over and the ip actually changes. the old version just sent NEWNYM and chrome
kept using its old connection, so the ip never changed lol

errors come back as {"status": "error", "code": ..., "message": ..., "detail": ...} so the
extension can say what's wrong and what to do
"""

import json
import random
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import requests
from stem import SocketError
from stem.connection import AuthenticationFailure
from stem.control import Controller

TOR_CONTROL_PORT = 9051
TOR_SOCKS_PORT = 9050               # always open, the extension falls back to it
SLOTS = 16                          # must match TOR_SLOTS in site.js
SLOT_PORTS = range(19100, 20000)    # extra SocksPorts this thing owns
CF_TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
ROTATOR_PORT = 8222  # local api port the extension calls
HOST_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9-]+(\.[a-z0-9-]+)+$", re.I)


class TorError(Exception):
    def __init__(self, code, message, status=503, detail=""):
        super().__init__(message)
        self.code, self.message, self.status, self.detail = code, message, status, detail


def explain(e):
    """turn any error into a TorError the extension can show."""
    if isinstance(e, TorError):
        return e
    detail = f"{type(e).__name__}: {e}"
    if isinstance(e, AuthenticationFailure):
        return TorError("tor_auth_failed", "Tor refused the rotator's login (cookie authentication).", detail=detail)
    if isinstance(e, (SocketError, ConnectionRefusedError)):
        return TorError("tor_control_unreachable", f"Can't reach Tor on port {TOR_CONTROL_PORT}. Is it running?", detail=detail)
    if isinstance(e, (requests.exceptions.Timeout, socket.timeout, TimeoutError)):
        return TorError("timeout", "Tor took too long to answer. It may still be building circuits.", 504, detail)
    if isinstance(e, (requests.exceptions.ConnectionError, OSError)):
        return TorError("tor_unreachable", "Couldn't get a connection through Tor. Try again in a moment.", detail=detail)
    return TorError("internal", "Unexpected error in the rotator.", 500, detail)


def tor_trace(port):
    """cloudflare trace through a tor SocksPort = the exit ip sites on that slot see."""
    proxy = f"socks5h://127.0.0.1:{port}"
    resp = requests.get(CF_TRACE_URL, proxies={"http": proxy, "https": proxy}, timeout=20)
    return dict(line.split("=", 1) for line in resp.text.splitlines() if "=" in line)


def warm_up(ports):
    """a brand new port's first connection sometimes lands on a different circuit than the ones
    after it (no idea why tor does that). so burn that first connection here, then the ip we report
    is the one the browser actually gets, and every site's circuit is ready before its first page load."""
    def touch(port):
        try:
            tor_trace(port)
        except Exception:
            pass  # the real request after this reports any problem
    with ThreadPoolExecutor(max(1, len(ports))) as pool:
        list(pool.map(touch, ports))


def _port(value):
    """'127.0.0.1:19123 IsolateDestAddr' -> 19123; None for unix sockets / 'auto'."""
    try:
        return int(value.split()[0].rsplit(":", 1)[-1])
    except ValueError:
        return None


def slot_ports(ctrl, fresh=False, only=None):
    """the SLOTS extra SocksPorts in slot order, makes them if missing.
    fresh=True replaces all of them, only=N replaces just slot N (other sites keep their circuits).
    order matters (slot N = Nth port) and tor keeps the SocksPort lines in the order we set them."""
    current = ctrl.get_conf("SocksPort", multiple=True)
    ours = [p for p in map(_port, current) if p in SLOT_PORTS]
    if len(ours) == SLOTS and not fresh and only is None:
        return ours
    keep = [v for v in current if _port(v) not in SLOT_PORTS]
    if TOR_SOCKS_PORT not in map(_port, keep):
        keep.append(f"127.0.0.1:{TOR_SOCKS_PORT}")
    for attempt in range(3):  # a random port might already be taken by some other program
        free = [p for p in SLOT_PORTS if p not in ours]
        if only is not None and len(ours) == SLOTS:
            new = list(ours)
            new[only] = random.choice(free)
        else:
            new = sorted(random.sample(free, SLOTS))
        try:
            ctrl.set_conf("SocksPort", keep + [f"127.0.0.1:{p}" for p in new])
            warm_up([p for p in new if p not in ours])
            return new
        except Exception as e:
            if attempt == 2:
                raise TorError("ports_unavailable", "Tor couldn't open its per-site ports.", detail=str(e)) from e


def controller():
    ctrl = Controller.from_port(port=TOR_CONTROL_PORT)
    ctrl.authenticate()  # cookie auth
    progress = re.search(r"PROGRESS=(\d+)", ctrl.get_info("status/bootstrap-phase", ""))
    if progress and int(progress.group(1)) < 100:
        ctrl.close()
        raise TorError("tor_starting", f"Tor is still starting ({progress.group(1)}%).")
    return ctrl


def has_geoip(ctrl):
    return ctrl.get_info("ip-to-country/ipv4-available", "0") == "1"


def locate(ctrl, info):
    """cloudflare says T1 for every tor exit (useless), so ask tor's own geoip where the exit is."""
    ip, loc = info.get("ip"), info.get("loc", "??")
    if ip and has_geoip(ctrl):
        try:
            return ctrl.get_info(f"ip-to-country/{ip}").upper()
        except Exception:
            pass
    return "??" if loc == "T1" else loc


def exit_country(ctrl):
    """'any', a two letter country code, or 'custom' if ExitNodes got set some other way."""
    nodes = (ctrl.get_conf("ExitNodes", "") or "").strip().lower()
    match = re.fullmatch(r"\{([a-z]{2})\}", nodes)
    return match.group(1) if match else ("any" if not nodes else "custom")


def status(q):
    slot = q.slot()
    with controller() as ctrl:
        ports = slot_ports(ctrl)
        country, geoip = exit_country(ctrl), has_geoip(ctrl)
        info = tor_trace(ports[slot])
        location = locate(ctrl, info)
    return {"current_ip": info.get("ip", "unknown"), "location": location, "ports": ports,
            "exit_country": country, "geoip": geoip}


def rotate(q):
    """scope=site: new circuit for just one site. scope=all: new circuits for every site."""
    slot, scope = q.slot(), q.scope()
    with controller() as ctrl:
        old_ip = tor_trace(slot_ports(ctrl)[slot]).get("ip")
        # no NEWNYM: fresh ports already = fresh circuits, and tor delays repeat NEWNYMs by up to
        # 10s which swapped the circuit AGAIN right after we reported the new ip. what the hell tor
        for _ in range(3):  # tor can randomly pick the same exit again, retry if so
            ports = slot_ports(ctrl, fresh=scope == "all", only=slot if scope == "site" else None)
            info = tor_trace(ports[slot])
            if info.get("ip") != old_ip:
                break
        location = locate(ctrl, info)
    return {
        "status": "success",
        "scope": scope,
        "changed": info.get("ip") != old_ip,
        "old_ip": old_ip,
        "new_ip": info.get("ip", "unknown"),
        "location": location,
        "ports": ports,
    }


def set_exit(q):
    """only use exits in one country ('any' = tor picks normally). rolls back if it cant connect."""
    country, slot = q.country(), q.slot()
    with controller() as ctrl:
        before = ctrl.get_conf("ExitNodes", "") or ""
        if country == "any":
            ctrl.reset_conf("ExitNodes")
        else:
            if not has_geoip(ctrl):
                raise TorError("no_geoip", "Your Tor has no country data (geoip file), so it can't pick exits by country.", 409)
            ctrl.set_conf("ExitNodes", f"{{{country}}}")
        ports = slot_ports(ctrl, fresh=True)  # old circuits might still exit somewhere else
        try:
            info = tor_trace(ports[slot])
        except Exception as e:
            if before:
                ctrl.set_conf("ExitNodes", before)
            else:
                ctrl.reset_conf("ExitNodes")
            err = explain(e)
            raise TorError("exit_failed", f"Couldn't connect through {country.upper()}, so the previous setting was kept.", err.status, err.detail) from e
        location = locate(ctrl, info)
    return {"status": "success", "country": country, "new_ip": info.get("ip", "unknown"), "location": location, "ports": ports}


def ping(q):
    """round trip through a site's tor circuit using tor's SOCKS RESOLVE thing: the exit just
    looks up the name, so the site itself never gets contacted (didnt want to spam sites)."""
    port, host = q.port(), q.host()
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=15)
    except ConnectionRefusedError as e:
        raise TorError("tor_unreachable", f"Nothing is listening on Tor port {port}. Is Tor running?", detail=str(e)) from e
    with s:
        s.settimeout(15)
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            raise TorError("tor_unreachable", f"Port {port} isn't a Tor SOCKS port.")
        name = host.encode()
        start = time.perf_counter()
        s.sendall(b"\x05\xf0\x00\x03" + bytes([len(name)]) + name + b"\x00\x00")
        reply = s.recv(262)
        ms = (time.perf_counter() - start) * 1000
    if len(reply) < 2 or reply[1] != 0:
        raise TorError("ping_failed", "The Tor exit didn't answer.", 502, f"SOCKS reply {reply[:2].hex()}")
    return {"ms": round(ms), "port": port}


class Query:
    """checks the query params, bad input = a 400 instead of crashing."""

    def __init__(self, query):
        self.q = parse_qs(query)

    def _get(self, name, default):
        return self.q.get(name, [default])[0]

    def slot(self):
        try:
            return int(self._get("slot", "0")) % SLOTS
        except ValueError:
            raise TorError("bad_request", "slot must be a number", 400)

    def port(self):
        try:
            port = int(self._get("port", str(TOR_SOCKS_PORT)))
        except ValueError:
            raise TorError("bad_request", "port must be a number", 400)
        if port != TOR_SOCKS_PORT and port not in SLOT_PORTS:
            raise TorError("bad_request", "port isn't one of the rotator's Tor ports", 400)
        return port

    def host(self):
        host = self._get("host", "www.cloudflare.com")
        if not HOST_RE.match(host):
            raise TorError("bad_request", "host must be a domain name", 400)
        return host

    def scope(self):
        scope = self._get("scope", "all")
        if scope not in ("site", "all"):
            raise TorError("bad_request", "scope must be 'site' or 'all'", 400)
        return scope

    def country(self):
        country = self._get("country", "any").lower()
        if country != "any" and not re.fullmatch(r"[a-z]{2}", country):
            raise TorError("bad_request", "country must be a two-letter code or 'any'", 400)
        return country


ROUTES = {"/status": status, "/rotate": rotate, "/ping": ping, "/exit": set_exit}


class RotationHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress default logging

    def do_GET(self):
        url = urlparse(self.path)
        route = ROUTES.get(url.path)
        if not route:
            return self._send_json(404, {"status": "error", "code": "not_found", "message": "Not found"})
        try:
            self._send_json(200, route(Query(url.query)))
        except Exception as e:
            err = explain(e)
            if err.code == "internal":
                print(f"[!] {url.path}: {err.detail}")
            self._send_json(err.status, {"status": "error", "code": err.code, "message": err.message, "detail": err.detail})

    def _send_json(self, code, data):
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode())
        except (BrokenPipeError, ConnectionResetError):
            pass  # popup closed before we answered


if __name__ == "__main__":
    print(f"[+] Tor IP Rotator API starting on port {ROTATOR_PORT}")
    print("[+] Endpoints:")
    print(f"    GET http://127.0.0.1:{ROTATOR_PORT}/status?slot=N       -> exit IP a site on slot N sees")
    print(f"    GET http://127.0.0.1:{ROTATOR_PORT}/rotate?slot=N&scope=site|all -> new circuit(s)")
    print(f"    GET http://127.0.0.1:{ROTATOR_PORT}/ping?port=P&host=H  -> round trip through that circuit")
    print(f"    GET http://127.0.0.1:{ROTATOR_PORT}/exit?country=de|any -> only use exits in one country")

    try:
        server = ThreadingHTTPServer(("127.0.0.1", ROTATOR_PORT), RotationHandler)
    except OSError as e:
        raise SystemExit(f"[X] Can't listen on port {ROTATOR_PORT} ({e}). Is the rotator already running?")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Rotator stopped")
        server.shutdown()
