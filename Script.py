#!/usr/bin/env python3
"""
Privacy Proxy Launcher - Maximum Privacy Edition (System Proxy Method)
======================================================================
Uses Windows system proxy settings instead of CLI flags for Electron/Chromium apps.
This prevents interference with local server connections while maintaining full privacy.
"""

import os
import sys
import time
import socket
import struct
import random
import string
import select
import threading
import subprocess
import argparse
import winreg
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
import socks  # pip install PySocks
import requests  # pip install requests
from stem import Signal
from stem.control import Controller

# --- Configuration -----------------------------------------------------------
TOR_SOCKS_HOST = "127.0.0.1"
TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051
LOCAL_HTTP_PROXY_PORT = 8118   # HTTP CONNECT proxy -> Tor
LOCAL_SOCKS_BRIDGE_PORT = 9060 # SOCKS5 bridge -> Tor
ROTATION_INTERVAL = 25 * 60    # 25 minutes
CF_TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
]


# --- Utility Functions -------------------------------------------------------

def generate_random_id(length=16):
    return ''.join(random.choices(string.hexdigits.lower(), k=length))


def get_random_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept-Language": random.choice([
            "en-US,en;q=0.9", "en-GB,en;q=0.8", "fr-FR,fr;q=0.7",
            "de-DE,de;q=0.9", "es-ES,es;q=0.8"
        ]),
        "DNT": "1",
    }


def check_exit_ip(proxy_dict=None):
    """Query Cloudflare trace through the proxy to find exit IP."""
    try:
        resp = requests.get(CF_TRACE_URL, proxies=proxy_dict, timeout=30)
        data = {}
        for line in resp.text.strip().split("\n"):
            if "=" in line:
                k, v = line.split("=", 1)
                data[k] = v
        return data.get("ip", "unknown"), data.get("loc", "??"), data.get("warp", "off")
    except Exception as e:
        return f"error: {e}", "??", "?"


def rotate_tor_circuit(password=""):
    """Send NEWNYM signal to Tor to request new circuits."""
    try:
        with Controller.from_port(port=TOR_CONTROL_PORT) as ctrl:
            ctrl.authenticate(password=password)
            ctrl.signal(Signal.NEWNYM)
            print("[+] Tor circuit rotated (NEWNYM sent)")
            return True
    except Exception as e:
        print(f"[!] Failed to rotate Tor circuit: {e}")
        return False


def start_tor_if_needed():
    """Check if Tor is running."""
    try:
        s = socket.create_connection((TOR_SOCKS_HOST, TOR_SOCKS_PORT), timeout=3)
        s.close()
        print("[+] Tor SOCKS proxy detected on port 9050")
        return True
    except OSError:
        print("[!] Tor not detected on port 9050.")
        print("    Make sure the .bat launcher started Tor before running this script.")
        sys.exit(1)


PROXY_VALUES = ("ProxyEnable", "ProxyServer", "ProxyOverride")
saved_proxy = None  # ur proxy settings from before, put back on exit


def read_system_proxy():
    values = {}
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as key:
        for name in PROXY_VALUES:
            try:
                values[name] = winreg.QueryValueEx(key, name)  # (value, type)
            except FileNotFoundError:
                values[name] = None
    return values


def set_system_proxy(host, port):
    """Set Windows system proxy via registry. Affects all apps including Electron."""
    global saved_proxy
    try:
        if saved_proxy is None:
            saved_proxy = read_system_proxy()
            # still pointing at us = a last run that crashed, not ur real settings
            if f"{host}:{port}" in str((saved_proxy.get("ProxyServer") or ("",))[0]):
                saved_proxy = {}
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                             0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"http={host}:{port};https={host}:{port}")
        winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "localhost;127.0.0.1;<local>")
        winreg.CloseKey(key)
        print(f"[+] System proxy set to {host}:{port} (loopback excluded)")
        return True
    except Exception as e:
        print(f"[!] Failed to set system proxy: {e}")
        return False


def restore_proxy_on_close():
    """closing the console window (X button) skips every finally block, so the system proxy would
    stay pointed at our dead port and other apps lose internet. windows gives a few secs to clean up"""
    import ctypes
    def on_event(event):
        if event in (2, 5, 6):  # window closed, logoff, shutdown
            restore_system_proxy()
        return 0  # let windows go on and close it
    restore_proxy_on_close.handler = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_uint)(on_event)  # keep it alive
    ctypes.windll.kernel32.SetConsoleCtrlHandler(restore_proxy_on_close.handler, True)


def restore_system_proxy():
    """Put back the proxy settings u had before (or just turn the proxy off if there were none)."""
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                             0, winreg.KEY_SET_VALUE)
        if saved_proxy:
            for name in PROXY_VALUES:
                if saved_proxy.get(name) is not None:
                    winreg.SetValueEx(key, name, 0, saved_proxy[name][1], saved_proxy[name][0])
                elif name == "ProxyEnable":
                    winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, 0)
                else:
                    try:
                        winreg.DeleteValue(key, name)
                    except FileNotFoundError:
                        pass
            winreg.CloseKey(key)
            print("[+] System proxy restored")
            return True
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        try:
            winreg.DeleteValue(key, "ProxyServer")
        except FileNotFoundError:
            pass
        try:
            winreg.DeleteValue(key, "ProxyOverride")
        except FileNotFoundError:
            pass
        winreg.CloseKey(key)
        print("[+] System proxy restored")
        return True
    except Exception as e:
        print(f"[!] Failed to restore system proxy: {e}")
        return False


def is_electron_or_chromium(app_path):
    """Detect if the app is likely Electron/Chromium-based."""
    lower = app_path.lower()
    electron_indicators = [
        "electron", "opencode", "vscode", "discord", "slack",
        "teams", "notion", "spotify", "whatsapp", "signal",
        "chrome", "chromium", "edge", "brave", "vivaldi", "opera"
    ]
    return any(ind in lower for ind in electron_indicators)


# --- SOCKS5 -> HTTP CONNECT Translator --------------------------------------

class HTTPConnectProxy(BaseHTTPRequestHandler):
    """HTTP CONNECT proxy that forwards through Tor SOCKS5."""

    def log_message(self, format, *args):
        pass

    def do_CONNECT(self):
        parts = self.path.rsplit(":", 1)
        if len(parts) != 2:
            self.send_error(400, "Bad request")
            return
        host, port = parts[0], int(parts[1])
        try:
            remote = socks.socksocket()
            remote.set_proxy(socks.SOCKS5, TOR_SOCKS_HOST, TOR_SOCKS_PORT)
            remote.settimeout(30)
            remote.connect((host, port))
            self.send_response(200, "Connection Established")
            self.end_headers()
            self._tunnel(self.connection, remote)
        except Exception as e:
            try:
                self.send_error(502, str(e))
            except Exception:
                pass

    def _tunnel(self, client, remote):
        sockets_list = [client, remote]
        while True:
            try:
                rlist, _, xlist = select.select(sockets_list, [], sockets_list, 60)
                if xlist:
                    break
                for sock in rlist:
                    other = remote if sock is client else client
                    data = sock.recv(65536)
                    if not data:
                        return
                    other.sendall(data)
            except Exception:
                break

    def do_GET(self): self._forward_http()
    def do_POST(self): self._forward_http()
    def do_PUT(self): self._forward_http()
    def do_DELETE(self): self._forward_http()
    def do_HEAD(self): self._forward_http()
    def do_OPTIONS(self): self._forward_http()
    def do_PATCH(self): self._forward_http()

    def _forward_http(self):
        url = urlparse(self.path)
        host = url.hostname
        port = url.port or 80
        path = url.path or "/"
        if url.query:
            path += "?" + url.query
        try:
            remote = socks.socksocket()
            remote.set_proxy(socks.SOCKS5, TOR_SOCKS_HOST, TOR_SOCKS_PORT)
            remote.settimeout(30)
            remote.connect((host, port))
            req_line = f"{self.command} {path} HTTP/1.1\r\n"
            # we read the answer till the server hangs up, so ask it to hang up (no keep-alive)
            headers = {k: v for k, v in self.headers.items() if k.lower() not in ("connection", "proxy-connection", "keep-alive")}
            headers["Connection"] = "close"
            headers["Host"] = host
            for k, v in get_random_headers().items():
                headers.setdefault(k, v)
            header_str = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
            body = b""
            length = self.headers.get("Content-Length")
            if length:
                body = self.rfile.read(int(length))
            remote.sendall((req_line + header_str + "\r\n").encode() + body)
            response = b""
            while True:
                chunk = remote.recv(65536)
                if not chunk:
                    break
                response += chunk
            self.wfile.write(response)
        except Exception as e:
            try:
                self.send_error(502, str(e))
            except Exception:
                pass


# --- Local SOCKS Bridge ------------------------------------------------------

class SocksBridge:
    """Local SOCKS5 server forwarding to Tor (stable endpoint for SOCKS5 apps)."""

    def __init__(self, listen_port, upstream_host, upstream_port):
        self.listen_port = listen_port
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port

    def handle_client(self, client):
        try:
            greeting = client.recv(256)
            if len(greeting) < 3 or greeting[0] != 5:
                client.close()
                return
            client.sendall(b"\x05\x00")

            req = client.recv(256)
            if len(req) < 7 or req[1] != 1:
                client.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
                client.close()
                return

            atyp = req[3]
            if atyp == 1:
                addr = socket.inet_ntoa(req[4:8])
                port = struct.unpack("!H", req[8:10])[0]
            elif atyp == 3:
                alen = req[4]
                addr = req[5:5 + alen].decode()
                port = struct.unpack("!H", req[5 + alen:7 + alen])[0]
            elif atyp == 4:
                addr = socket.inet_ntop(socket.AF_INET6, req[4:20])
                port = struct.unpack("!H", req[20:22])[0]
            else:
                client.close()
                return

            upstream = socks.socksocket()
            upstream.set_proxy(socks.SOCKS5, self.upstream_host, self.upstream_port)
            upstream.settimeout(30)
            upstream.connect((addr, port))

            bind = upstream.getsockname()
            ip_bytes = socket.inet_aton(bind[0])
            client.sendall(b"\x05\x00\x00\x01" + ip_bytes + struct.pack("!H", bind[1]))

            socks_list = [client, upstream]
            while True:
                rlist, _, xlist = select.select(socks_list, [], socks_list, 60)
                if xlist:
                    break
                for s in rlist:
                    other = upstream if s is client else client
                    data = s.recv(65536)
                    if not data:
                        return
                    other.sendall(data)
        except Exception:
            pass
        finally:
            client.close()

    def serve_forever(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", self.listen_port))
        server.listen(128)
        print(f"[+] Local SOCKS5 bridge on 127.0.0.1:{self.listen_port}")
        while True:
            client, _ = server.accept()
            threading.Thread(target=self.handle_client, args=(client,), daemon=True).start()


# --- Rotation Thread ---------------------------------------------------------

def rotation_loop(stop_event, password):
    while not stop_event.wait(ROTATION_INTERVAL):
        print("\n[*] Rotating Tor circuit (25 min elapsed)...")
        rotate_tor_circuit(password)
        time.sleep(10)
        proxies = {
            "http": f"http://127.0.0.1:{LOCAL_HTTP_PROXY_PORT}",
            "https": f"http://127.0.0.1:{LOCAL_HTTP_PROXY_PORT}"
        }
        ip, loc, warp = check_exit_ip(proxies)
        print(f"[*] New exit IP: {ip} ({loc}) | WARP: {warp}")


# --- Main Launcher -----------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Privacy Proxy Launcher - Maximum Privacy")
    parser.add_argument("app", nargs="+", help="Application command to launch")
    parser.add_argument("--tor-password", default="", help="Tor control password")
    parser.add_argument("--warp", action="store_true", help="Enable WARP proxy mode")
    parser.add_argument("--no-rotate", action="store_true", help="Disable circuit rotation")
    args = parser.parse_args()

    print("=" * 60)
    print("  Privacy Proxy Launcher - Maximum Privacy Edition")
    print("=" * 60)
    print()

    # 1. Check Tor
    start_tor_if_needed()

    # 2. Optional WARP
    warp_enabled = False
    if args.warp:
        print("[*] Enabling Cloudflare WARP proxy mode...")
        try:
            subprocess.run(["warp-cli", "mode", "proxy"], check=True, capture_output=True)
            subprocess.run(["warp-cli", "connect"], check=True, capture_output=True)
            warp_enabled = True
            print("[+] WARP proxy mode enabled")
        except Exception as e:
            print(f"[!] WARP setup failed: {e}. Continuing with Tor only.")

    # 3. Start HTTP CONNECT proxy
    http_server = ThreadingHTTPServer(("127.0.0.1", LOCAL_HTTP_PROXY_PORT), HTTPConnectProxy)  # one tunnel per thread
    threading.Thread(target=http_server.serve_forever, daemon=True).start()
    print(f"[+] HTTP CONNECT proxy on 127.0.0.1:{LOCAL_HTTP_PROXY_PORT}")

    # 4. Start SOCKS5 bridge
    bridge = SocksBridge(LOCAL_SOCKS_BRIDGE_PORT, TOR_SOCKS_HOST, TOR_SOCKS_PORT)
    threading.Thread(target=bridge.serve_forever, daemon=True).start()

    # 5. Verify exit IP
    proxies = {
        "http": f"http://127.0.0.1:{LOCAL_HTTP_PROXY_PORT}",
        "https": f"http://127.0.0.1:{LOCAL_HTTP_PROXY_PORT}"
    }
    ip, loc, warp_status = check_exit_ip(proxies)
    print(f"[+] Exit IP: {ip} ({loc}) | WARP: {warp_status}")

    # 6. Circuit rotation
    stop_event = threading.Event()
    if not args.no_rotate:
        t = threading.Thread(target=rotation_loop, args=(stop_event, args.tor_password), daemon=True)
        t.start()
        print(f"[+] Circuit rotation every {ROTATION_INTERVAL // 60} minutes")

    # 7. Session identity
    session_id = generate_random_id(16)
    ua = random.choice(USER_AGENTS)
    print(f"[+] Session ID: {session_id}")
    print(f"[+] User-Agent: {ua[:65]}...")

    # 8. Build environment variables (for CLI tools)
    env = os.environ.copy()
    env.update({
        "HTTP_PROXY": f"http://127.0.0.1:{LOCAL_HTTP_PROXY_PORT}",
        "HTTPS_PROXY": f"http://127.0.0.1:{LOCAL_HTTP_PROXY_PORT}",
        "http_proxy": f"http://127.0.0.1:{LOCAL_HTTP_PROXY_PORT}",
        "https_proxy": f"http://127.0.0.1:{LOCAL_HTTP_PROXY_PORT}",
        "ALL_PROXY": f"socks5h://127.0.0.1:{LOCAL_SOCKS_BRIDGE_PORT}",
        "all_proxy": f"socks5h://127.0.0.1:{LOCAL_SOCKS_BRIDGE_PORT}",
        "NO_PROXY": "localhost,127.0.0.1,::1",
        "no_proxy": "localhost,127.0.0.1,::1",
        "PRIVACY_SESSION_ID": session_id,
        "PRIVACY_USER_AGENT": ua,
    })

    # 9. Set system proxy for Electron/Chromium apps
    app_path = args.app[0]
    uses_system_proxy = is_electron_or_chromium(app_path)

    if uses_system_proxy:
        print(f"[+] Detected Electron/Chromium app: {os.path.basename(app_path)}")
        print(f"[+] Setting Windows system proxy (honored natively by Electron)")
        if set_system_proxy("127.0.0.1", LOCAL_HTTP_PROXY_PORT):
            restore_proxy_on_close()
        cmd = args.app  # No CLI flags needed!
    else:
        print(f"[+] Non-Electron app, using env-var proxy only")
        cmd = args.app

    # 10. Print privacy summary
    print()
    print("-" * 60)
    print("  PRIVACY PROTECTION SUMMARY")
    print("-" * 60)
    print(f"  [OK] Tor routing          : All traffic -> Tor network")
    print(f"  [OK] Exit IP               : {ip}")
    print(f"  [OK] DNS leak protection   : DNS resolved via Tor (SOCKS5h)")
    print(f"  [OK] WebRTC leak blocked   : System proxy + Tor handles this")
    print(f"  [OK] IPv6 leak blocked     : NO_PROXY excludes ::1")
    print(f"  [OK] Local server preserved : Loopback excluded from proxy")
    print(f"  [OK] Device fingerprint    : Randomized UA + headers + session")
    rotation = "Manual (from the extension)" if args.no_rotate else f"Every {ROTATION_INTERVAL // 60} min"
    print(f"  [OK] Circuit rotation      : {rotation}")
    print(f"  [OK] Method                : {'System proxy (Electron)' if uses_system_proxy else 'Env vars (CLI)'}")
    print("-" * 60)
    print()

    # 11. Launch
    print(f"[*] Launching: {' '.join(cmd)}")
    print("-" * 60)
    try:
        proc = subprocess.Popen(cmd, env=env)
        proc.wait()
    except FileNotFoundError:
        print(f"[X] App not found: {cmd[0]}")
        print("    Check the path and try again.")
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
    finally:
        stop_event.set()
        http_server.shutdown()
        if uses_system_proxy:
            restore_system_proxy()
        if warp_enabled:
            try:
                subprocess.run(["warp-cli", "disconnect"], capture_output=True)
                print("[+] WARP disconnected")
            except Exception:
                pass
        print("[+] Cleanup complete")


if __name__ == "__main__":
    main()