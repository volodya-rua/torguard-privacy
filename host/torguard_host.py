#!/usr/bin/env python3
"""
torguard native host
====================
chrome runs this when the extension asks (native messaging), so the popup can start tor by itself
and u dont need the .bat window. it only knows 3 things:

  start   start tor + the rotator if theyre not running yet
  stop    stop whatever THIS started (tor from start_privacy.bat is left alone)
  status  whats running

one message in, one answer out, then it exits. tor keeps running in the background.
install once with install_host.bat (adds one registry entry for ur user, no admin needed)
"""

import json
import os
import socket
import struct
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
STATE = Path(os.environ.get("LOCALAPPDATA", str(REPO))) / "torguard" / "started.json"
PORTS = {"tor": 9050, "rotator": 8222}
DEVNULL = subprocess.DEVNULL


def tor_home():
    """same order as start_privacy.bat: TOR_HOME, then tor next to the repo, then Documents\\FBypass."""
    if os.environ.get("TOR_HOME"):
        return Path(os.environ["TOR_HOME"])
    if (REPO / "tor" / "tor.exe").exists():
        return REPO
    return Path.home() / "Documents" / "FBypass"


def listening(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False


def esc(path):
    return str(path).replace("\\", "\\\\")  # torrc wants doubled backslashes in quotes


def write_torrc(home):
    lines = ["SocksPort 127.0.0.1:9050", "ControlPort 127.0.0.1:9051", "CookieAuthentication 1",
             f'DataDirectory "{esc(home / "tor_data")}"']
    for option, name in (("GeoIPFile", "geoip"), ("GeoIPv6File", "geoip6")):
        if (home / "data" / name).exists():
            lines.append(f'{option} "{esc(home / "data" / name)}"')
    bridges = home / "torguard-bridges.conf"  # written by the rotator when u turn on bridges
    if bridges.exists():
        lines.append(f'%include "{esc(bridges)}"')
    (home / "torrc").write_text("\n".join(lines) + "\n", encoding="ascii")


def spawn(args, env=None):
    """start it with no window and not tied to chrome, so tor survives the popup closing."""
    flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    for breakaway in (0x01000000, 0):  # CREATE_BREAKAWAY_FROM_JOB, chrome doesnt always allow it
        try:
            return subprocess.Popen(args, stdin=DEVNULL, stdout=DEVNULL, stderr=DEVNULL, env=env,
                                    creationflags=flags | breakaway, close_fds=True).pid
        except OSError:
            if not breakaway:
                raise


def load_state():
    try:
        return json.loads(STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_state(state):
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(state), encoding="utf-8")


def command_line(pid):
    out = subprocess.run(["powershell", "-NoProfile", "-Command", f"(Get-CimInstance Win32_Process -Filter 'ProcessId={int(pid)}').CommandLine"],
                         capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW).stdout
    return out.strip().lower()


def start(_msg):
    home = tor_home()
    tor_exe = home / "tor" / "tor.exe"
    state = load_state()
    if not listening(PORTS["tor"]):
        if not tor_exe.exists():
            return {"ok": False, "error": "no_tor",
                    "message": f"tor.exe isn't in {home}\\tor. Get the Tor Expert Bundle and extract it into the repo folder."}
        write_torrc(home)
        state["tor"] = spawn([str(tor_exe), "-f", str(home / "torrc")])
    if not listening(PORTS["rotator"]):
        state["rotator"] = spawn([sys.executable, str(REPO / "tor_rotator.py")], env={**os.environ, "TOR_HOME": str(home)})
    save_state(state)
    return {"ok": True, "managed": sorted(state)}


def stop(_msg):
    state = load_state()
    stopped = []
    for name, pid in state.items():
        # make sure that pid is still OUR tor / rotator and not some random process that got the same number
        cmd = command_line(pid)
        if ("tor.exe" in cmd and name == "tor") or ("tor_rotator.py" in cmd and name == "rotator"):
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], stdout=DEVNULL, stderr=DEVNULL,
                           creationflags=subprocess.CREATE_NO_WINDOW)
            stopped.append(name)
    save_state({})
    return {"ok": True, "stopped": stopped}


def status(_msg):
    return {"ok": True, "tor": listening(PORTS["tor"]), "rotator": listening(PORTS["rotator"]), "managed": sorted(load_state())}


def read_message():
    raw = sys.stdin.buffer.read(4)
    if len(raw) < 4:
        return {}
    return json.loads(sys.stdin.buffer.read(struct.unpack("<I", raw)[0]) or b"{}")


def send(message):
    data = json.dumps(message).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("<I", len(data)) + data)
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    try:
        msg = read_message()
        handler = {"start": start, "stop": stop, "status": status}.get(msg.get("cmd"))
        send(handler(msg) if handler else {"ok": False, "error": "bad_command", "message": "Unknown command."})
    except Exception as e:  # never leave chrome hanging without an answer
        send({"ok": False, "error": "host_crashed", "message": f"{type(e).__name__}: {e}"})
