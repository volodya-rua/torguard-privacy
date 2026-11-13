#!/usr/bin/env python3
"""
registers the native host so the extension can start/stop tor by itself.
writes com.torguard.host.json next to this file and points chrome (and edge/brave) at it
through one registry key under HKEY_CURRENT_USER. no admin needed.

  python install.py              install (run it again if u move the repo folder)
  python install.py --uninstall  remove it
"""

import json
import sys
import winreg
from pathlib import Path

NAME = "com.torguard.host"
EXTENSION_ID = "bajbfjfamddbbconknamkmekbeaojnem"  # fixed by the "key" in extension/manifest.json
HERE = Path(__file__).resolve().parent
MANIFEST = HERE / f"{NAME}.json"
BROWSERS = {
    "Chrome": rf"Software\Google\Chrome\NativeMessagingHosts\{NAME}",
    "Edge": rf"Software\Microsoft\Edge\NativeMessagingHosts\{NAME}",
    "Brave": rf"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\{NAME}",
}


def install():
    MANIFEST.write_text(json.dumps({
        "name": NAME,
        "description": "TorGuard Privacy: starts and stops Tor for the extension",
        "path": str(HERE / "torguard_host.bat"),
        "type": "stdio",
        "allowed_origins": [f"chrome-extension://{EXTENSION_ID}/"],
    }, indent=2), encoding="utf-8")
    for browser, key in BROWSERS.items():
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key) as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, str(MANIFEST))
    print(f"[OK] installed for {', '.join(BROWSERS)}. the popup can start tor by itself now")
    print("     (reload the extension in chrome://extensions if it was already open)")


def uninstall():
    for key in BROWSERS.values():
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key)
        except FileNotFoundError:
            pass
    MANIFEST.unlink(missing_ok=True)
    print("[OK] removed. use start_privacy.bat to run tor again")


if __name__ == "__main__":
    uninstall() if "--uninstall" in sys.argv else install()
