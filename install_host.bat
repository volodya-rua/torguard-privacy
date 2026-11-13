@echo off
:: run this once so the extension's "turn on" button starts tor by itself (so u dont have to leave the .bat open)
:: adds one registry entry for ur user, no admin. "install_host.bat --uninstall" removes it again
python "%~dp0host\install.py" %*
pause
