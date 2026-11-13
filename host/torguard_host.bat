@echo off
:: chrome runs this (see install.py). python talks to chrome over stdin/stdout so nothing else can print here
python -u "%~dp0torguard_host.py" %*
