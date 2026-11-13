@echo off
setlocal EnableDelayedExpansion
title Full Privacy Suite
color 0A

:: --- CONFIGURATION ---------------------------------------------------------
set "SUBDIR="
set "BASE_DIR=%~dp0%SUBDIR%"
set "ROTATOR_SCRIPT=%BASE_DIR%tor_rotator.py"
set "MAIN_SCRIPT=%BASE_DIR%Script.py"

:: where tor lives. easiest: extract the tor expert bundle right here so u get tor\tor.exe + data\geoip
:: or set TOR_HOME urself before running this. falls back to Documents\FBypass (my old setup)
set "HERE=%~dp0"
set "HERE=%HERE:~0,-1%"
if not defined TOR_HOME if exist "%HERE%\tor\tor.exe" set "TOR_HOME=%HERE%"
if not defined TOR_HOME set "TOR_HOME=%USERPROFILE%\Documents\FBypass"
set "TOR_EXE=%TOR_HOME%\tor\tor.exe"
set "TORRC=%TOR_HOME%\torrc"
set "TOR_DATA=%TOR_HOME%\tor_data"

:: Embedded PS helper (Base64) for port checking - no batch escaping needed
set "B64=%TEMP%\torguard_ports.b64"
set "PS_HELPER=%TEMP%\torguard_ports.ps1"
set "STARTED_TOR=0"

echo ============================================================
echo   Starting Full Privacy Suite
echo ============================================================
echo.
echo [*] Base directory: %BASE_DIR%
echo.

:: --- DECODE PORT CHECK HELPER ----------------------------------------------
> "!B64!" echo -----BEGIN CERTIFICATE-----
>> "!B64!" echo cGFyYW0oW3N0cmluZ10kUG9ydCkKdHJ5IHsgJGMgPSBOZXctT2JqZWN0IE5ldC5Tb2NrZXRzLlRj
>> "!B64!" echo cENsaWVudCgnMTI3LjAuMC4xJywgW2ludF0kUG9ydCk7ICRjLkNsb3NlKCk7IGV4aXQgMCB9IGNh
>> "!B64!" echo dGNoIHsgZXhpdCAxIH0K
>> "!B64!" echo -----END CERTIFICATE-----
certutil -decode "!B64!" "!PS_HELPER!" >nul 2>&1
del "!B64!" >nul 2>&1

if not exist "!PS_HELPER!" (
    echo [X] Failed to create port check helper.
    pause & exit /b 1
)

:: --- VERIFY FILES EXIST ----------------------------------------------------
if not exist "%ROTATOR_SCRIPT%" (
    echo [X] Rotator script not found: !ROTATOR_SCRIPT!
    pause & exit /b 1
)
if not exist "%MAIN_SCRIPT%" (
    echo [X] Main script not found: !MAIN_SCRIPT!
    pause & exit /b 1
)
if not exist "%TOR_EXE%" (
    echo [X] Tor binary not found: !TOR_EXE!
    echo     Get the Tor Expert Bundle from torproject.org/download/tor and extract it into this folder.
    pause & exit /b 1
)
echo [OK] All files located
echo.

:: --- START TOR IF NOT RUNNING ----------------------------------------------
echo [*] Checking if Tor is running on port 9050...
powershell -NoProfile -ExecutionPolicy Bypass -File "!PS_HELPER!" -Port 9050 >nul 2>&1
if errorlevel 1 (
    echo [!] Tor not running. Starting Tor now...
    
    rem torrc wants windows paths with doubled backslashes in quotes, C:/ makes tor whine
    set "TOR_DATA_ESC=!TOR_DATA:\=\\!"
    set "GEOIP_ESC=!TOR_HOME:\=\\!\\data"
    set "BRIDGES_ESC=!TOR_HOME:\=\\!\\torguard-bridges.conf"
    (
        echo SocksPort 127.0.0.1:9050
        echo ControlPort 127.0.0.1:9051
        echo CookieAuthentication 1
        echo DataDirectory "!TOR_DATA_ESC!"
        echo Log notice stdout
        rem country data for the exit country setting - the tor expert bundle's data folder
        if exist "%TOR_HOME%\data\geoip" echo GeoIPFile "!GEOIP_ESC!\\geoip"
        if exist "%TOR_HOME%\data\geoip6" echo GeoIPv6File "!GEOIP_ESC!\\geoip6"
        rem bridges u turned on in the popup, so tor uses them from the very first connection
        if exist "%TOR_HOME%\torguard-bridges.conf" echo %%include "!BRIDGES_ESC!"
    ) > "%TORRC%"
    
    start "TorService" /B "%TOR_EXE%" -f "%TORRC%"
    set "STARTED_TOR=1"

    echo [*] Waiting for Tor to bootstrap (up to 60s^)...
    set "READY=0"
    for /L %%i in (1,1,30) do (
        if "!READY!"=="0" (
            timeout /t 2 /nobreak >nul
            powershell -NoProfile -ExecutionPolicy Bypass -File "!PS_HELPER!" -Port 9050 >nul 2>&1
            if not errorlevel 1 set "READY=1"
        )
    )
    if "!READY!"=="0" (
        echo [X] Tor failed to start. Check firewall/antivirus.
        call :stop_services
        pause & exit /b 1
    )
    echo [OK] Tor bootstrapped successfully
) else (
    echo [OK] Tor already running
)
echo.

:: --- START ROTATOR API -----------------------------------------------------
:: already running (like the one click start from the popup)? use that one and dont kill it later
powershell -NoProfile -ExecutionPolicy Bypass -File "!PS_HELPER!" -Port 8222 >nul 2>&1
if not errorlevel 1 (
    echo [OK] Rotator already running
    goto rotator_ready
)
echo [*] Starting Tor IP Rotator API...
cd /d "%BASE_DIR%"
start "TorRotator" /B python "%ROTATOR_SCRIPT%"
set "STARTED_ROTATOR=1"
timeout /t 3 /nobreak >nul

:: just check the port, /status goes through tor now and can take a while
powershell -NoProfile -ExecutionPolicy Bypass -File "!PS_HELPER!" -Port 8222 >nul 2>&1
if errorlevel 1 (
    echo [X] Rotator API failed to start.
    call :stop_services
    pause & exit /b 1
)
echo [OK] Rotator API ready on port 8222
:rotator_ready
echo.

:: --- OPTIONAL: LAUNCH AN APP THROUGH THE PROXY ------------------------------
:: Script.py needs an app to launch, like  start_privacy.bat "C:\path\to\app.exe"
if "%~1"=="" (
    echo [*] Tor + rotator are running. Turn protection on from the extension popup.
    echo [*] Press any key to stop everything...
    pause >nul
) else (
    echo [*] Starting Privacy Proxy Launcher - manual rotation mode...
    rem -- = everything after it goes to ur app, so app flags like --inspect dont confuse Script.py
    python "%MAIN_SCRIPT%" --no-rotate -- %*
)
echo.

:: --- CLEANUP ON EXIT -------------------------------------------------------
echo [*] Shutting down services...
call :stop_services
echo [OK] All services stopped
pause
exit /b 0

:stop_services
:: /B processes have no window title so match by command line / path instead.
:: only kills tor + the rotator if this script started them
powershell -NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { ('!STARTED_ROTATOR!' -eq '1' -and $_.Name -like 'python*' -and $_.CommandLine -like '*tor_rotator.py*') -or ('!STARTED_TOR!' -eq '1' -and $_.ExecutablePath -eq '!TOR_EXE!') } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }" >nul 2>&1
del "!PS_HELPER!" >nul 2>&1
exit /b