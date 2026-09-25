@echo off
rem RemoteDev - lanceur Windows.
rem   remotedev              ouvre la mini-interface (double-clic)
rem   remotedev http [--minutes 30] [--allow-dev] [--no-tunnel]
rem   remotedev status | stop | check | stdio
setlocal
set "ROOT=%~dp0"
set "PY=%ROOT%.venv\Scripts\python.exe"
set "PYW=%ROOT%.venv\Scripts\pythonw.exe"
set "SRV=%ROOT%server.py"

if exist "%PY%" goto :venv_ok
echo [remotedev] Premiere utilisation : creation de l'environnement Python...
python -m venv "%ROOT%.venv" || goto :fail
"%PY%" -m pip install -q -r "%ROOT%requirements.txt" || goto :fail
:venv_ok

if exist "%ROOT%config\hosts.yaml" goto :config_ok
echo [remotedev] config\hosts.yaml manquant : copier config\hosts.example.yaml puis l'adapter.
goto :fail
:config_ok

set "ACTION=%~1"
if "%ACTION%"=="" set "ACTION=ui"
if /i "%ACTION%"=="ui"     goto :ui
if /i "%ACTION%"=="http"   goto :http
if /i "%ACTION%"=="status" goto :status
if /i "%ACTION%"=="stop"   goto :stop
if /i "%ACTION%"=="check"  goto :check
if /i "%ACTION%"=="stdio"  goto :stdio
echo Usage : remotedev [ui ^| http [--minutes N] [--allow-dev] [--no-tunnel] ^| status ^| stop ^| check ^| stdio]
exit /b 2

:ui
start "" "%PYW%" "%SRV%" --ui
exit /b 0
:http
"%PY%" "%SRV%" --http %2 %3 %4 %5 %6
exit /b %ERRORLEVEL%
:status
"%PY%" "%SRV%" --status
exit /b %ERRORLEVEL%
:stop
"%PY%" "%SRV%" --stop %2
exit /b %ERRORLEVEL%
:check
"%PY%" "%SRV%" --check
exit /b %ERRORLEVEL%
:stdio
"%PY%" "%SRV%"
exit /b %ERRORLEVEL%

:fail
echo.
pause
exit /b 1
