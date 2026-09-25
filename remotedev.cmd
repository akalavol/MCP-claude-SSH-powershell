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

rem Marqueur ecrit seulement apres une installation reussie (un venv a moitie cree est repare).
if exist "%ROOT%.venv\.remotedev-ok" goto :venv_ok
echo [remotedev] Installation de l'environnement Python...
if not exist "%PY%" python -m venv "%ROOT%.venv" || goto :fail
"%PY%" -m pip install -q -r "%ROOT%requirements.txt" || goto :fail
type nul > "%ROOT%.venv\.remotedev-ok"
:venv_ok

set "CFG=%REMOTEDEV_CONFIG_DIR%"
if "%CFG%"=="" set "CFG=%ROOT%config"
if exist "%CFG%\hosts.yaml" goto :config_ok
rem Premier lancement : liste vide, les machines s'ajoutent depuis l'interface (bouton Ajouter).
echo [remotedev] %CFG%\hosts.yaml cree (vide) : ajouter les machines dans l'interface.
> "%CFG%\hosts.yaml" echo hosts: {}
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
