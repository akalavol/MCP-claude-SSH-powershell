@echo off
rem SSH_ASKPASS de RemoteDev (voir askpass.py). RD_ASKPASS_PY : python du MCP.
"%RD_ASKPASS_PY%" "%~dp0askpass.py" %*
