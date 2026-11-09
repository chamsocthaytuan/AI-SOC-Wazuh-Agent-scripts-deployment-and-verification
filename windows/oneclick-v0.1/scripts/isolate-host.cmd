@echo off
setlocal
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0isolate-host.ps1"
exit /b %ERRORLEVEL%
