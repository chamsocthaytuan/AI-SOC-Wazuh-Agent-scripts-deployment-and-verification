@echo off
setlocal
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0block-ip.ps1"
exit /b %ERRORLEVEL%
