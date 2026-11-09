@echo off
setlocal
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0kill-process-win.ps1"
exit /b %ERRORLEVEL%
