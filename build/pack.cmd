@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0pack.ps1" %*
echo.
pause
