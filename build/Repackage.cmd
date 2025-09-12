@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Repackage.ps1" %*
echo.
pause
