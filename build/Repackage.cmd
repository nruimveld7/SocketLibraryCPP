@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts/Repackage.ps1" %*
echo.
pause
