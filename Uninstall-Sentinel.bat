@echo off
setlocal
title Sentinel EDR - Uninstaller
color 0C

echo ===============================================================================
echo                SENTINEL // EDR UNINSTALLATION WIZARD
echo ===============================================================================
echo.

echo [*] Terminating running Sentinel processes...
taskkill /F /IM "Sentinel.exe" >nul 2>&1

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$Desktop = [Environment]::GetFolderPath('Desktop'); " ^
    "$StartMenu = [Environment]::GetFolderPath('Programs'); " ^
    "$f1 = Join-Path $Desktop 'Sentinel EDR Console.lnk'; " ^
    "$f2 = Join-Path $StartMenu 'Sentinel EDR Console.lnk'; " ^
    "if (Test-Path $f1) { Remove-Item $f1 -Force }; " ^
    "if (Test-Path $f2) { Remove-Item $f2 -Force };"

echo [✓] Desktop and Start Menu shortcuts removed.

echo [*] Removing Windows Auto-Start registry entry...
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SentinelEDR" /f >nul 2>&1
echo [✓] Auto-Start registry entry removed.

echo.
echo ===============================================================================
echo                 SENTINEL UNINSTALLED SUCCESSFULLY!
echo ===============================================================================
echo.
pause
exit /b 0
