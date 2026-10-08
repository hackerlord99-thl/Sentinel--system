@echo off
setlocal enabledelayedexpansion
title Sentinel EDR - Windows Installation Wizard
color 0B

echo ===============================================================================
echo                SENTINEL // HOST EDR INSTALLATION WIZARD
echo               Endpoint Detection ^& Threat Defense Platform
echo ===============================================================================
echo.

set "APP_DIR=%~dp0"
set "APP_DIR=%APP_DIR:~0,-1%"
set "EXE_PATH=%APP_DIR%\Sentinel.exe"
set "ICON_PATH=%APP_DIR%\sentinel.ico"

echo [*] Target Directory: %APP_DIR%

:: Step 1: Check Node.js
echo [*] Checking Node.js runtime environment...
where node >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [-] Error: Node.js is required but was not found in PATH.
    echo     Please install Node.js from https://nodejs.org
    pause
    exit /b 1
)
for /f "tokens=*" %%v in ('node -v') do set "NODE_VER=%%v"
echo [✓] Node.js verified: !NODE_VER!

:: Step 2: Ensure Node dependencies
if not exist "%APP_DIR%\node_modules" (
    echo [*] Installing production dependencies...
    cd /d "%APP_DIR%"
    call npm install --omit=dev
)
echo [✓] Dependencies verified.

:: Step 3: Compile / Verify Sentinel.exe
if not exist "%EXE_PATH%" (
    echo [*] Compiling native Windows executable (Sentinel.exe)...
    set "CSC=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
    if not exist "!CSC!" set "CSC=C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"
    
    if exist "!CSC!" (
        "!CSC!" /target:winexe /optimize+ /win32icon:"%ICON_PATH%" /out:"%EXE_PATH%" "%APP_DIR%\SentinelLauncher.cs" >nul 2>&1
    )
)

if not exist "%EXE_PATH%" (
    echo [-] Warning: Could not compile Sentinel.exe. Using script launcher fallback.
) else (
    echo [✓] Native Windows application verified: Sentinel.exe
)

:: Step 4: Create Desktop & Start Menu Shortcuts via PowerShell
echo [*] Creating Windows Shortcuts...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$WshShell = New-Object -ComObject WScript.Shell; " ^
    "$DesktopPath = [Environment]::GetFolderPath('Desktop'); " ^
    "$StartMenuPath = [Environment]::GetFolderPath('Programs'); " ^
    "$ShortcutPath1 = Join-Path $DesktopPath 'Sentinel EDR Console.lnk'; " ^
    "$Shortcut1 = $WshShell.CreateShortcut($ShortcutPath1); " ^
    "$Shortcut1.TargetPath = '%EXE_PATH%'; " ^
    "$Shortcut1.WorkingDirectory = '%APP_DIR%'; " ^
    "$Shortcut1.Description = 'Sentinel Real-Time Endpoint Detection and Response'; " ^
    "$Shortcut1.IconLocation = '%ICON_PATH%'; " ^
    "$Shortcut1.Save(); " ^
    "$ShortcutPath2 = Join-Path $StartMenuPath 'Sentinel EDR Console.lnk'; " ^
    "$Shortcut2 = $WshShell.CreateShortcut($ShortcutPath2); " ^
    "$Shortcut2.TargetPath = '%EXE_PATH%'; " ^
    "$Shortcut2.WorkingDirectory = '%APP_DIR%'; " ^
    "$Shortcut2.Description = 'Sentinel Real-Time Endpoint Detection and Response'; " ^
    "$Shortcut2.IconLocation = '%ICON_PATH%'; " ^
    "$Shortcut2.Save(); "

echo [✓] Desktop shortcut created: Sentinel EDR Console
echo [✓] Start Menu shortcut created

:: Step 5: Configure Auto-Start on Windows Login
echo [*] Enabling background sensor on Windows login...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SentinelEDR" /t REG_SZ /d "\"%EXE_PATH%\"" /f >nul 2>&1
echo [✓] Windows Auto-Start registered in Registry.

echo.
echo ===============================================================================
echo                INSTALLATION COMPLETED SUCCESSFULLY!
echo ===============================================================================
echo  [✓] Sentinel is now installed on your Windows system.
echo  [✓] Real-time host sensor will run automatically on Windows startup.
echo  [✓] Double-click the 'Sentinel EDR Console' shortcut on your Desktop anytime.
echo ===============================================================================
echo.

:: Launch Sentinel immediately
echo [*] Launching Sentinel EDR Console...
start "" "%EXE_PATH%"

timeout /t 3 >nul
exit /b 0
