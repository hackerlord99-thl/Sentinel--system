# Sentinel Host EDR PowerShell Installer

Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "               SENTINEL // HOST EDR POWERSHELL INSTALLER" -ForegroundColor Cyan
Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host ""

$AppDir = $PSScriptRoot
if (-not $AppDir) { $AppDir = (Get-Location).Path }
$ExePath = Join-Path $AppDir "Sentinel.exe"
$IconPath = Join-Path $AppDir "sentinel.ico"

# 1. Compile Sentinel.exe if missing
if (-not (Test-Path $ExePath)) {
    Write-Host "[*] Compiling Sentinel.exe with native C# compiler..." -ForegroundColor Yellow
    $csc = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
    if (Test-Path $csc) {
        $csFile = Join-Path $AppDir "SentinelLauncher.cs"
        Start-Process -FilePath $csc -ArgumentList "/target:winexe", "/optimize+", "/win32icon:`"$IconPath`"", "/out:`"$ExePath`"", "`"$csFile`"" -Wait -NoNewWindow
    }
}

if (Test-Path $ExePath) {
    Write-Host "[OK] Native executable verified: Sentinel.exe" -ForegroundColor Green
} else {
    Write-Host "[ERROR] Could not find or compile Sentinel.exe" -ForegroundColor Red
    exit 1
}

# 2. Create Shortcuts
Write-Host "[*] Creating Desktop and Start Menu shortcuts..." -ForegroundColor Yellow
$WshShell = New-Object -ComObject WScript.Shell

$DesktopPath = [Environment]::GetFolderPath('Desktop')
$DesktopLnk = Join-Path $DesktopPath "Sentinel EDR Console.lnk"
$Shortcut1 = $WshShell.CreateShortcut($DesktopLnk)
$Shortcut1.TargetPath = $ExePath
$Shortcut1.WorkingDirectory = $AppDir
$Shortcut1.Description = "Sentinel Endpoint Detection and Response Console"
$Shortcut1.IconLocation = $IconPath
$Shortcut1.Save()
Write-Host "[OK] Desktop shortcut created: $DesktopLnk" -ForegroundColor Green

$StartMenuPath = [Environment]::GetFolderPath('Programs')
$StartMenuLnk = Join-Path $StartMenuPath "Sentinel EDR Console.lnk"
$Shortcut2 = $WshShell.CreateShortcut($StartMenuLnk)
$Shortcut2.TargetPath = $ExePath
$Shortcut2.WorkingDirectory = $AppDir
$Shortcut2.Description = "Sentinel Endpoint Detection and Response Console"
$Shortcut2.IconLocation = $IconPath
$Shortcut2.Save()
Write-Host "[OK] Start Menu shortcut created: $StartMenuLnk" -ForegroundColor Green

# 3. Enable Auto-Start on Windows Login
Write-Host "[*] Registering Auto-Start on Windows login..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SentinelEDR" -Value "`"$ExePath`""
Write-Host "[OK] Windows Auto-Start registered in HKCU Run key." -ForegroundColor Green

Write-Host ""
Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "                  SENTINEL INSTALLED SUCCESSFULLY!" -ForegroundColor Cyan
Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host ""
