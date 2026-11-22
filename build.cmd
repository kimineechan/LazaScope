@echo off
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\build.ps1
if errorlevel 1 (
  echo Build failed. Read the error above.
  pause
  exit /b 1
)
echo Ready: dist\LazaScope.exe and dist\lazascope-cli.exe
pause
