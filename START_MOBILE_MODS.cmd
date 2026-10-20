@echo off
cd /d "%~dp0"
set /p "TMAL_SERIAL=ADB device serial: "
if not defined TMAL_SERIAL exit /b 1
echo Install the matching companion first. Save and exit the world.
pause
python tools/start_mobile.py --serial "%TMAL_SERIAL%" --saved-and-exited
pause
