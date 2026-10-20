@echo off
set /p "TMAL_SERIAL=ADB emulator serial: "
if not defined TMAL_SERIAL exit /b 1
echo Opens the original game; does not enable emulator mod support.
adb -s "%TMAL_SERIAL%" shell am start -W -n com.and.games505.TerrariaPaid/com.unity3d.player.UnityPlayerActivity
pause
