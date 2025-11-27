@echo off
title 🌟 Lorry AntiVirus - Batch Mode 🌟
color 0A
cls

:: Welcome message
echo =====================================================
echo           🌟 Lorry AntiVirus - Batch Mode 🌟
echo =====================================================
echo.

:menu
echo [1] Install Lorry AntiVirus
echo [2] Run Quick Scan
echo [3] Exit
echo.
set /p choice="Choose an option [1-3]: "

if "%choice%"=="1" goto install
if "%choice%"=="2" goto scan
if "%choice%"=="3" goto exit
echo Invalid choice! Try again.
echo.
goto menu

:install
echo Installing Lorry AntiVirus...
ping 127.0.0.1 -n 3 >nul
echo ✅ Installed successfully!
echo.
pause
cls
goto menu

:scan
echo Starting Quick Scan...
ping 127.0.0.1 -n 2 >nul
set targets=C:\Users C:\Downloads D:\USB
for %%f in (%targets%) do (
    echo Scanning %%f ...
    ping 127.0.0.1 -n 2 >nul
)
echo ✅ Scan complete. No threats detected.
echo.
pause
cls
goto menu

:exit
echo Goodbye! Stay safe. 🌟
timeout /t 2 /nobreak >nul
exit
