@echo off
setlocal
chcp 65001 >nul
title ProcNet Risk Traffic Demo

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\demo-risk-traffic.ps1" -Port 39110 -CountdownSeconds 0 -DurationSeconds 15 -ChunkBytes 1048576 -DelayMilliseconds 10
set "DEMO_EXIT=%ERRORLEVEL%"

echo.
if not "%DEMO_EXIT%"=="0" (
    echo Demo failed. Review the message above.
) else (
    echo Demo traffic finished successfully.
)
echo Press any key to close this window.
pause >nul
exit /b %DEMO_EXIT%
