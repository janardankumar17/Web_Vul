@echo off
title Web-Vul Backend Server
echo ==============================================
echo   Web-Vul Backend Server Starter
echo ==============================================
cd /d "%~dp0"

if exist venv\Scripts\python.exe (
    echo [OK] Using Python from local venv: .\venv\Scripts\python.exe
    echo [OK] Starting Flask server on http://localhost:5000 ...
    echo Press Ctrl+C to stop the server.
    echo.
    .\venv\Scripts\python.exe app.py
) else if exist ..\backend\venv\Scripts\python.exe (
    echo [OK] Using Python from backend venv...
    cd ..\backend
    .\venv\Scripts\python.exe app.py
) else (
    echo [ERROR] Virtual environment not found at .\venv\
    echo Please make sure the venv folder exists.
    pause
)
