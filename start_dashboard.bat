@echo off
cd /d "%~dp0"
echo ============================================================
echo   ARGUS EDR Dashboard
echo   http://localhost:8080
echo   Run as Administrator for injection (RUN DEMO) to work
echo ============================================================
echo.

echo Checking Python dependencies...
python -m pip install -r dashboard\requirements.txt -q
if errorlevel 1 (
    echo ERROR: pip install failed. Make sure Python is installed and in PATH.
    pause
    exit /b 1
)
echo Dependencies OK.
echo.

echo Starting server...
echo Browser will open automatically in 3 seconds.
echo.

start "" powershell -WindowStyle Hidden -Command "Start-Sleep 3; Start-Process 'http://localhost:8080'"
python dashboard\server.py
pause
