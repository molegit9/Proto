@echo off
setlocal enabledelayedexpansion

REM Change directory to the script location
cd /d "%~dp0"

echo ===================================================
echo   Starting WebSecurityGuard FastAPI Server on Windows
echo ===================================================

REM 1. Check if virtual environment exists and activate it
set "VENV_ACTIVE=0"
if exist "venv\Scripts\activate.bat" (
    echo [INFO] Activating virtual environment venv...
    call venv\Scripts\activate.bat
    set "VENV_ACTIVE=1"
)

REM 2. Resolve Python executable path
set "PYTHON_EXE=python"
if "!VENV_ACTIVE!"=="0" (
    echo [WARNING] venv Scripts activate.bat not found.
    echo [WARNING] Searching for installed Python in AppData...
    
    if exist "%USERPROFILE%\AppData\Local\Programs\Python\Python39\python.exe" set "PYTHON_EXE=%USERPROFILE%\AppData\Local\Programs\Python\Python39\python.exe"
    if exist "%USERPROFILE%\AppData\Local\Programs\Python\Python310\python.exe" set "PYTHON_EXE=%USERPROFILE%\AppData\Local\Programs\Python\Python310\python.exe"
    if exist "%USERPROFILE%\AppData\Local\Programs\Python\Python311\python.exe" set "PYTHON_EXE=%USERPROFILE%\AppData\Local\Programs\Python\Python311\python.exe"
    if exist "%USERPROFILE%\AppData\Local\Programs\Python\Python312\python.exe" set "PYTHON_EXE=%USERPROFILE%\AppData\Local\Programs\Python\Python312\python.exe"
)

echo [INFO] Selected Python: !PYTHON_EXE!

REM 3. Print local IPv4 addresses to make remote configuration easy
echo ===================================================
echo   Detected Local IP Addresses (for Remote Demo):
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr "IPv4"') do (
    set "IP_TEMP=%%a"
    set "IP_TEMP=!IP_TEMP:~1!"
    echo   - [IP] !IP_TEMP!
)
echo ===================================================

REM 4. Choose whether to enable Remote Tunneling (Localtunnel)
set "ENABLE_LT=n"
set /p "ENABLE_LT=Enable Remote Tunneling (Localtunnel) for Remote Demo? [y/n] (Default: n): "

if /i "!ENABLE_LT!"=="y" (
    echo [INFO] Starting uvicorn server in a new window...
    start "WebSecurityGuard Backend Server" "!PYTHON_EXE!" -u -m uvicorn app.main:app --host 0.0.0.0 --port 8000
    
    echo ===================================================
    echo   Starting Localtunnel...
    echo   Please copy the URL shown below and paste it
    echo   into your extension options page.
    echo ===================================================
    call npx localtunnel --port 8000
) else (
    echo [INFO] Starting uvicorn server directly in this window...
    echo [INFO] Press Ctrl+C to terminate.
    "!PYTHON_EXE!" -u -m uvicorn app.main:app --host 0.0.0.0 --port 8000
)


echo ===================================================
echo   Server has stopped or failed to start.
echo ===================================================
pause
