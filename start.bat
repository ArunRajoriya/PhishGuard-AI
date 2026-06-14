@echo off
echo ========================================
echo PhishGuard AI - Starting Application
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed
    echo Please install Python 3.12 or higher from https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Check if .env file exists
if not exist ".env" (
    echo WARNING: .env file not found
    if exist ".env.example" (
        copy .env.example .env
        echo Created .env file from .env.example
        echo IMPORTANT: Please add your VirusTotal API key to .env
        notepad .env
    )
)

REM Install dependencies if needed
echo Checking dependencies...
pip show fastapi >nul 2>&1
if errorlevel 1 (
    echo Installing dependencies...
    pip install -r requirements.txt
)

REM Train model if not exists
if not exist "model\model.pkl" (
    echo Training ML model...
    python model\train_model.py
)

REM Remove corrupted database if exists
if exist "database\phishguard.db" (
    echo Checking database...
)

echo.
echo Starting PhishGuard AI...
echo.
echo Access at: http://localhost:8000
echo API Docs at: http://localhost:8000/docs
echo.
echo Press Ctrl+C to stop the server
echo.

uvicorn app:app --host 0.0.0.0 --port 8000 --reload

pause
