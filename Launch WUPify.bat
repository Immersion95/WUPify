@echo off
setlocal
cd /d "%~dp0"

python -c "import cryptography" >nul 2>&1
if errorlevel 1 (
    echo [WUPify] Installing required dependency: cryptography...
    python -m pip install cryptography
    if errorlevel 1 (
        echo.
        echo [ERROR] Could not install cryptography.
        echo Make sure Python and pip are installed, then try again.
        pause
        exit /b 1
    )
)

python WUPify.py --path . --recursive
pause
