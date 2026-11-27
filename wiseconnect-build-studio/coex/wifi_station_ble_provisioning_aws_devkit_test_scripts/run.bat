@echo off
setlocal
cd /d "%~dp0"

if not exist config.local.json (
    echo config.local.json not found.
    echo Copy config.example.json to config.local.json and fill in your settings:
    echo     copy config.example.json config.local.json
    exit /b 1
)

echo Make sure WiseConnect Build Studio is running ^(python app.py^) before starting.
python -u run_test.py %*
exit /b %ERRORLEVEL%
