@echo off
setlocal
cd /d "%~dp0"

if not exist config.local.json (
  echo ERROR: config.local.json is missing.
  echo Copy config.example.json to config.local.json and set SDK, WLAN, Pi, and board values.
  exit /b 2
)

python run_test.py --config config.local.json %*
exit /b %ERRORLEVEL%
