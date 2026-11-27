@echo off
setlocal
cd /d "%~dp0"

if not exist config.local.json (
  echo ERROR: config.local.json is missing.
  echo Copy config.example.json to config.local.json and set the SDK paths.
  exit /b 2
)

py -3 run_test.py --config config.local.json %*
exit /b %ERRORLEVEL%
