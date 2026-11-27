@echo off
setlocal
py -3 "%~dp0run_test.py" --config "%~dp0config.local.json" %*
exit /b %errorlevel%
