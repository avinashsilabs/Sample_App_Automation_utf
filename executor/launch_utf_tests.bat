@echo off
setlocal

if not EXIST %~dp0..\venv\pyvenv.cfg (
    echo.
    echo Python virtual environment does not exist.  Please run setup_workspace.bat
    echo.
    exit /b 1
)

call %~dp0..\venv\scripts\activate
set PYTHONPATH=%~dp0..\utf_core\src
python ../utf_core/src/utf/executor/launch_utf_tests.py %*

