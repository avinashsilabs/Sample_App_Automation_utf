@echo off
setlocal

if not EXIST %~dp0..\venv\pyvenv.cfg (
    echo.
    echo Python virtual environment does not exist.  Please run setup_workspace.bat
    echo.
    exit /b 1
)

call %~dp0..\venv\scripts\activate
set PYTHONPATH=%~dp0..\utf_core\src;%~dp0..\utf_wiseconnect;%~dp0..\utf_wiseconnect_3;%~dp0..\utf_core\tools
set PYTEST_COMMAND="pytest example_test_package/test_cases/test_fixtures_on_secodary_raspi.py --manifest manifest/manifest_917_soc_telnet.yaml --tb=native --skip_parametrization"
python launch_utf_tests.py --executor_type=local --pytest_command=%PYTEST_COMMAND% %*

