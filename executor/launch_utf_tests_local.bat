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
set PYTEST_COMMAND="pytest example_test_package/sqa_test_suites_wifi_sdk_3/wlan_standalone/functional/scan_2_4ghz/test_wlan_bg_scan_sdk.py::test_wifi_sdk_bgscan_c19035 --manifest manifest/manifest_917_soc_telnet.yaml --tb=native --skip_parametrization"
python launch_utf_tests.py --executor_type=local --pytest_command=%PYTEST_COMMAND% %*

