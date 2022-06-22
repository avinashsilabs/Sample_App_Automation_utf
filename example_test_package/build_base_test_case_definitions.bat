call %~dp0..\venv\Scripts\activate
set PYTHONPATH=%~dp0..\utf_core\src;%~dp0..\utf_wiseconnect;
pytest --collect-only .
echo Success