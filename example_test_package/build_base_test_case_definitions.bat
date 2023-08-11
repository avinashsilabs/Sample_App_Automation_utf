call %~dp0..\venv\Scripts\activate
set PYTHONPATH=%~dp0..\utf_core\src;%~dp0..\utf_wiseconnect;%~dp0..\;
pytest --collect-only --disable-pytest-warnings .
if %ERRORLEVEL% neq 0 goto FILEERROR
goto EOF

:FILEERROR
if %ERRORLEVEL% neq 2 goto ERROR
goto EOF

:ERROR
echo Build Failed
exit /b 1

:EOF
echo Finish building base test case definitions...
exit /b 0