@echo off
setlocal
pushd %~dp0


if not EXIST venv\pyvenv.cfg (
    python --version | findstr /C:"Python 3" > NUL 2>&1
    if %errorlevel% neq 0 (
        set "ERROR_MESSAGE=Python 3 is required to run this script"
        goto ERROR
    )
    python -m venv venv
    if %errorlevel% neq 0 (
        set "ERROR_MESSAGE=Error creating python virtual environment"
        goto ERROR
    )
)
call venv\scripts\activate

python -m pip install --upgrade pip
pip install --upgrade setuptools
pip install wheel pyyaml
python utf_core\tools\workspace_setup.py %CD% config\workspace.yaml
if %errorlevel% neq 0 (
   set "ERROR_MESSAGE=FATAL ERROR: Workspace setup failed."
   goto ERROR
)

if "%1"=="skip_gui" (
    goto SUCCESS
)
SET "UTF_GUI=%LOCALAPPDATA%\Programs\utf-sequence-manager\UTF Sequence Manager.exe"

if not EXIST "%UTF_GUI%" (
    echo Installing UTF Sequence Manager...
    start /wait utf_core\tools\utf-gui-setup.exe
)

if not EXIST "UTF Launcher.lnk" (
    "%UTF_GUI%" %CD% --create-shortcut > NUL
)

:SUCCESS
echo ===========================================================================
echo Workspace was set up successfully!
echo ===========================================================================
echo.
exit /b 0

:ERROR
echo.
echo ===========================================================================
echo %ERROR_MESSAGE%
echo ===========================================================================
echo.
pause
exit /b 1

