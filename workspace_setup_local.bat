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
pip install wheel pyyaml

echo ===========================================================================
echo Updating ChromeDriver...
echo ===========================================================================
REM Install requests if not already installed (required by update_chromedriver.py)
pip install requests
python update_chromedriver.py
if %errorlevel% neq 0 (
    echo WARNING: ChromeDriver update failed. Continuing with workspace setup...
)
echo.

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
echo.
echo ===========================================================================
echo             WORKSPACE SETUP COMPLETED SUCCESSFULLY!
echo ===========================================================================
echo.
echo ===========================================================================
echo                    CHROMEDRIVER INSTALLATION INFO
echo ===========================================================================
echo.
echo ChromeDriver Location: %USERPROFILE%\chromedriver\chromedriver.exe
echo.
echo ===========================================================================
echo                      IMPORTANT - NEXT STEPS
echo ===========================================================================
echo.
echo To use ChromeDriver, add this to your System PATH:
echo    %USERPROFILE%\chromedriver
echo.
echo How to add to PATH:
echo  1. Press Windows key and search "Environment Variables"
echo  2. Click "Edit the system environment variables"
echo  3. Click "Environment Variables" button
echo  4. Under "System variables", select "Path" and click "Edit"
echo  5. Click "New" and add: %USERPROFILE%\chromedriver
echo  6. Move it to the TOP if you have old ChromeDriver installations
echo  7. Click OK on all windows
echo  8. Restart your terminal/PowerShell
echo.
echo To verify: Open NEW terminal and run: chromedriver --version
echo.
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

