@echo off
if not exist .\tcmgr\tcmgr.py (
  git submodule update --init --recursive tcmgr
)
set tcm=.\tcmgr\tcmgr.ps1
IF [%1]==[] (
   set inputxml=ToolchainInfoWindows.yaml
) ELSE (
   set inputxml=%1
)
ECHO Using inputxml: %inputxml%
set projfile=projenv.bat
set projproperties=projenv.properties


PowerShell -inputformat none -ExecutionPolicy Bypass -File  %tcm% %inputxml% %projfile%
if %errorlevel% neq 0 (
    set exitcode=%errorlevel%
    goto TCM_ERROR
    )

echo Toolchains downloadeded successfully.

if not exist utf_pytest\test-requirements.txt (
   git submodule update --init --recursive utf_pytest
)

if not exist utf_pytest\utf\utils\utf_queue_client\test-requirements.txt (
   cd utf_pytest
   git submodule update --init --recursive
   cd ..
)

if not exist utf_pytest\venv\pyvenv.cfg (
   call %projfile%
   python -m venv utf_pytest\venv
   call utf_pytest\venv\scripts\activate
   pip install wheel
   pushd utf_pytest
   pip install -r test-requirements.txt
   popd
)

goto DONE

:TCM_ERROR
echo.
echo FATAL ERROR: Toolchain Manager returned error code '%errorlevel%'
echo.
exit /b %exitcode%

:DONE
exit /b 0
