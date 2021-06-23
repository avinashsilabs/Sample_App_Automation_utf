@echo off
if not exist .\tcmgr (
  git submodule update --init --recursive
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

echo(
echo Contents of %projfile%:
echo ---------------------------
type %projfile%
echo ---------------------------
echo(
echo Contents of %projproperties%:
echo ---------------------------
type %projproperties%
echo ---------------------------
echo(
echo Activate project environment by running '%projfile%'
echo(


goto DONE

:TCM_ERROR
echo.
echo FATAL ERROR: Toolchain Manager returned error code '%errorlevel%'
echo.
exit /b %exitcode%

:DONE
exit /b 0
