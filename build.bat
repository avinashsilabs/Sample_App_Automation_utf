@echo off
setlocal
if not exist projenv.bat (
    echo Calling TCMGR to get dependencies
    call tcm_setup.bat
)

call projenv.bat

pushd sqa_test_application
if NOT "%1"=="gen" goto build

set GECKO_SDK=%~dp0mini_gecko_sdk
call slc configuration -s %GECKO_SDK% -gcc %ARM_GCC_DIR_WIN%

:: clean rs9116 sources in mini gecko sdk
pushd %GECKO_SDK%\platform\radio\wifi\rs9116
git clean -ffdx
popd

:: copy files from rs911x repo to mini gecko sdk
xcopy /s /i /q rs911x_sdk\component %GECKO_SDK%\platform\radio\wifi\rs9116\component
xcopy /s /i /q rs911x_sdk\sapi %GECKO_SDK%\platform\radio\wifi\rs9116\sapi
xcopy /s /i /q rs911x_sdk\platforms\efx32 %GECKO_SDK%\platform\radio\wifi\rs9116\efx32

:: generate SLC project
call slc generate --copy-sdk-sources -p sqa_test_agent.slcp -d build -o makefile

:: build
:build
make -C build -f sqa_test_agent.Makefile -j

popd
