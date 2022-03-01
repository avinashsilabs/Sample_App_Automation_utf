setlocal


if "%UTF_PYTEST_COMMAND%"=="" set "UTF_PYTEST_COMMAND=pytest --tb=native example_test_package --manifest /app/manifest/manifest.yaml

:: args:
:: 1 = SSH target (DUT)
:: 2 = harness name
:: 3 = pass 'debug' to launch in debug mode.
:: 4 = custom test script to run

@echo off
setlocal enabledelayedexpansion
SET DOCKER_TARGET=%1
SET HARNESS_NAME=%2
SET DEBUG=%3
set TEST_SCRIPT=%4

if "%UTF_DOCKER_TARGET%"=="" set UTF_DOCKER_TARGET=192.168.1.4
if "%UTF_HARNESS_NAME%"=="" set UTF_HARNESS_NAME=rs9116test
if "%UTF_DEBUG%"=="" set UTF_DEBUG=no_debug
if "%UTF_TEST_SCRIPT%"=="" set UTF_TEST_SCRIPT=run_tests.sh
if "%UTF_DOCKER_FLAGS%"=="" set UTF_DOCKER_FLAGS=-t
if "%UTF_DOCKER_CONTAINER_NAME%"=="" set UTF_DOCKER_CONTAINER_NAME=wifitest_1

if "%1"=="" set DOCKER_TARGET=%UTF_DOCKER_TARGET%
if "%2"=="" set HARNESS_NAME=%UTF_HARNESS_NAME%
if "%3"=="" set DEBUG=%UTF_DEBUG%
if "%4"=="" set TEST_SCRIPT=%UTF_TEST_SCRIPT%

set PYTEST_COMMAND_ARG=
if not "%UTF_PYTEST_COMMAND%"=="" set PYTEST_COMMAND_ARG=--pytest_command "%UTF_PYTEST_COMMAND%"

set DEBUG_ARG=
if "%DEBUG%"=="debug" set DEBUG_ARG=--debug true

set HWMUX_ARGS=
if NOT "%UTF_HWMUX_GROUP_JSON%"=="" set HWMUX_ARGS=--hwmux_group_json %UTF_HWMUX_GROUP_JSON%
if NOT "%UTF_HWMUX_TOKEN%"=="" set HWMUX_ARGS=--hwmux_token %UTF_HWMUX_TOKEN% %HWMUX_ARGS%
if NOT "%UTF_HWMUX_GROUP_ID%"=="" set HWMUX_ARGS=--hwmux_group_id %UTF_HWMUX_GROUP_ID% %HWMUX_ARGS%

set PYTHON_EXE=python
if NOT EXIST venv (
    where python3 > NUL
    if "%errorlevel%" equ "0" (
        set PYTHON_EXE=python3
    ) ELSE (
        where python > NUL
        if "%errorlevel%" neq "0" (
            echo Unable to find python in your system path.  Please install python 3.6 or higher.
            exit /b 1
        )
    )
    !PYTHON_EXE! -m venv venv
    if "%errorlevel%" neq "0" (
       echo Unable to create python virtual environment.
       exit /b 1
    )
)

call venv\scripts\activate
if "%errorlevel%" neq "0" (
   echo Unable to activate python virtual environment.
   exit /b 1
)
pushd executor
set PYTHON_CMD=%PYTHON_EXE% launch_utf_tests.py --target %DOCKER_TARGET% --harness %HARNESS_NAME% %DEBUG_ARG% --docker_flags "%UTF_DOCKER_FLAGS%" --container_name %UTF_DOCKER_CONTAINER_NAME%  %PYTEST_COMMAND_ARG% --test_script %TEST_SCRIPT% %HWMUX_ARGS%
echo %PYTHON_CMD%
%PYTHON_CMD%