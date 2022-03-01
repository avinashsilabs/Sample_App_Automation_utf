@echo off
setlocal

pushd test_agent

set RELEASE_PACKAGE_VERSION=%1
if "%1"=="" (
   set RELEASE_PACKAGE_VERSION=RS916W.2.5.0.14
)
set SSH_KEY=%2
if "%2"=="" (
   set SSH_KEY=%USERPROFILE%\.ssh\id_rsa
)
set BUILD_LOCATION=$3
if "%3"=="" (
   set BUILD_LOCATION=release_packages
)
set DOCKER_BUILDKIT=1
docker build --build-arg RELEASE_PACKAGE_VERSION=%RELEASE_PACKAGE_VERSION% --build-arg BUILD_LOCATION=$BUILD_LOCATION -t wifi_test_agent_build --ssh default=%SSH_KEY% .
if %errorlevel% neq 0 (
   exit /b 1
)

if exist build (
    rd /s /q build
)
mkdir build
docker run --rm -it -v %CD%/build:/build/rs911x/Host_MCU/test/sqa_test_agent/build/build wifi_test_agent_build
if %errorlevel% neq 0 (
   exit /b 1
)

popd

copy test_agent\build\debug\sqa_test_agent.hex manifest

:: run python script to parse map file to view memory usage
call venv\scripts\activate
python test_agent\map_file_parser.py test_agent\build\debug\sqa_test_agent.map 1024
