@echo off
setlocal

set RELEASE_PACKAGE_VERSION=%1
if "%1"=="" (
   set RELEASE_PACKAGE_VERSION=RS916W.2.5.0.14
)
set DOCKER_BUILDKIT=1
docker build --build-arg RELEASE_PACKAGE_VERSION=%RELEASE_PACKAGE_VERSION% -f test_agent/Dockerfile -t wifi_test_agent_build --ssh default=%USERPROFILE%\.ssh\id_rsa .
if %errorlevel% neq 0 (
   exit /b 1
)

if exist test_agent\build (
    rd /s /q test_agent\build
)
mkdir test_agent\build
docker run --rm -it -v %CD%/test_agent/build:/build/rs911x/Host_MCU/test/sqa_test_agent/build/build wifi_test_agent_build
if %errorlevel% neq 0 (
   exit /b 1
)
copy test_agent\build\debug\sqa_test_agent.hex example_test_package

