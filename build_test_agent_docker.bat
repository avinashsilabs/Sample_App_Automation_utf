@echo off
setlocal

pushd test_agent

set RELEASE_PACKAGE_VERSION=%1
if "%1"=="" (
   set RELEASE_PACKAGE_VERSION=RS916W.2.5.0.14
)
set BUILD_LOCATION=%2
if "%2"=="" (
   set BUILD_LOCATION=release_packages
)
set SSH_KEY=%3
if "%3"=="" (
   set SSH_KEY=%USERPROFILE%\.ssh\id_rsa
)
set DOCKER_BUILDKIT=1
docker build --build-arg RELEASE_PACKAGE_VERSION=%RELEASE_PACKAGE_VERSION% --build-arg BUILD_LOCATION=%BUILD_LOCATION% -t wifi_test_agent_build --ssh default=%SSH_KEY% .
if %errorlevel% neq 0 (
   exit /b 1
)

if exist build (
    rd /s /q build
)
mkdir build
docker run --rm -it -v %CD%/build:/build/src/build wifi_test_agent_build
if %errorlevel% neq 0 (
   exit /b 1
)

popd


copy test_agent\build\*.hex manifest


