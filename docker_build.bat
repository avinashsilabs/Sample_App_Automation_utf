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
docker run --rm -it wifi_test_agent_build

