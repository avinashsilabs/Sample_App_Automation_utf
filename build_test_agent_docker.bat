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

@rem temporarily adding -u root to fix following error
@rem 2022-03-15 18:31:40.104 |  /build/src/generic_test_agent /build/src
@rem 2022-03-15 18:31:40.104 |  make: Entering directory '/build/src/generic_test_agent/build'
@rem 2022-03-15 18:31:40.104 |  Building gecko_sdk_3.1.0/hardware/board/src/sl_board_control_gpio.c
@rem 2022-03-15 18:31:40.104 |  Building gecko_sdk_3.1.0/hardware/board/src/sl_board_init.c
@rem 2022-03-15 18:31:40.104 |  Building gecko_sdk_3.1.0/platform/CMSIS/RTOS2/Source/os_systick.c
@rem 2022-03-15 18:31:40.104 |  mkdir: cannot create directory 'build': Permission denied

docker run -u root --rm -it -v %CD%/build:/build/src/build wifi_test_agent_build
if %errorlevel% neq 0 (
   exit /b 1
)

popd


copy test_agent\build\*.hex manifest


