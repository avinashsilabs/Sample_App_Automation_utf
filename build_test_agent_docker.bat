@echo off
setlocal

pushd utf_wiseconnect

call build_test_agent_docker.bat %*

popd

copy utf_wiseconnect\test_agent\build\*.hex manifest