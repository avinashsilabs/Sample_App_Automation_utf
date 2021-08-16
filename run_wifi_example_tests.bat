setlocal

xcopy /s /i /q /y example_test_package utf_pytest\test_package
pushd utf_pytest
call load_tests_docker.bat %*