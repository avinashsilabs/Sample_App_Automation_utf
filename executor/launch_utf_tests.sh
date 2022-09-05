#!/bin/bash

set +v

if [ ! -f "../venv/pyvenv.cfg" ]; then
    echo.
    echo Python virtual environment does not exist.  Please run setup_workspace.sh
    echo.
    exit 1
fi

. ../venv/bin/activate
export PYTHONPATH=../utf_core/src
python launch_utf_tests.py %*