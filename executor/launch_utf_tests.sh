#!/bin/bash

set +v

if [ ! -f "../venv/pyvenv.cfg" ]; then
    echo.
    echo Python virtual environment does not exist.  Please run setup_workspace.sh
    echo.
    exit 1
fi

. ../venv/bin/activate
SCRIPT_DIR=$(dirname "$0")
export PYTHONPATH=$SCRIPT_DIR/../utf_core/src:$SCRIPT_DIR/../utf_rail:$SCRIPT_DIR/..
python $SCRIPT_DIR/launch_utf_tests.py "$@"
status=$?
echo launch_utf_tests.py exited with code $status
if [ $status -ne 0 ]; then
  exit 1
fi