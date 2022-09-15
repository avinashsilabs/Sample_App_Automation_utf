#!/bin/bash
SCRIPT_DIR=$(dirname "$0")
echo "*** setting up workspace ***"

if [[ -z "${PYTHON3_VENV_DIR}" ]]; then
  PYTHON3_VENV_DIR=${SCRIPT_DIR}/venv
  if [ ! -f $PYTHON3_VENV_DIR/bin/activate ]; then
    echo "creating virtual environment"
    python3 -m venv $PYTHON3_VENV_DIR
    python3 -m pip install --upgrade pip
    $PYTHON3_VENV_DIR/bin/pip3 install wheel pyyaml
  fi
fi

echo "installing requirements"
. $PYTHON3_VENV_DIR/bin/activate
python3 ./utf_core/tools/workspace_setup.py $PWD config/workspace.yaml
