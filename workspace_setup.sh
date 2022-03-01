echo "*** setting up workspace ***"
alias python3='/usr/bin/python3.9'

if [ ! -f venv/bin/activate ]; then
  echo "creating venv"
  python3 -m venv venv
fi

. ./venv/bin/activate
echo "installing wheel"
pip3 install wheel pyyaml

echo "creating workspace"
python ./utf_core/tools/workspace_setup.py $PWD config/workspace.yaml