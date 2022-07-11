echo "*** setting up workspace ***"
#alias python3='/usr/bin/python3.9'
python_version='python3 --version'

if [ ! $python_version =~ "Python 3" ]; then
  echo "Python 3+ version is not installed"
fi

if [ ! -f venv/bin/activate ]; then
  echo "creating venv"
  python3 -m venv venv
fi

. ./venv/bin/activate

echo "upgrading pip"
python -m pip install --upgrade pip

echo "installing wheel"
pip3 install wheel pyyaml

echo "creating workspace"
python ./utf_core/tools/workspace_setup.py $PWD config/workspace.yaml