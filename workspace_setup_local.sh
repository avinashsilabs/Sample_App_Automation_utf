#!/bin/bash
# TODO: This file has not been tested yet and needs pipeline validation
# As part of pipeline testing, verify functionality and rectify any minor issues
# that may arise during execution in the CI/CD environment
SCRIPT_DIR=$(dirname "$0")
echo "*** setting up workspace ***"

if [[ -z "${PYTHON3_VENV_DIR}" ]]; then
  PYTHON3_VENV_DIR=${SCRIPT_DIR}/venv
  if [ ! -f $PYTHON3_VENV_DIR/bin/activate ]; then
    echo "creating virtual environment"
    python3 -m venv $PYTHON3_VENV_DIR
    $PYTHON3_VENV_DIR/bin/python3 -m pip install --upgrade pip
    $PYTHON3_VENV_DIR/bin/pip3 install wheel pyyaml
  fi
fi

echo "installing requirements"
. $PYTHON3_VENV_DIR/bin/activate

echo "==========================================================================="
echo "Updating ChromeDriver..."
echo "==========================================================================="
# Install requests if not already installed (required by update_chromedriver.py)
pip3 install requests
python3 update_chromedriver_linux.py
if [ $? -ne 0 ]; then
    echo "WARNING: ChromeDriver update failed. Continuing with workspace setup..."
fi
echo ""

python3 ./utf_core/tools/workspace_setup.py $PWD config/workspace.yaml
if [ $? -ne 0 ]; then
    echo ""
    echo "==========================================================================="
    echo "FATAL ERROR: Workspace setup failed."
    echo "==========================================================================="
    echo ""
    exit 1
fi

echo ""
echo "==========================================================================="
echo "             WORKSPACE SETUP COMPLETED SUCCESSFULLY!"
echo "==========================================================================="
echo ""
echo "==========================================================================="
echo "                    CHROMEDRIVER INSTALLATION INFO"
echo "==========================================================================="
echo ""
echo "ChromeDriver Location: $HOME/chromedriver/chromedriver"
echo ""
echo "==========================================================================="
echo "                      IMPORTANT - NEXT STEPS"
echo "==========================================================================="
echo ""
echo "To use ChromeDriver, add this to your PATH:"
echo "    $HOME/chromedriver"
echo ""
echo "How to add to PATH:"
echo "  For bash (add to ~/.bashrc):"
echo "    echo 'export PATH=\"\$HOME/chromedriver:\$PATH\"' >> ~/.bashrc"
echo "    source ~/.bashrc"
echo ""
echo "  For zsh (add to ~/.zshrc):"
echo "    echo 'export PATH=\"\$HOME/chromedriver:\$PATH\"' >> ~/.zshrc"
echo "    source ~/.zshrc"
echo ""
echo "To verify: Open NEW terminal and run: chromedriver --version"
echo ""
echo "==========================================================================="
echo ""
