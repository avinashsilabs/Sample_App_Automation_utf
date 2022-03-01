# Initial Workspace Setup

The first step in setting up your workspace is to clone the repo to your PC.  Please ensure that you initialize the submodules when cloning, because they are a key component of the workspace.
After the UTF application repo is cloned to your local workstation, follow the steps below to prepare your workspace for running UTF tests.

## Windows

### Install Python 3  (optional, but recommended)
Python 3 is required to launch UTF tests, but an alternative to installing it locally is to use the embedded python distribution within [Toolchain Manager](./TCMGR.md), so this is an optional step.
However, it's highly recommended to install the full version of Python 3 if you are planning to do any significant python development, since the embedded python version does not integrate as well with the Pycharm debugger as the full version.

#### Download Location
If you choose to install the full version of python 3, you may download it from [here](https://www.python.org/downloads/).  <b>Important:</b> The latest Python 3.9 version is recommended for maximum compatibility with third-party packages.  At the time of this writing, many third-party packages are not compatible with Python 3.10, and it is <b>extremely likely</b> that you will encounter errors during package installation. 
#### Virtual environment creation
Once Python has been downloaded and installed, create a virtual environment in a directory named `venv` in the root folder of your workspace (i.e. the folder in which the UTF application repo was cloned).
To do this, run the following command from a command prompt within the root folder:

`python -m venv venv`

This will create a folder named `venv` within your workspace.

### Run `workspace_setup.bat` to install packages into the virtual environment and install the UTF sequence manager.
From the workspace root folder, run the batch script `workspace_setup.bat`.  This will create a virtual environment (if one was not created previously), and will then install all required python packages into your virtual environment.
The UTF Sequence Manager will be installed next, and a shortcut to launch the GUI will be created in the root folder.

## MacOS / Linux

### Prerequisites

Typical Mac OS and Linux distributions contain a recent version of Python 3.  UTF requires a minimum of version Python 3.7 as well as the [venv](https://docs.python.org/3/library/venv.html) module (which may not be included by default in some linux distributions).

### Run `workspace_setup.sh` to install packages into your virtual environment
From the workspace root folder, run the shell script `workspace_setup.sh`. This will create a virtual environment (if one was not created previously), and will then install all required python packages into your virtual environment.

At this time, the UTF Sequence Manager is not supported on Mac or Linux.
