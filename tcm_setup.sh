#!/bin/bash

tcm=./tcmgr/tcmgr.sh
inputxml=ToolchainInfoLinux.yaml
projfile=projenv.sh

$tcm $inputxml $projfile
exitcode=$?

if [ $exitcode -eq 0 ]
    then
    echo
    echo Contents of $projfile:
    echo ---------------------------
    cat $projfile
    echo ---------------------------
    echo
    echo Activate project environment by running \'source $projfile\'
    echo
else
    echo FATAL ERROR: Toolchain Manager returned error code \'$exitcode\'
    exit $exitcode
fi

exit 0


