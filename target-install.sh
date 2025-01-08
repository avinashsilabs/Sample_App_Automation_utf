#!/bin/bash

pushd $(dirname "$0")
pip3 install -r host-requirements.txt
popd

