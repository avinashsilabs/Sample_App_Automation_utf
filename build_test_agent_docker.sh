#!/bin/bash

pushd utf_wiseconnect || exit 1

. build_test_agent_docker.sh "$@"

popd || exit 1

cp ./utf_wiseconnect/test_agent/build/*.hex manifest