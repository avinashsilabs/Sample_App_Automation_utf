#!/bin/bash

pushd utf_wiseconnect || exit 1

. build_test_agent_docker.sh "$@"

popd || exit 1


