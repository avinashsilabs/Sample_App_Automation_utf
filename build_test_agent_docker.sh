#!/bin/bash

pushd test_agent

RELEASE_PACKAGE_VERSION=$1
if [ -z "$1" ]; then
   RELEASE_PACKAGE_VERSION=RS916W.2.5.0.14
fi
SSH_KEY=$2
if [ -z "$2" ]; then
   SSH_KEY=$HOME/.ssh/id_rsa
fi
BUILD_LOCATION=$3
if [ -z "$3" ]; then
   BUILD_LOCATION=release_packages
fi
export DOCKER_BUILDKIT=1
set -e
docker build --build-arg RELEASE_PACKAGE_VERSION=$RELEASE_PACKAGE_VERSION --build-arg BUILD_LOCATION=$BUILD_LOCATION -t wifi_test_agent_build --ssh default=$SSH_KEY .

rm -rf build
mkdir -p build

docker run -u $UID --rm -t -v ${PWD}/build:/build/rs911x/Host_MCU/test/sqa_test_agent/build/build wifi_test_agent_build

popd

cp ./test_agent/build/debug/sqa_test_agent.hex manifest
