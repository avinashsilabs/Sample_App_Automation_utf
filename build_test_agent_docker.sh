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

# Jenkins Username, Id and Group Id if passed from JenkinsFile #jenkins, 995, 997
USERNAME=$4
if [ -z "$4" ]; then
   USERNAME=jenkins
fi

USER_ID=$5
if [ -z "$5" ]; then
   USER_ID=995
fi

GROUP_ID=$6
if [ -z "$6" ]; then
   GROUP_ID=997
fi

export DOCKER_BUILDKIT=1
set -e
docker build --build-arg RELEASE_PACKAGE_VERSION=$RELEASE_PACKAGE_VERSION --build-arg BUILD_LOCATION=$BUILD_LOCATION --build-arg USERNAME="$USERNAME" --build-arg USER_ID="$USER_ID" --build-arg GROUP_ID="$GROUP_ID" -t wifi_test_agent_build --ssh default=$SSH_KEY .

rm -rf build
mkdir -p build

docker run -u $UID --rm -t -v ${PWD}/build:/build/src/build wifi_test_agent_build

popd

cp ./test_agent/build/*.hex manifest
