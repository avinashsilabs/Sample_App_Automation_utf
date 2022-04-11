#!/bin/bash

set -e

generate_project () {
    cp -r -f /build/sdk_patches/* ${GECKO_SDK}/platform/radio/wifi/rs9116
    cp -r -f ${SRC_ROOT}/$project/sdk_patches/* ${GECKO_SDK}/platform/radio/wifi/rs9116 2>/dev/null || :

    pushd $1
    slc generate --generator-timeout=240 --copy-sdk-sources -p project.slcp -d build -o makefile  
    popd

}

IFS=' '
for project in $PROJECT_LIST
do
    generate_project $project
done
