#!/bin/bash


set -e

output_base_dir=${PWD}/build
map_file_parser=${PWD}/../map_file_parser.py

build_project () {
    pushd $1
    
    rm -rf ${output_base_dir}/$1
    
    make -C build -f $1.Makefile -j
    cp -r build ${output_base_dir}/$1
    cp ${output_base_dir}/$1/build/debug/$1.hex ${output_base_dir}/$1.hex
    python3 ${map_file_parser} ${output_base_dir}/$1/build/debug/$1.map 1024 > ${output_base_dir}/memory_summaries/$1.txt

    popd

}

mkdir -p ${output_base_dir}/memory_summaries
IFS=' '
for project in $PROJECT_LIST
do
 echo $project
   echo $project $SRC_ROOT $GECKO_SDK
   cp -r ${SDK_PATCHES}/* ${GECKO_SDK}/platform/radio/wifi/rs9116
   cp -r ${SRC_ROOT}/${CURRENT_PROJ_PATH}/sdk_patches/* ${GECKO_SDK}/platform/radio/wifi/rs9116
   build_project $project
done
