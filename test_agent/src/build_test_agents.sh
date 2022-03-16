#!/bin/bash


set -e

echo --------- DEBUG INSIDE DOCKER build_test_agents.sh ---------
ls -ll
echo $UID

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
    build_project $project
done
