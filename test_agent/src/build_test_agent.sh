#!/bin/bash

#projects=("general_test_agent" "concurrent_test_agent")

output_base_dir=${PWD}/build

build_project () {
    pushd $1

    rm -rf ${output_base_dir}/$1

    slc generate --copy-sdk-sources -p sqa_test_agent.slcp -d ${output_base_dir}/$1 -o makefile
    make -C ${output_base_dir}/$1 -f sqa_test_agent.Makefile -j
    cp ${output_base_dir}/$1/build/debug/sqa_test_agent.hex ${output_base_dir}/$1.hex
    python3 ${output_base_dir}/$1/build/debug/sqa_test_agent.hex 1024 > ${output_base_dir}/memory_summaries/$1.txt

    popd

}

mkdir -p ${output_base_dir}/memory_summaries
for project in general_test_agent concurrent_test_agent
do
    build_project $project
done
