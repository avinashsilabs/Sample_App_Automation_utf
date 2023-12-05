#below variables are taken from build_info.ynal file , 
FIRMWARE=$1 #varaiable defines firmware name
Rps_Path=$2 #rps_path is defined in build_info.yaml , which describes the path inside the release folder where the rps is located
Rps_Prefix=$3 #rps_prefix is defined in build_info.yaml , which describes the first prefix in rps file name like RS9116W 
Customer_Id=$4 #Customer_Id is defined in build_info.yaml , which describes the customer id of the rps file
Build_type=$5 #Build_type is defined in build_info.yaml , which describes the type of firmware like RS9116_A10, RS9116_A11
prefix=$( echo $FIRMWARE |cut -d '.' -f1 )
major=$( echo $FIRMWARE |cut -d '.' -f2 )
minor=$( echo $FIRMWARE |cut -d '.' -f3 )
patch=$( echo $FIRMWARE |cut -d '.' -f4 )
build=$( echo $FIRMWARE |cut -d '.' -f5 )

#depending up on build_type below commands are updated
#below commands mainly uses shell commands to replace firmware name appropriately in the required yaml files
#Firmware rps file for any build_type will be downloaded with its relative path in rs9116_binary//$FIRMWARE folder when ran by jenkins pipeline, so file operations on rps file will be made accordingly 

if [[ "${Build_type}" == RS9116* ]]; then
    new_upgrade_fw_value=/RS9116W.$major.$minor.$patch.$build.rps
    sed_param='/upgrade_fw:/,/value:/ s|value:.*|value: "'"$new_upgrade_fw_value"'"|'
    sed -i "$sed_param" config/harnesses/dev_sanity_harness_example.yaml 
    new_upgrade_fw_value=/RS916W.$major.$minor.$patch.$build.rps
    sed_param='/upgrade_fw:/,/value:/ s|value:.*|value: "'"$new_upgrade_fw_value"'"|'
    sed -i "$sed_param" config/harnesses/dev_sanity_harness_example_1_5.yaml
    pwd && ls

    new_upgrade_fw_value=$Rps_Prefix.$major.$minor.$patch.$build.rps
    #sed_param='/firmware:/,/rs911x:/ s|rs911x:.*|rs911x: "'"$new_upgrade_fw_value"'"|'
    sed_param='2 s|RS9116W.*|'"$new_upgrade_fw_value"'|'
    sed -i "$sed_param" manifest/manifest_without_aws_test_agent.yaml
elif [ "${Build_type}" == Combo_SDK_9117_NCP ]; then
    new_upgrade_fw_value=/SiWG917-A.$major.$minor.$patch.$build.rps
    sed_param='/upgrade_fw:/,/value:/ s|value:.*|value: "'"$new_upgrade_fw_value"'"|'
    sed_param='/upgrade_fw:/,/value:/ s|value:.*|value: "'"$new_upgrade_fw_value"'"|'
    sed -i "$sed_param" config/harnesses/dev_sanity_harness_example_9117_A0_NCP.yaml
    pwd && ls

    new_upgrade_fw_value=$Rps_Prefix.$major.$minor.$patch.$build.rps
    sed_param='2 s|RS9116W.*|'"$new_upgrade_fw_value"'|'
    sed -i "$sed_param" manifest/manifest_917_ncp.yaml
elif [ "${Build_type}" == 9117_A0_CCP ]; then
    new_upgrade_fw_value=/SiWG917-A.$major.$minor.$patch.$build.bin
    sed_param='/upgrade_fw:/,/value:/ s|value:.*|value: "'"$new_upgrade_fw_value"'"|'
    sed -i "$sed_param" config/harnesses/harness_example_si917_A0_ccp.yaml
    pwd && ls
    cp rs9116_binary/$FIRMWARE/$Rps_Path/new_upgrade_fw_value utf_core/src/utf/interfaces/http/www
    mv rs9116_binary/$FIRMWARE/$Rps_Path/$Rps_Prefix.$major.$minor.$patch.$Customer_Id.$build.bin rs9116_binary/$FIRMWARE/$Rps_Path/$Rps_Prefix.$major.$minor.$patch.$build.bin
    cp rs9116_binary/$FIRMWARE/$Rps_Path/$Rps_Prefix.$major.$minor.$patch.$build.bin manifest/
    new_upgrade_fw_value=$Rps_Prefix.$major.$minor.$patch.$build.bin
    sed_param='4 s|RS9116W.*|'"$new_upgrade_fw_value"'|'
    sed -i "$sed_param" manifest/manifest_917_ccp.yaml
elif [ "${Build_type}" == 9117_B0_CCP ]; then
    new_upgrade_fw_value=/SiWG917-B.$major.$minor.$patch.$build.rps
    sed_param='/upgrade_fw:/,/value:/ s|value:.*|value: "'"$new_upgrade_fw_value"'"|'
    sed -i "$sed_param" config/harnesses/harness_example_si917_B0_ccp.yaml
    pwd && ls
    cp rs9116_binary/$FIRMWARE/$Rps_Path/*.rps utf_core/src/utf/interfaces/http/www
    mv rs9116_binary/$FIRMWARE/$Rps_Path/$Rps_Prefix.$major.$minor.$patch.$Customer_Id.$build.rps rs9116_binary/$FIRMWARE/$Rps_Path/$Rps_Prefix.$major.$minor.$patch.$build.rps
    cp rs9116_binary/$FIRMWARE/$Rps_Path/$Rps_Prefix.$major.$minor.$patch.$build.rps manifest/
    new_upgrade_fw_value=$Rps_Prefix.$major.$minor.$patch.$build.rps
    sed_param='4 s|RS9116W.*|'"$new_upgrade_fw_value"'|'
    sed -i "$sed_param" manifest/manifest_917_ccp.yaml
else
    Build_type is not defined
fi     
#pwd && ls
#cp rs9116_binary/$FIRMWARE/$Rps_Path/*.rps utf_core/src/utf/interfaces/http/www
#mv rs9116_binary/$FIRMWARE/$Rps_Path/$Rps_Prefix.$major.$minor.$patch.$Customer_Id.$build.rps rs9116_binary/$FIRMWARE/$Rps_Path/$Rps_Prefix/$prefix.$major.$minor.$patch.$build.rps
#cp rs9116_binary/$FIRMWARE/$Rps_Path/$Rps_Prefix.$major.$minor.$patch.$build.rps manifest/
#new_upgrade_fw_value=$Rps_Prefix.$major.$minor.$patch.$build.rps
#sed_param='/firmware:/,/rs911x:/ s|rs911x:.*|rs911x: "'"$new_upgrade_fw_value"'"|'
#sed -i "$sed_param" manifest/manifest.yaml
