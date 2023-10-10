FIRMWARE=$1
Rps_Path=$2
Rps_Prefix=$3
Customer_Id=$4
prefix=$( echo $FIRMWARE |cut -d '.' -f1 )
major=$( echo $FIRMWARE |cut -d '.' -f2 )
minor=$( echo $FIRMWARE |cut -d '.' -f3 )
patch=$( echo $FIRMWARE |cut -d '.' -f4 )
build=$( echo $FIRMWARE |cut -d '.' -f5 )
if [[ "${FIRMWARE}" == RS9116* ]]; then 
    new_upgrade_fw_value=/RS9116W.$major.$minor.$patch.$build.rps
    sed_param='/upgrade_fw:/,/value:/ s|value:.*|value: "'"$new_upgrade_fw_value"'"|'
    sed -i "$sed_param" config/harnesses/dev_sanity_harness_example.yaml 
    new_upgrade_fw_value=/RS916W.$major.$minor.$patch.$build.rps
    sed_param='/upgrade_fw:/,/value:/ s|value:.*|value: "'"$new_upgrade_fw_value"'"|'
    sed -i "$sed_param" config/harnesses/dev_sanity_harness_example_1_5.yaml
    pwd && ls

    new_upgrade_fw_value=$Rps_Prefix.$major.$minor.$patch.$build.rps
    #sed_param='/firmware:/,/rs911x:/ s|rs911x:.*|rs911x: "'"$new_upgrade_fw_value"'"|'
    sed_param='2 s|RS9116W.2.9.0.1.rps|'"$new_upgrade_fw_value"'|'
    sed -i "$sed_param" manifest/manifest_without_aws_test_agent.yaml
else
    new_upgrade_fw_value=/SiWG917-A.$major.$minor.$patch.$build.rps
    sed_param='/upgrade_fw:/,/value:/ s|value:.*|value: "'"$new_upgrade_fw_value"'"|'
    sed_param='/upgrade_fw:/,/value:/ s|value:.*|value: "'"$new_upgrade_fw_value"'"|'
    sed -i "$sed_param" config/harnesses/dev_sanity_harness_example_9117_A0_NCP.yaml
    pwd && ls

    new_upgrade_fw_value=$Rps_Prefix.$major.$minor.$patch.$build.rps
    sed_param='2 s|RS9116W.2.9.0.1.rps|'"$new_upgrade_fw_value"'|'
    sed -i "$sed_param" manifest/manifest_917_ncp.yaml
fi     
#pwd && ls
#cp rs9116_binary/$FIRMWARE/$Rps_Path/*.rps utf_core/src/utf/interfaces/http/www
#mv rs9116_binary/$FIRMWARE/$Rps_Path/$Rps_Prefix.$major.$minor.$patch.$Customer_Id.$build.rps rs9116_binary/$FIRMWARE/$Rps_Path/$Rps_Prefix/$prefix.$major.$minor.$patch.$build.rps
#cp rs9116_binary/$FIRMWARE/$Rps_Path/$Rps_Prefix.$major.$minor.$patch.$build.rps manifest/
#new_upgrade_fw_value=$Rps_Prefix.$major.$minor.$patch.$build.rps
#sed_param='/firmware:/,/rs911x:/ s|rs911x:.*|rs911x: "'"$new_upgrade_fw_value"'"|'
#sed -i "$sed_param" manifest/manifest.yaml