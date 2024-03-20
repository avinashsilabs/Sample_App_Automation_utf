@Library('pipeline-shared-library@main') _
import groovy.json.JsonSlurper
import main.groovy.HWMuxUtils
import groovy.json.JsonSlurperClassic
import groovy.json.JsonOutput

pipeline {
    agent {
        label 'nomadagent-utf_wifi'
    }
    environment {
        UTF_HWMUX_TOKEN = credentials('utf-sqa-hwmux-token')
        ARTIFACTORY_CREDENTIALS = credentials('artifactory-username-password')
        JENKINS_USER_NAME = "${sh(script:'id -un', returnStdout: true).trim()}"
        JENKINS_USER_ID = "${sh(script:'id -u', returnStdout: true).trim()}"
        JENKINS_GROUP_ID = "${sh(script:'id -g', returnStdout: true).trim()}"
        LOKI_URL = "https://loki-distributor.silabs.net/loki/api/v1/push"
        BASE_ARTIFACTORY_URL= "https://artifactory-local.silabs.net/artifactory/iotwifi-generic-development/sl_net-917-smoketest"
        STACK = "WIFI"
        JENKIN_RUN_NUM = "${BUILD_NUMBER}"
        JENKINS_JOB_NAME = "${JOB_NAME}"
        JENKINS_JOB_STAGE_NAME = "Run Tests"
        variables_set = false
        teastagent_executed = false
        UTF_WISECONNECT_COMMIT = null
        UTF_WIFI_COMMIT = null
        UTF_CORE_COMMIT = null
        
    }
    options {
        globalLock(credentialsId: 'utf-sqa-hwmux-token', deviceGroup: env.device_group_name, label: env.device_group_label, variable: 'data')
    }
    stages{
        stage("parallel"){
            failFast true // Fail all branches if any branch fails
            parallel{
                stage("main_pipeline"){
                    stages{
                        stage('Toolchain Setup'){
                            steps {
                                cleanWs()
                                script {
                                    if (env.SQA_TEST_AGENT == "") {
                                        env.SQA_TEST_AGENT = env.FIRMWARE_NAME
                                    }
                                    echo env.SSH_TARGET
                                    echo env.HARNESS_NAME
                                    echo "${env.data}"
                                    configString = env.data.trim()
                                    def configJSON = readJSON text: configString
                                    print  configJSON["a_device_groups"][0]
                                    id_num=configJSON["a_device_groups"][0]
                                    def hwmuxUtils = new HWMuxUtils()
                                    url= "https://hwmux.silabs.net/api/groups/${id_num}/"
                                    def responseJson = hwmuxUtils.httpCallToJson(url, 'GET', '200', null, UTF_HWMUX_TOKEN)
                                    echo JsonOutput.toJson(responseJson)
                                    env.tests_url= env.JENKINS_URL + 'view/UTF/job/'+env.JOB_NAME+ '/'+env.BUILD_NUMBER + '/testReport/'

                                  
                                    env.RELEASE_NAME = "${Release_Name}"     
                                    env.BRANCH_NAME = "${SDK_BRANCH_NAME}"
                                    env.build = sh(script: "echo ${FIRMWARE_NAME} | cut -d '.' -f5", returnStdout: true).trim()
                                    env.SDK_BUILD_NUM = build
                                    env.SDK_URL = "https://artifactory-local.silabs.net/artifactory/iotwifi-generic-staging/wifi_release_packages/release_packages/RS9116_WiSeConnect_SDK/$FIRMWARE_NAME"
                                    env.JENKINS_SERVER_NAME = "${JENKINS_URL}"
                                    env.JENKIN_RUN_NUM_VAR = "${BUILD_NUMBER}"
                                    env.JENKINS_TEST_RESULTS_URL = "${tests_url}"
                                    env.TESTBED_NAME = "${SSH_TARGET}"
                                    env.major=FIRMWARE_NAME.split("\\.")[1]
                                    env.minor=FIRMWARE_NAME.split("\\.")[2]
                                    env.patch=FIRMWARE_NAME.split("\\.")[3]
                                    env.build_num=FIRMWARE_NAME.split("\\.")[4]

                                    if (device_group_name == "utf_sqa_smoke_test_device_group") {
                                        env.JOB_TYPE = "smoke"
                                    } else {
                                        env.JOB_TYPE = "regression"

                                    }
                                    def causes = currentBuild.rawBuild.getCauses()
                                    def startedByUser = null
                                    
                                    for (cause in causes) {
                                        if (cause.class == hudson.model.Cause$UserIdCause) {
                                            startedByUser = cause.userName
                                            break
                                        }
                                    }
                                    
                                    if (startedByUser) {
                                        echo "This job was started by ${startedByUser}."
                                    } else {
                                        echo "This job was not manually triggered by a user."
                                    }
                                    env.BUILD_USER_ID = startedByUser  
                                   
                                  
                                }   
                                withCredentials([sshUserPrivateKey(credentialsId: 'mwlabuser-ssh-username-key', \
                                                                    keyFileVariable: 'JENKINS_SSH_KEY_PATH', \
                                                                    passphraseVariable: 'SSH_KEY_PATH_PASSPHRASE', \
                                                                    usernameVariable: 'SSH_KEY_USERNAME')]) {
                                    sh '''
                                        export GIT_SSH=ssh
                                        export GIT_SSH_COMMAND="ssh -i ${JENKINS_SSH_KEY_PATH} -o StrictHostKeyChecking=no"
                                        git clone --single-branch --branch ${UTF_WIFI_BRANCH} --no-tags ssh://git@bitbucket-hyd.silabs.com/iot_infra_sw/utf_wifi.git .
                                   
                                        ls -l
                                        git submodule update --init --recursive   
                                        cd utf_wiseconnect_3
                                        git checkout  ${SL_NET_COMMIT}
                                    '''
                                }
                                     
                               
                                script {
                                    UTF_WISECONNECT_COMMIT = sh(script: "git submodule status utf_wiseconnect | awk '{print \$1}'", returnStdout: true).trim()
                                    UTF_WIFI_COMMIT = sh(script: "git rev-parse HEAD", returnStdout: true).trim()
                                    url = "${BASE_ARTIFACTORY_URL}/${ARTIFACTORY_FOLDER}/${FIRMWARE_NAME}/${SL_NET_COMMIT}"
                                  
                                    variables_set = true
                                    if(isUnix()) {
                                        sh '''
                                           ./workspace_setup.sh
                                   
                                        '''
                                    } else {
                                        bat '''
                                            call workspace_setup.bat
                                        '''
                                    }
                                }
                            }
                        }
                        stage('Get rs9116 binary') {
                            steps{
                                script{
                                    if(BUILD_LOCATION != "source_code"){
                                        if(FIRMWARE_NAME != "Internal"){
                                                withCredentials([usernamePassword(credentialsId: 'artifactory-username-password', passwordVariable: 'PASSWORD', usernameVariable: 'USERNAME')]) {
                                                def read_path = readYaml(file: 'jenkins_scripts/build_info.yaml')
                                                env.rps_file_path = read_path['rps_path']["${build_type}"]["path"]
                                                env.customer_id = read_path['rps_path']["${build_type}"]["customerid"]
                                                env.rps_file_prefix = read_path['rps_path']["${build_type}"]["rps_prefix"]
                                                env.security_bit = read_path['rps_path']["${build_type}"]["security_bit"]
                                                PACKAGE_TYPE=FIRMWARE_NAME.split("\\.")[0]
                                                withEnv(["PACKAGE_TYPE=${PACKAGE_TYPE}","rps_file_prefix=${rps_file_prefix}","customer_id=${customer_id}","rps_file_path=${rps_file_path}"]){
                                                    if(BUILD_LOCATION == "build_artifacts"){
                                                        sh '''
                                                            rm -rf rs9116_binary
                                                            mkdir rs9116_binary
                                                            cd rs9116_binary
                                                            if [[ "${FIRMWARE_NAME}" == RS9116W.* ]]; then
                                                                    wget https://artifactory-local.silabs.net/artifactory/iotwifi-generic-development/wifi_build_artifacts/build_artifacts/RS9116W/${FIRMWARE_NAME}.zip 
                                                                    python3 ../jenkins_scripts/normalize_release_packages.py "${BUILD_LOCATION}" "${FIRMWARE_NAME}" 
                                                                elif wget --spider "https://artifactory-local.silabs.net/artifactory/iotwifi-generic-development/wifi_build_artifacts/build_artifacts/${PACKAGE_TYPE}/${FIRMWARE_NAME}/${rps_file_prefix}.${major}.${minor}.${security_bit}.${patch}.${customer_id}.${build_num}.rps" 2>/dev/null; then
                                                                    mkdir ${FIRMWARE_NAME}
                                                                    cd  ${FIRMWARE_NAME}
                                                                    wget https://artifactory-local.silabs.net/artifactory/iotwifi-generic-development/wifi_build_artifacts/build_artifacts/${PACKAGE_TYPE}/${FIRMWARE_NAME}/${rps_file_prefix}.${major}.${minor}.${security_bit}.${patch}.${customer_id}.${build_num}.rps
                                                                    mv ${rps_file_prefix}.${major}.${minor}.${security_bit}.${patch}.${customer_id}.${build_num}.rps  ${rps_file_prefix}.${major}.${minor}.${patch}.${build_num}.rps
                                                                    cp -r * ../../utf_core/src/utf/interfaces/http/www
                                                                    cp -r * ../../manifest/
                                                                else
                                                                    wget https://artifactory.silabs.net/artifactory/iotwifi-generic-development/wifi_build_artifacts/build_artifacts/${PACKAGE_TYPE}/${FIRMWARE_NAME}/${FIRMWARE_NAME}.zip
                                                                    unzip ${FIRMWARE_NAME}.zip

                                                                    cp -r ${FIRMWARE_NAME}/${rps_file_path}/*.rps ../utf_core/src/utf/interfaces/http/www
                                                                    mv ${FIRMWARE_NAME}/${rps_file_path}/${rps_file_prefix}.${major}.${minor}.${security_bit}.${patch}.${customer_id}.${build_num}.rps  ${FIRMWARE_NAME}/${rps_file_path}/${rps_file_prefix}.${major}.${minor}.${patch}.${build_num}.rps
                                                                    cp -r ${FIRMWARE_NAME}/${rps_file_path}/${rps_file_prefix}.${major}.${minor}.${patch}.${build_num}.rps ../utf_core/src/utf/interfaces/http/www
                                                                    cp -r ${FIRMWARE_NAME}/${rps_file_path}/${rps_file_prefix}.${major}.${minor}.${patch}.${build_num}.rps ../manifest/
                                                                fi
                                                        '''
                                                    } else {
                                                        sh '''
                                                            rm -rf rs9116_binary
                                                            mkdir rs9116_binary
                                                            cd rs9116_binary
                                                            if [[ "${FIRMWARE_NAME}" == RS9116W.* ]]; then
                                                                    wget https://artifactory-local.silabs.net/artifactory/iotwifi-generic-staging/wifi_release_packages/release_packages/RS9116W/${FIRMWARE_NAME}.zip
                                                                    python3 ../jenkins_scripts/normalize_release_packages.py "${BUILD_LOCATION}" "${FIRMWARE_NAME}" 
                                                                elif wget --spider "https://artifactory-local.silabs.net/artifactory/iotwifi-generic-staging/wifi_release_packages/release_packages/${PACKAGE_TYPE}/${FIRMWARE_NAME}/${rps_file_prefix}.${major}.${minor}.${security_bit}.${patch}.${customer_id}.${build_num}.rps" 2>/dev/null; then
                                                                    mkdir ${FIRMWARE_NAME}
                                                                    cd  ${FIRMWARE_NAME}
                                                                    wget https://artifactory-local.silabs.net/artifactory/iotwifi-generic-staging/wifi_release_packages/release_packages/${PACKAGE_TYPE}/${FIRMWARE_NAME}/${rps_file_prefix}.${major}.${minor}.${security_bit}.${patch}.${customer_id}.${build_num}.rps   
                                                                    mv ${rps_file_prefix}.${major}.${minor}.${security_bit}.${patch}.${customer_id}.${build_num}.rps  ${rps_file_prefix}.${major}.${minor}.${patch}.${build_num}.rps  
                                                                    cp * ../../utf_core/src/utf/interfaces/http/www
                                                                    cp * ../../manifest/                                               
                                                                else
                                                                    wget https://artifactory.silabs.net/artifactory/iotwifi-generic-staging/wifi_release_packages/release_packages/${PACKAGE_TYPE}/${FIRMWARE_NAME}/${FIRMWARE_NAME}.zip
                                                                    unzip ${FIRMWARE_NAME}.zip

                                                                    cp ${FIRMWARE_NAME}/${rps_file_path}/*.rps ../utf_core/src/utf/interfaces/http/www
                                                                    mv ${FIRMWARE_NAME}/${rps_file_path}/${rps_file_prefix}.${major}.${minor}.${security_bit}.${patch}.${customer_id}.${build_num}.rps  ${FIRMWARE_NAME}/${rps_file_path}/${rps_file_prefix}.${major}.${minor}.${patch}.${build_num}.rps
                                                                    cp ${FIRMWARE_NAME}/${rps_file_path}/${rps_file_prefix}.${major}.${minor}.${patch}.${build_num}.rps ../utf_core/src/utf/interfaces/http/www
                                                                    cp ${FIRMWARE_NAME}/${rps_file_path}/${rps_file_prefix}.${major}.${minor}.${patch}.${build_num}.rps ../manifest/
                                                                fi
                                                        '''
                                                    }
                                                }
                                            }
                                            dir('rs9116_binary'){
                                                sh '''
                                                if [ -d venv/bin ]; then
                                                . venv/bin/activate
                                                elif [ -d venv/Scripts ]; then
                                                . venv/Scripts/activate
                                                fi
                                                

                                                '''
                                            }
                
                                                sh '''
                                                pwd && ls
                                                bash -ex jenkins_scripts/initialize_config.sh ${FIRMWARE_NAME} ${rps_file_path} ${rps_file_prefix} ${customer_id} ${build_type} ${security_bit}
                                                cat config/harnesses/dev_sanity_harness_example.yaml
                                                ls utf_core/src/utf/interfaces/http/www
                                            '''
                                        }
                                    } else {
                                        echo "Skipping release package checkout for RS9116 firmware."
                                    }
                                }
                            }
                        }
                        stage("Download hexfiles"){
                            steps{
                                script{
                                    waitUntil(initialRecurrencePeriod: 10, quiet: true)
                                    {
                                        script
                                        {
                                            return teastagent_executed == true
                                        }
                                    }

                                    PACKAGE_TYPE=FIRMWARE_NAME.split("\\.")[0]
                                    withEnv(["PACKAGE_TYPE=${PACKAGE_TYPE}"]){
                                        sh '''
                                        cd manifest
                                        # Specify a local directory to save the downloaded files
                                        jf rt dl --flat --url "https://artifactory.silabs.net/artifactory"  --insecure-tls --user $ARTIFACTORY_CREDENTIALS_USR --password $ARTIFACTORY_CREDENTIALS_PSW  "iotwifi-generic-development/wifi_build_artifacts/build_artifacts/${ARTIFACTORY_FOLDER}/${FIRMWARE_NAME}/${SL_NET_COMMIT}/"                          
                                        ls -l
                                                                        
                                        '''
                                    }
                                }
                            }
                        }
                        stage('Update manifest yaml'){
                            steps {
                                sh '''
                                    if [ -d venv/bin ]; then
                                        . venv/bin/activate
                                    else
                                        . venv/Scripts/activate
                                    fi

                                '''
                            }
                        }
                        stage('Run Tests') {
                            steps {
                                echo BUILD_URL
                                echo BUILD_NUMBER
                                echo UTF_WIFI_BRANCH
                                echo RUN_TESTS_DISPLAY_URL
                                echo FIRMWARE_NAME
                                echo PUBLISH_TEST_RESULTS
                                withEnv(['JENKINS_SERVER_NAME='+BUILD_URL, 'JENKIN_RUN_NUM='+BUILD_NUMBER, 'UTF_WIFI_BRANCH='+UTF_WIFI_BRANCH, 'JENKINS_TEST_RESULTS_URL='+RUN_TESTS_DISPLAY_URL, 'SDK_URL=https://artifactory-local.silabs.net/artifactory/iotwifi-generic-staging/wifi_release_packages/release_packages/RS9116_WiSeConnect_SDK/$FIRMWARE_NAME/$FIRMWARE_NAME']){
                                        sh "echo \$BUILD_URL"
                                        sh "echo \$BUILD_NUMBER"
                                        sh "echo \$UTF_WIFI_BRANCH"
                                        sh "echo \$RUN_TESTS_DISPLAY_URL"
                                        sh "echo \$INSTALLER_URL_SDK"
                                }
                                script{
                                    try{
                                        sh '''
                                            rm -rf reports
                                            export SKIP_PROCESSING_ARTIFACTS=1

                                            if [ -d venv/bin ]; then
                                            . venv/bin/activate
                                            else
                                            . venv/Scripts/activate
                                            fi
                                            echo "${RELEASE_NAME}"
                                            echo "${BRANCH_NAME}"
                                            echo "check_here"

                                            export PYTHONPATH=./utf_core/src
                                            export QUERY_EXPR=$(printf '{stack=\\\\"%s\\\\",job=\\\\"%s\\\\",stage=\\\\"%s\\\\",build=\\\\"%s\\\\"}' "${STACK}" "${JENKINS_JOB_NAME}" "${JENKINS_JOB_STAGE_NAME}" "${JENKIN_RUN_NUM}")
                                            export GRAFANA_BASE_URL="https://grafana.silabs.net/explore?orgId=1^&left="
                                            export GRAFANA_PARAMS="{\\"datasource\\":\\"loki-production\\",\\"queries\\":[{\\"expr\\":\\"${QUERY_EXPR}\\",\\"maxLines\\":10000}],\\"range\\":{\\"from\\":\\"now-1d\\",\\"to\\":\\"now\\"}}"
                                            export CONVERT_URL_CMD="import urllib.parse; import os; print('View live logs for this test run at ' + os.environ['GRAFANA_BASE_URL'] + urllib.parse.quote(os.environ['GRAFANA_PARAMS']))"
                                            python -c "${CONVERT_URL_CMD}"

                                            export QUERY_EXPR=$(printf '{stack=\\\\"%s\\\\",job=\\\\"%s\\\\",stage=\\\\"%s\\\\",build=\\\\"%s\\\\"}' "${STACK}" "${JENKINS_JOB_NAME}" "${JENKINS_JOB_STAGE_NAME}" "${JENKIN_RUN_NUM}")
                                            export GRAFANA_BASE_URL="https://grafana.silabs.net/explore?orgId=1^&left="
                                            export GRAFANA_PARAMS="{\\"datasource\\":\\"loki-production\\",\\"queries\\":[{\\"expr\\":\\"${QUERY_EXPR}\\",\\"maxLines\\":10000}],\\"range\\":{\\"from\\":\\"now-1d\\",\\"to\\":\\"now\\"}}"
                                            export CONVERT_URL_CMD="import urllib.parse; import os; print('View live logs for this test run at ' + os.environ['GRAFANA_BASE_URL'] + urllib.parse.quote(os.environ['GRAFANA_PARAMS']))"
                                            python -c "${CONVERT_URL_CMD}"

                                            python executor/launch_utf_tests.py \
                                                --target ${SSH_TARGET} \
                                                --pytest_command "${UTF_PYTEST_COMMAND}" \
                                                --harness ${HARNESS_NAME} \
                                                --publish_test_results ${PUBLISH_TEST_RESULTS} \
                                                --test_results_source_api TEST_RAIL_API \
                                                --docker_flags "-e JENKINS_SERVER_NAME=${BUILD_URL}, \
                                                    -e JENKIN_RUN_NUM=${BUILD_NUMBER}, \
                                                    -e JENKINS_TEST_RESULTS_URL=${JOB_URL}${BUILD_NUMBER}/testReport, \
                                                    -e JENKINS_JOB_NAME=${JOB_NAME}, \
                                                    -e SDK_URL=https://artifactory-local.silabs.net/artifactory/iotwifi-generic-staging/wifi_release_packages/release_packages/RS9116_WiSeConnect_SDK/$FIRMWARE_NAME, \
                                                    -e STUDIO_URL=http://bostonstudiomirror/studio/v4/WSQA/rel.2885/, \
                                                    -e TEST_SUITE=OT_Smoke_brd4161a, \
                                                    -e STACK_NAME=${STACK}, \
                                                    -e SSH_TARGET=${SSH_TARGET}, \
                                                    -e GIT_BRANCH=${UTF_WIFI_BRANCH}" \

                                            export exitcode=$?

                                            # ssh -o StrictHostKeyChecking=no pi@${SSH_TARGET} "sudo reboot"
                                            # ping -n 20 ${SSH_TARGET} || true

                                            exit $exitcode
                                        '''
                                    } catch(err) {
                                        echo err.toString()
                                        // Below stages in pipeline won't execute
                                        sh ''' exit 1'''
                                    }
                                }
                            }
                            post {
                                always {
                                    script {
                                        withCredentials([usernamePassword(credentialsId: 'artifactory-username-password', passwordVariable: 'PASSWORD', usernameVariable: 'USERNAME')]) {
                                            //archiveArtifacts 'example_test_package/**'
                                            //archiveArtifacts 'manifest/**'
                                            archiveArtifacts 'reports/**'
                                            // archiveArtifacts "config/harnesses/${env.HARNESS_NAME}"
                                            junit allowEmptyResults: false, testResults: 'reports/junit_report.xml'
                                            sh '''
                                            zip -r reports.zip reports -x "*.pcap"
                                            curl -u ${USERNAME}:${PASSWORD} -X PUT "https://artifactory-local.silabs.net/artifactory/iotwifi-generic-development/wifi_build_artifacts/build_artifacts/${JOB_NAME}/${BUILD_NUMBER}/reports/" -T reports.zip
                                            curl -u ${USERNAME}:${PASSWORD} -X PUT "https://artifactory-local.silabs.net/artifactory/iotwifi-generic-development/wifi_build_artifacts/build_artifacts/${JOB_NAME}/${BUILD_NUMBER}/config/harnesses/${HARNESS_NAME}" -T config/harnesses/${HARNESS_NAME}
                                            rm -rf reports
                                            '''
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                stage('Build sqa test agent binary') {
                     environment 
                    {
                        // Setting HOME to root folder is needed to access /.yakka tools.
                        HOME = '/'
                    }
                   
                    steps{
                        script{
                            if(SQA_TEST_AGENT != "Internal"){
                                withCredentials([sshUserPrivateKey(credentialsId: 'mwlabuser-ssh-username-key', \
                                                            keyFileVariable: 'JENKINS_SSH_KEY_PATH', \
                                                            passphraseVariable: 'SSH_KEY_PATH_PASSPHRASE', \
                                                            usernameVariable: 'SSH_KEY_USERNAME')]) {
                                    PACKAGE_TYPE=FIRMWARE_NAME.split("\\.")[0]
                                    waitUntil(initialRecurrencePeriod: 10, quiet: true)
                                    {
                                        script
                                        {
                                            return variables_set == true
                                        }
                                    }
                                                
                                    def statusCode = sh(script: "curl --fail-early -s -o /dev/null -w '%{http_code}' -I -L ${ARTIFACTORY_URL}/${ARTIFACTORY_FOLDER}/${FIRMWARE_NAME}/${SL_NET_COMMIT}", returnStdout: true).trim()                                   
                                    println(statusCode)
                                
                                    if (statusCode == '200') {
                                        sh '''
                                        echo "Artifact is available. Proceeding with the main pipeline."
                                        
                                        ''' 
                                    } else {
                                        echo "Artifact is not available. Triggering the main pipeline."
                                        // Trigger the main pipeline job with propagate=false
                                        build job: '917_sl_net_test_agent', parameters: [ string(name: 'SL_NET_COMMIT', value: params.SL_NET_COMMIT),
                                                                                string(name: 'FIRMWARE_NAME', value: params.FIRMWARE_NAME),   
                                                                                string(name: 'ARTIFACTORY_FOLDER', value: params.ARTIFACTORY_FOLDER) ], propagate: true
                                                                    
                                    }
                                        
                                    teastagent_executed = true
                                        
                                    
                                    
                                }
                            }
                        }
                    }
                }
            }
        }
      
    }
}

