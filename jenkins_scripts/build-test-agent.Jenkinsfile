@Library('pipeline-shared-library@main') _
import groovy.json.JsonSlurper
import main.groovy.HWMuxUtils
import groovy.json.JsonSlurperClassic
import groovy.json.JsonOutput

pipeline {
    agent {
        label 'wifi-testagent'
    }

    environment {
        UTF_HWMUX_TOKEN = credentials('utf-sqa-hwmux-token')
        JENKINS_USER_NAME = "${sh(script:'id -un', returnStdout: true).trim()}"
        JENKINS_USER_ID = "${sh(script:'id -u', returnStdout: true).trim()}"
        JENKINS_GROUP_ID = "${sh(script:'id -g', returnStdout: true).trim()}"
        
    }
    stages{
        stage('Toolchain Setup'){
            steps {
                cleanWs()
                script {
                    env.SQA_TEST_AGENT = env.RS9116_FIRMWARE
                    echo env.SSH_TARGET
                    echo env.HARNESS_NAME
                }
                withCredentials([sshUserPrivateKey(credentialsId: 'mwlabuser-ssh-username-key', \
                                                    keyFileVariable: 'JENKINS_SSH_KEY_PATH', \
                                                    passphraseVariable: 'SSH_KEY_PATH_PASSPHRASE', \
                                                    usernameVariable: 'SSH_KEY_USERNAME')]) {
                    sh '''
                        export GIT_SSH=ssh
                        export GIT_SSH_COMMAND="ssh -i ${JENKINS_SSH_KEY_PATH} -o StrictHostKeyChecking=no"
                       
                        git clone --single-branch --branch ${UTF_WIFI_BRANCH} --no-tags ssh://git@stash.silabs.com/iot_infra_sw/utf_wifi.git .
                        git checkout ${UTF_WIFI_COMMIT}
                        git config --file=.gitmodules submodule.utf_wiseconnect.url ssh://git@stash.silabs.com/utf/utf_wiseconnect
                        git submodule update --init --recursive utf_wiseconnect
                       
                        cd utf_wiseconnect
                        git checkout ${UTF_WISECONNECT_COMMIT}
                    '''
                }
      
            }
        }
        stage('Build sqa test agent binary') {
            steps{
                script{
                    if(SQA_TEST_AGENT != "Internal"){
                        withCredentials([sshUserPrivateKey(credentialsId: 'mwlabuser-ssh-username-key', keyFileVariable: 'JENKINS_SSH_KEY_PATH', passphraseVariable: 'SSH_KEY_PATH_PASSPHRASE', usernameVariable: 'SSH_KEY_USERNAME')]) {
                            withCredentials([usernamePassword(credentialsId: 'artifactory-username-password', passwordVariable: 'ARTIFACTORY_PASSWORD', usernameVariable: 'ARTIFACTORY_USERNAME')]) {
                                PACKAGE_TYPE=RS9116_FIRMWARE.split("\\.")[0]
                                withEnv(["PACKAGE_TYPE=${PACKAGE_TYPE}"]){
                                    sh '''
                                     
                                        mkdir -p reports
                                        ./build_test_agent_docker.sh ${RS9116_FIRMWARE} ${JENKINS_SSH_KEY_PATH} ${BUILD_LOCATION} ${JENKINS_USER_NAME} ${JENKINS_USER_ID} ${JENKINS_GROUP_ID} ${PACKAGE_TYPE}  ${ARTIFACTORY_URL}/  ${ARTIFACTORY_USERNAME} ${ARTIFACTORY_PASSWORD} 
                                        if [ $? -ne 0 ]; then
                                          echo building test agent failed!
                                          exit 1
                                      
                                        fi
                                        ls -l utf_wiseconnect/test_agent
                                        zip -r -j ${PACKAGE_TYPE}.zip utf_wiseconnect/test_agent/build/*.hex
                                        curl -f -u ${ARTIFACTORY_USERNAME}:${ARTIFACTORY_PASSWORD} -X PUT --upload-file ${PACKAGE_TYPE}.zip --url ${ARTIFACTORY_URL}
                                    '''
                                }
                            }    
                        }
                    }
                }
            }
        }
    }
}