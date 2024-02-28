@Library('utf-pipeline-libraries@main') _

pipeline {
    agent none
    options {
        parallelsAlwaysFailFast()
        quietPeriod(20)
        disableConcurrentBuilds()
        office365ConnectorWebhooks(
            [
                [   // send notifications to 'Jenkins Alerts' channel for failures only
                    name: 'jenkins-alerts', notifyBackToNormal: true, notifyFailure: true, notifyNotBuilt: true,
                    notifyRepeatedFailure: true, notifyUnstable: true,  notifyAborted: true,
                    url: 'https://silabs.webhook.office.com/webhookb2/f32efe2c-4054-44e7-a35a-896d4418e86d@54dbd822-5231-4b20-944d-6f4abcd541fb/JenkinsCI/c20267f6a1a14453b36458912f6c360d/eb415314-edf4-4416-b04b-bc76de139102'
                ]
            ]
        )
    }
    stages {
        stage('Run Smoke tests') {
            agent {
                node "infraswHyderabadNode"
            }
            environment {
                UTF_HWMUX_TOKEN = credentials('utf-dev-hwmux-token')
                HWMUX_GROUP_LABEL = "utf_dev_team_hyd_integration_test"
                HWMUX_GROUP_JSON_FILE_NAME = "integration_tests_3_hwmux_group.json"
                HARNESS_NAME= "__hwmux__integration_tests_3.yaml"
                TEST_CONFIG_FILE = ".sequence_manager/test_execution_definitions/integration_test_3.yaml"
            }
            stages {
                stage('Setup Environment') {
                    steps {
                        sh '''
                        . $PYTHON3_VENV_DIR/bin/activate
                        python3 -m pip install --upgrade pip

                        ./workspace_setup.sh

                        PYTHON3_VENV_DIR=$SCRIPT_DIR/../venv/pyvenv.cfg

                        if ! command -v ./yq &> /dev/null
                        then
                           curl -k -L https://artifactory.silabs.net/artifactory/tcmgr-generic-production/yq/yq_linux_amd64 --output yq
                           chmod +x yq
                        fi
                        '''
                    }
                }
                stage('Run Integration Tests') {
                    environment {
                        MILESTONE_BRANCH_NAME = 'staging_milestone'
                    }
                    steps {
                        withCredentials([sshUserPrivateKey(credentialsId: 'mwlabuser_jenkins_ssh', keyFileVariable: 'MWLABUSER_JENKINS_SSH', passphraseVariable: 'PASSPHRASE_UNUSED', usernameVariable: 'USERNAME_UNUSED')]) {
                            hwmuxReserveAnyGroupFromLabel(HWMUX_GROUP_LABEL, null, UTF_HWMUX_TOKEN, "HWMUX_GROUP_JSON")  {
                                timeout(time: 120, unit: 'MINUTES') {
                                    writeFile(file: env.HWMUX_GROUP_JSON_FILE_NAME, text: env.HWMUX_GROUP_JSON)
                                    sh(label: "Run UTF Launcher", script: '''
                                        UTF_DOCKER_TARGET=$(./yq eval '.metadata.host_ip' $HWMUX_GROUP_JSON_FILE_NAME)
                                        ./yq eval '.metadata.harness' $HWMUX_GROUP_JSON_FILE_NAME  -P > config/harnesses/$HARNESS_NAME
                                        rm -rf reports

                                        . $PYTHON3_VENV_DIR/bin/activate
                                        cp utf_core/unit_tests/.coveragerc integration_test/.coveragerc

                                        PYTEST_COMMAND="pytest --tb=native --tmconfig integration_test/$TEST_CONFIG_FILE --manifest /app/manifest/manifest_without_aws_test_agent.yaml integration_test"
                                        ./executor/launch_utf_tests.sh --harness $HARNESS_NAME --target $UTF_DOCKER_TARGET --pytest_command "$PYTEST_COMMAND"
                                        exitcode=$?

                                        set +e
                                        ssh -i $MWLABUSER_JENKINS_SSH -o StrictHostKeyChecking=no pi@$UTF_DOCKER_TARGET "sudo reboot"
                                        # wait a bit for reboot, otherwise next job may fail
                                        sleep 15
                                        exit $exitcode
                                    ''')
    //                                dir('integration_test') {
    //                                    archiveArtifacts artifacts: env.TEST_CONFIG_FILE
    //                                }
                                    archiveArtifacts artifacts: "reports/pytest-log.txt,reports/junit_report.xml,reports/pytest-report.html"
                                    junit allowEmptyResults: false, testResults: "reports/junit_report.xml"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}