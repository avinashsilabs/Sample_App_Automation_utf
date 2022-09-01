@Library('utf-pipeline-libraries@main') _

pipeline {
    agent none
    options {
        parallelsAlwaysFailFast()
        quietPeriod(20)
        disableConcurrentBuilds()
        office365ConnectorWebhooks(
            [
                [   // send notifications to 'IOT Infra SW - HYD - Alerts' channel for failures only
                    name: 'utf-dev-team-hyd-jenkins-alerts', notifyBackToNormal: true, notifyFailure: true, notifyNotBuilt: true,
                    notifyRepeatedFailure: true, notifyUnstable: true,  notifyAborted: true,
                    url: 'https://silabs.webhook.office.com/webhookb2/8b1f6858-1a20-4ed5-9358-a7182e6bbeb2@54dbd822-5231-4b20-944d-6f4abcd541fb/JenkinsCI/0c96b07b0334491c8f1990c97220058e/5ed37d9b-6818-4972-a549-6cd1c3ad5a31'
                ]
            ]
        )
    }
    stages {
        stage('Run Sanity test') {
            agent {
                node "infraswBostonNode"
            }
            environment {
                UTF_HWMUX_TOKEN = credentials('utf-dev-hwmux-token')
                HWMUX_GROUP_LABEL = "utf_dev_team_hyd_integration_test"
                HWMUX_GROUP_JSON_FILE_NAME = "integration_tests_3_hwmux_group.json"
                HARNESS_NAME= "__hwmux__integration_tests_3.yaml"
                TEST_CONFIG_FILE = ".sequence_manager/test_execution_definitions/sanity_test.yaml"
            }
            stages {
                stage('Setup Environment') {
                    steps {
                        sh '''
                        ./workspace_setup.sh
                        if ! command -v ./yq &> /dev/null
                        then
                           curl -k -L https://nexus.silabs.net/repository/TCMGR/yq/yq_linux_amd64 --output yq
                           chmod +x yq
                        fi
                        '''
                    }
                }
                stage('Launch Tests') {
                    steps {
                        hwmuxReserveAnyGroupFromLabel(HWMUX_GROUP_LABEL, null, UTF_HWMUX_TOKEN, "HWMUX_GROUP_JSON")  {
                            timeout(time: 120, unit: 'MINUTES') {
                                writeFile(file: env.HWMUX_GROUP_JSON_FILE_NAME, text: env.HWMUX_GROUP_JSON)
                                sh(label: "Run UTF Launcher", script: '''
                                    UTF_DOCKER_TARGET=$(echo $HWMUX_GROUP_JSON_FILE_NAME | ./yq -r .metadata.host_ip)

                                    echo $HWMUX_GROUP_JSON_FILE_NAME  | ./yq .metadata.harness -P > config/harnesses/$HARNESS_NAME

                                    rm -rf reports

                                    . $PYTHON3_VENV_DIR/bin/activate
                                    cp utf_core/unit_tests/.coveragerc integration_test/.coveragerc
                                    cd executor

                                    PYTEST_COMMAND="pytest --tb=native --tmconfig integration_test/$TEST_CONFIG_FILE --manifest /app/manifest/manifest_without_aws_test_agent.yaml integration_test"

                                    set +e
                                    ./launch_utf_tests.sh --harness $HARNESS_NAME --target $UTF_DOCKER_TARGET --pytest_command "$PYTEST_COMMAND"
                                    exitcode=$?

                                    ssh -o StrictHostKeyChecking=no pi@$UTF_DOCKER_TARGET "sudo reboot"
                                    :: wait a bit for reboot, otherwise next job may fail
                                    ping -n 15 $UTF_DOCKER_TARGET
                                    exit $exitcode
                                ''')
                                dir('integration_test') {
                                    archiveArtifacts artifacts: env.TEST_CONFIG_FILE
                                }
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