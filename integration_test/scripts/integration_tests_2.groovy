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
        stage('Run integration tests set 2') {
            agent {
                label 'LAB0014503'
            }
            environment {
                UTF_HWMUX_TOKEN = credentials('utf-dev-hwmux-token')
                PYTHON3 = "t:\\python_3_9_2_x64\\python.exe"
                HWMUX_GROUP_LABEL = "utf_wifi_integration_smoke_test"
                HWMUX_GROUP_JSON_FILE_NAME = "integration_tests_2_hwmux_group.json"
                HARNESS_NAME= "__hwmux__integration_tests_2.yaml"
                TEST_CONFIG_FILE = "integration_tests_sequence_2.yaml"
            }
            stages {
                stage('Setup Environment') {
                    steps {
                        bat """
                            if not EXIST venv\\pyvenv.cfg (
                               %PYTHON3%  -m venv venv
                            )
                            call workspace_setup.bat skip_gui
                        """
                    }
                }
                stage('Run Integration Tests') {
                    steps {
                        hwmuxReserveAnyGroupFromLabel(HWMUX_GROUP_LABEL, null, UTF_HWMUX_TOKEN, "HWMUX_GROUP_JSON")  {
                            timeout(time: 120, unit: 'MINUTES') {
                                writeFile(file: env.HWMUX_GROUP_JSON_FILE_NAME, text: env.HWMUX_GROUP_JSON)
                                bat(label: "Run UTF Launcher", script: """
                                    type %HWMUX_GROUP_JSON_FILE_NAME% | utf_core\\tools\\jq.exe -r .metadata.host_ip  > tmp_host_ip
                                    set /p UTF_DOCKER_TARGET= < tmp_host_ip
                                    del tmp_host_ip

                                    if not exist yq.exe (
                                        curl -k -L https://github.com/mikefarah/yq/releases/download/v4.21.1/yq_windows_amd64.exe --output yq.exe
                                    )
                                    type %HWMUX_GROUP_JSON_FILE_NAME%  | yq.exe .metadata.harness -P > config\\harnesses\\%HARNESS_NAME%

                                    rd /s /q reports

                                    call venv\\scripts\\activate
                                    copy utf_core\\unit_tests\\.coveragerc integration_test\\.coveragerc
                                    pushd executor

                                    set "PYTEST_COMMAND=pytest --tb=native --tmconfig integration_test/%TEST_CONFIG_FILE% --manifest /app/manifest/manifest_without_aws_test_agent.yaml integration_test"

                                    call launch_utf_tests.bat --harness %HARNESS_NAME% --target %UTF_DOCKER_TARGET% --pytest_command "%PYTEST_COMMAND%"
                                    set exitcode=%ERRORLEVEL%

                                    ssh -o StrictHostKeyChecking=no pi@%UTF_DOCKER_TARGET% "sudo reboot"
                                    :: wait a bit for reboot, otherwise next job may fail
                                    ping -n 15 %UTF_DOCKER_TARGET%
                                    exit /b %exitcode%
                                """)
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