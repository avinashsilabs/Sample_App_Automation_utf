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
        stage('Run Integration Smoke Tests') {
            agent {
                label 'LAB0014503'
            }
            environment {
                UTF_HWMUX_TOKEN = credentials('utf-dev-hwmux-token')
                PYTHON3 = "t:\\python_3_9_2_x64\\python.exe"
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
                        hwmuxReserveAnyGroupFromLabel('utf_dev_team_hyd_integration_test', null, UTF_HWMUX_TOKEN, "HWMUX_GROUP_JSON")  {
                            timeout(time: 120, unit: 'MINUTES') {
                                writeFile(file: 'smoke_test_hwmux_group.json', text: env.HWMUX_GROUP_JSON)
                                bat(label: "Run UTF Launcher", script: """
                                    type smoke_test_hwmux_group.json | utf_core\\tools\\jq.exe -r .metadata.host_ip  > tmp_host_ip
                                    set /p UTF_DOCKER_TARGET= < tmp_host_ip
                                    del tmp_host_ip

                                    if not exist yq.exe (
                                        curl -k -L https://github.com/mikefarah/yq/releases/download/v4.21.1/yq_windows_amd64.exe --output yq.exe
                                    )
                                    set HARNESS_NAME=__hwmux__-utf_wifi_integration_tests_3.yaml
                                    type smoke_test_hwmux_group.json  | yq.exe .metadata.harness -P > config\\harnesses\\%HARNESS_NAME%

                                    rd /s /q reports

                                    call venv\\scripts\\activate
                                    copy utf_core\\unit_tests\\.coveragerc integration_test\\tests\\.coveragerc
                                    pushd executor

                                    if "%TEST_CONFIG_FILE%"=="" (
                                        set TEST_CONFIG_FILE=integration_tests_sequence_1.yaml
                                    )

                                    set "PYTEST_COMMAND=pytest --tb=native --tmconfig integration_test/%TEST_CONFIG_FILE% --manifest /app/manifest/manifest.yaml integration_test/tests"

                                    call launch_utf_tests.bat --harness %HARNESS_NAME% --target %UTF_DOCKER_TARGET% --pytest_command "%PYTEST_COMMAND%"
                                    set exitcode=%ERRORLEVEL%

                                    ssh -o StrictHostKeyChecking=no pi@%UTF_DOCKER_TARGET% "sudo reboot"
                                    :: wait a bit for reboot, otherwise next job may fail
                                    ping -n 15 %UTF_DOCKER_TARGET%
                                    exit /b %exitcode%
                                """)
                                dir('integration_test/tests') {
                                    archiveArtifacts artifacts: "smoke_test_suite.yaml"
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