@Library('utf-pipeline-libraries@main') _

pipeline {
    agent none
    options {
        parallelsAlwaysFailFast()
        quietPeriod(20)
        disableConcurrentBuilds()
    }
    stages {
        stage('Run Sanity test') {
            agent {
                label 'Windows'
            }
            environment {
                UTF_HWMUX_TOKEN = credentials('utf-dev-hwmux-token')
                PYTHON3_TAG = 'python_3_9_12_win64_rel_02'
                PYTHON3_HOME = "t:\\$PYTHON3_TAG"
                PYTHON3 = "$PYTHON3_HOME\\python.exe"
                HWMUX_GROUP_LABEL = "utf_dev_team_hyd_integration_test"
                HWMUX_GROUP_JSON_FILE_NAME = "integration_tests_3_hwmux_group.json"
                HARNESS_NAME= "__hwmux__integration_tests_3.yaml"
                TEST_CONFIG_FILE = ".sequence_manager/test_execution_definitions/sanity_test.yaml"
                MWLABUSER_JENKINS_SSH = credentials('mwlabuser_jenkins_ssh')
                DOCKER_BUILD_TIMEOUT = '10800'  // 3 hours (10800 seconds) for Docker image build timeout
            }
            stages {
                stage('Setup Environment') {
                    steps {
                            bat """
                                if not exist %PYTHON3_HOME% (
                                    set GIT_SSH_COMMAND=ssh -i "%MWLABUSER_JENKINS_SSH%" -o StrictHostKeyChecking=no
                                    git clone --depth 1 -b %PYTHON3_TAG% ssh://git@stash.silabs.com/toolchain_external/python_3_9_12_win64.git %PYTHON3_HOME%
                                )
                                
                                if EXIST venv rd /s /q venv
                                %PYTHON3% -m venv venv
                                
                                call workspace_setup.bat skip_gui
                            """
                    }
                }
                stage('Launch Tests') {
                    steps {
                        script {
                            withCredentials([sshUserPrivateKey(credentialsId: 'mwlabuser_jenkins_ssh', keyFileVariable: 'MWLABUSER_JENKINS_SSH', passphraseVariable: 'PASSPHRASE_UNUSED', usernameVariable: 'USERNAME_UNUSED')]) {
                                hwmuxReserveAnyGroupFromLabel(HWMUX_GROUP_LABEL, null, UTF_HWMUX_TOKEN, "HWMUX_GROUP_JSON")  {
                                    timeout(time: 180, unit: 'MINUTES') {
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
    }
    post {
        always {
            script {
                def prev = currentBuild.previousBuild?.result
                def isFixed = currentBuild.currentResult == 'SUCCESS' && prev != null && prev != 'SUCCESS'
                if (currentBuild.currentResult != 'SUCCESS' || isFixed) {
                    withCredentials([string(credentialsId: 'teams-webhook-url', variable: 'WEBHOOK_URL')]) {
                        echo "Sending Teams alert: status=${currentBuild.currentResult}"
                        office365ConnectorSend webhookUrl: env.WEBHOOK_URL, status: currentBuild.currentResult
                        echo "Teams alert sent successfully"
                    }
                }
            }
        }
    }
}