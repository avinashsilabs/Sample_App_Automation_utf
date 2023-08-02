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
                label 'LAB0014503'
            }
            environment {
                UTF_HWMUX_TOKEN = credentials('utf-dev-hwmux-token')
                PYTHON3 = "t:\\python_3_9_2_x64\\python.exe"
                HWMUX_GROUP_JSON_FILE_NAME = "integration_tests_3_hwmux_group.json"
                LOKI_URL = "https://loki-distributor.silabs.net/loki/api/v1/push"
                JENKIN_RUN_NUM = "$BUILD_NUMBER"
                JENKINS_JOB_NAME = "$JOB_NAME"
                JENKINS_JOB_STAGE_NAME = "Launch Tests"
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
                stage('Launch Tests') {
                    steps {
                        hwmuxReserveAnyGroupFromLabel(HWMUX_GROUP_LABEL, null, UTF_HWMUX_TOKEN, "HWMUX_GROUP_JSON")  {
                            timeout(time: 600, unit: 'MINUTES') {
                                writeFile(file: env.HWMUX_GROUP_JSON_FILE_NAME, text: env.HWMUX_GROUP_JSON)
                                bat(label: "Run UTF Launcher", script: """
                                    type %HWMUX_GROUP_JSON_FILE_NAME% | utf_core\\tools\\jq.exe -r .metadata.host_ip  > tmp_host_ip
                                    set /p UTF_DOCKER_TARGET= < tmp_host_ip
                                    del tmp_host_ip

                                    :: if not exist yq.exe (
                                    ::     curl -k -L https://github.com/mikefarah/yq/releases/download/v4.21.1/yq_windows_amd64.exe --output yq.exe
                                    :: )
                                    :: type %HWMUX_GROUP_JSON_FILE_NAME%  | yq.exe .metadata.harness -P > config\\harnesses\\%HARNESS_NAME%

                                    rd /s /q reports

                                    call venv\\scripts\\activate
                                    copy utf_core\\unit_tests\\.coveragerc integration_test\\.coveragerc
                                    pushd executor

                                    set "PYTEST_COMMAND=%UTF_PYTEST_COMMAND%"
                                    :: Display Grafana URL for live logs
                                    set QUERY_EXPR={stack=\\"WIFI\\",job=\\"%JENKINS_JOB_NAME%\\",stage=\\"%JENKINS_JOB_STAGE_NAME%\\",build=\\"%JENKIN_RUN_NUM%\\"}
                                    set GRAFANA_BASE_URL=https://grafana.silabs.net/explore?orgId=1^&left=
                                    set GRAFANA_PARAMS={"datasource":"loki-production","queries":[{"expr":"%QUERY_EXPR%","maxLines":10000}],"range":{"from":"now-1d","to":"now"}}
                                    set CONVERT_URL_CMD=import urllib.parse; import os; print('View live logs for this test run at ' + os.environ['GRAFANA_BASE_URL'] + urllib.parse.quote(os.environ['GRAFANA_PARAMS']))
                                    python -c "%CONVERT_URL_CMD%"

                                    call launch_utf_tests.bat --harness %HARNESS_NAME% --target %UTF_DOCKER_TARGET% --pytest_command "%PYTEST_COMMAND%"
                                    set exitcode=%ERRORLEVEL%

                                    ssh -o StrictHostKeyChecking=no pi@%UTF_DOCKER_TARGET% "sudo reboot"
                                    :: wait a bit for reboot, otherwise next job may fail
                                    ping -n 15 %UTF_DOCKER_TARGET%
                                    exit /b %exitcode%
                                """)
                                archiveArtifacts artifacts: "reports/**"
                                junit allowEmptyResults: false, testResults: "reports/junit_report.xml"
                            }
                        }
                    }
                }
            }
        }
    }
}
