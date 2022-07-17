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
    parameters {
        booleanParam description: 'Set to true to enable code coverage reporting', name: 'ENABLE_COVERAGE'
    }
    stages {
        stage('Run Unit Tests and Integration Tests in Parallel') {
            parallel {
//                 stage('Unit Test Setup and Execution') {
//                     agent {
//                         docker {
//                             label 'Docker_Linux'
//                             image 'joesavage71/utf_unit_test'
//                         }
//                     }
//                     stages {
//                         stage("Env Setup") {
//                             steps {
//                                 dir('utf_core') {
//                                     sh """
//                                        if [ ! -d venv ]; then
//                                             python3 -m venv venv
//                                        fi
//                                        . venv/bin/activate
//                                        pip3 install wheel
//                                        pip3 install -r unittest-requirements.txt
//                                     """
//                                 }
//                             }
//                         }
//                         stage("Run Tests") {
//                             environment {
//                                 TEST_RESULTS_DIR = 'unit_tests/test_results'
//                                 HARNESS_NAME = 'unit_test'
//                             }
//                             steps {
//                                 dir('utf_core') {
//                                     sh(label: "Run Pytest", script: '''
//                                         . venv/bin/activate
//                                         if [ -d ${TEST_RESULTS_DIR} ]; then
//                                             rm -rf ${TEST_RESULTS_DIR}
//                                         fi
//                                         mkdir -p ${TEST_RESULTS_DIR}
//                                         set +e
//                                         export COVERAGE_FILE=.coverage.unit
//                                         export PYTHONPATH=${PWD}/src
//                                         python -m pytest unit_tests --junitxml=${TEST_RESULTS_DIR}/junit_report_unit.xml --cov-branch --cov=utf --cov-config=unit_tests/.coveragerc
//                                         exitcode=$?
//                                         flake8 . > flake8.txt
//                                         exit $exitcode
//                                     ''')
//                                     archiveArtifacts artifacts: 'flake8.txt,.coverage.unit'
//                                     archiveArtifacts artifacts: "${TEST_RESULTS_DIR}/junit_report_*.xml"
//                                     junit allowEmptyResults: false, testResults: "${TEST_RESULTS_DIR}/junit_report_*.xml"
//                                     stash includes: '.coverage.unit', name: 'unit_test_coverage_data'
//                                     stash includes: 'flake8.txt', name: 'flake8_report'
//                                 }
//                             }
//                         }
//                     }
//                 }
                stage('Run integration tests set 1') {
                    agent {
                        label 'NB0015129'
                    }
                    environment {
                        UTF_HWMUX_TOKEN = credentials('utf-dev-hwmux-token')
                        PYTHON3 = "t:\\python_3_9_2_x64\\python.exe"
                        HWMUX_GROUP_LABEL = "utf_integration_test"
                        HWMUX_GROUP_JSON_FILE_NAME = "integration_tests_1_hwmux_group.json"
                        HARNESS_NAME= "__hwmux__integration_tests_1.yaml"
                        TEST_CONFIG_FILE = ".sequence_manager/test_execution_definitions/integration_test_1.yaml"
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

                                            if "%TEST_CONFIG_FILE%"=="" (
                                                set TEST_CONFIG_FILE=integration_tests_sequence_1.yaml
                                            )

                                            set "PYTEST_COMMAND=pytest --tb=native --tmconfig integration_test/%TEST_CONFIG_FILE% --manifest /app/manifest/manifest_without_aws_test_agent.yaml integration_test"
                                            if "%ENABLE_COVERAGE%"=="true" (
                                               set "PYTEST_COMMAND=coverage run --branch --rcfile=integration_test/.coveragerc --source=utf -m %PYTEST_COMMAND% | tee /app/reports/pytest-log.txt"
                                            )

                                            call launch_utf_tests.bat --harness %HARNESS_NAME% --target %UTF_DOCKER_TARGET% --pytest_command "%PYTEST_COMMAND%" --docker_flags "-e COVERAGE_FILE=/app/reports/.coverage.integration"
                                            set exitcode=%ERRORLEVEL%

                                            if "%ENABLE_COVERAGE%"=="true" (
                                                copy reports\\.coverage.integration .
                                            )
                                            ssh -o StrictHostKeyChecking=no pi@%UTF_DOCKER_TARGET% "sudo reboot"
                                            :: wait a bit for reboot, otherwise next job may fail
                                            ping -n 15 %UTF_DOCKER_TARGET%
                                            exit /b %exitcode%
                                        """)
                                        dir('integration_test') {
                                            archiveArtifacts artifacts: env.TEST_CONFIG_FILE
                                        }
                                        script {
                                            if (env.ENABLE_COVERAGE == "true") {
                                                stash includes: '.coverage.integration', name: 'integration_test_coverage_data'
                                                archiveArtifacts artifacts: ".coverage.integration"
                                            }
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
        stage('Generate Coverage Report and Run Sonarqube Analysis') {
            when {
                environment name: 'ENABLE_COVERAGE', value: 'true'
                beforeAgent true
            }
            agent {
                docker {
                    label 'Docker_Linux'
                    image 'joesavage71/utf_unit_test'
                }
            }
            environment {
                GIT_HASH = GIT_COMMIT.take(10)
                COVERAGE_FILE = "unit_tests/.coveragerc"
                COVERAGE_REPORT = "unit_tests/test_results/coverage.xml"
            }
            steps {
                dir('utf_core') {
                    withSonarQubeEnv(installationName: 'SILABS_SONARQUBE_SERVER') {
                        sh '''
                            set +e
                            rm -rf .coverage.*
                            rm -rf cov_html
                            rm -rf unit_tests/test_results/coverage.xml
                            exit 0
                        '''
                        unstash 'unit_test_coverage_data'
                        unstash 'integration_test_coverage_data'
                        unstash 'flake8_report'
                        sh '''
                            if [ ! -d venv ]; then
                                python3 -m venv venv
                            fi
                            . venv/bin/activate
                            pip3 install coverage

                            coverage combine --rcfile=$COVERAGE_FILE .coverage.unit .coverage.integration
                            coverage xml -o $COVERAGE_REPORT --rcfile=$COVERAGE_FILE
                            coverage html -d cov_html --rcfile=$COVERAGE_FILE

                            ${SONAR_SCANNER} -Dsonar.projectVersion=${GIT_HASH}
                        '''
                    }
                    archiveArtifacts artifacts: "cov_html/*.*,${COVERAGE_REPORT}"
                    cobertura autoUpdateHealth: false, autoUpdateStability: false, coberturaReportFile: "${COVERAGE_REPORT}", conditionalCoverageTargets:'70,0,0', failUnhealthy:false, failUnstable:false, lineCoverageTargets: '80,0,0', maxNumberOfBuilds:0, methodCoverageTargets: '80,0,0', onlyStable:false, sourceEncoding:'ASCII', zoomCoverageChart: false
                }
            }
        }
    }
}