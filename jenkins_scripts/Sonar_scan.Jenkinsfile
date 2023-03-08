
pipeline {
    agent {
        label 'cbs-iot-wifi-linux-autoscale'
    }
    environment {
        PIP_OPTIONS = "--trusted-host artifactory.silabs.net --index-url https://artifactory.silabs.net/artifactory/api/pypi/infrasw-python-remote/simple"
        PROJECT = "utf_wifi"
    }
    stages {
        stage("Checkout") {
           steps {
                withCredentials([sshUserPrivateKey(credentialsId: 'mwlabuser-ssh-username-key', 
                                                    keyFileVariable: 'JENKINS_SSH_KEY_PATH', 
                                                    passphraseVariable: 'SSH_KEY_PATH_PASSPHRASE', 
                                                    usernameVariable: 'SSH_KEY_USERNAME')]) {
                    sh '''
                        export GIT_SSH=ssh
                        export GIT_SSH_COMMAND="ssh -i ${JENKINS_SSH_KEY_PATH} -o StrictHostKeyChecking=no"
                        
                        git submodule sync 
                        git config --file=.gitmodules submodule.utf_core.url ssh://git@stash.silabs.com/utf/utf_core.git
                        git config --file=.gitmodules submodule.utf_wiseconnect.url ssh://git@stash.silabs.com/utf/utf_wiseconnect.git
                        git config --file=.gitmodules submodule.tcmgr.url ssh://git@stash.silabs.com/toolchain_internal/tcmgr.git
                        git submodule update --init --recursive

                        ln -s utf_core/src/utf utf
                    '''
                }
            }
        }
        stage("Env Setup") {
            steps {
                sh """
                    
                    if [ ! -d venv ]; then
                        python3 -m venv venv
                    fi
                    . venv/bin/activate
                    python3 -m pip install --upgrade pip
                    pip3 install setuptools==57.5.0
                    pip3 install wheel $PIP_OPTIONS
                    pip3 install -r requirements.txt $PIP_OPTIONS
                """
                dir('utf_core') {
                    sh """
                        . ../venv/bin/activate                      
                        sudo apt-get install libbluetooth-dev -y
                        pip3 install setuptools==57.5.0
                        pip3 install -r unittest-requirements.txt $PIP_OPTIONS

                    """
                }
            }
        }
        stage("Run Tests") {
            environment {
                TEST_RESULTS_DIR = 'integration_test/test_results'
                GIT_HASH = GIT_COMMIT.take(10)
                SONAR = tool name: 'sonarscanner', type: 'hudson.plugins.sonar.SonarRunnerInstallation'
                SONAR_TOKEN = credentials('sonar_token')
            }
            steps {
                    script {
                    sh '''#!/bin/bash

                        . venv/bin/activate
                        if [ -d ${TEST_RESULTS_DIR} ]; then
                            rm -rf ${TEST_RESULTS_DIR}
                        fi
                        mkdir -p ${TEST_RESULTS_DIR}
                        export PYTHONPATH=${PWD}/utf_wifi/src
                        set +e
                        python -m pytest integration_test -v --html=${TEST_RESULTS_DIR}/pytest-report.html --self-contained-html --junitxml=${TEST_RESULTS_DIR}/junit_report_unit.xml --cov-branch --cov-report xml:${TEST_RESULTS_DIR}/coverage.xml --cov-report html:${TEST_RESULTS_DIR}/cov_html --cov=.
                        exitcode=$?

                        flake8 . > flake8.txt

                        exit 0
                    '''
                    archiveArtifacts artifacts: 'flake8.txt'
                    archiveArtifacts artifacts: "${TEST_RESULTS_DIR}/junit_report_*.xml,${TEST_RESULTS_DIR}/cov_html/**/*,${TEST_RESULTS_DIR}/pytest-report.html"
                    junit allowEmptyResults: false, testResults: "${TEST_RESULTS_DIR}/junit_report_*.xml"
                    cobertura autoUpdateHealth: false, autoUpdateStability: false, coberturaReportFile: "${TEST_RESULTS_DIR}/coverage.xml", conditionalCoverageTargets:'70,0,0', failUnhealthy:false, failUnstable:false, lineCoverageTargets: '80,0,0', maxNumberOfBuilds:0, methodCoverageTargets: '80,0,0', onlyStable:false, sourceEncoding:'ASCII', zoomCoverageChart: false

                    withSonarQubeEnv(installationName: 'SILABS_SONARQUBE_SERVER') {
                        script {
                            sh '''
                                ${SONAR}/bin/sonar-scanner -Dsonar.projectVersion=${GIT_HASH} -Dsonar.branch.name=${UTF_WIFI_BRANCH}
                            '''
                            }
                        }
                        sleep time: 30, unit: 'SECONDS'
                    }
                }
            }
        }
     post {
        always {
            script {
                withCredentials([string(credentialsId:'sonar_token',variable:'SONAR_TOKEN')]) {
                    println env.PROJECT
                    sh """               
                        curl -o sonar.json -u ${SONAR_TOKEN}: 'https://sonarqube.silabs.net/api/measures/component?component=${env.PROJECT}&branch=${env.UTF_WIFI_BRANCH}&metricKeys=bugs,new_bugs,vulnerabilities,new_vulnerabilities,security_hotspots,new_security_hotspots,code_smells,new_code_smells,coverage,new_coverage,duplicated_lines,duplicated_lines_density'
                        """
                    def json = readJSON(file: 'sonar.json')
                    def metrics = json.component.measures
                    metrics.each {
                        def metricName = it.metric
                        def metricValue = it.value ?: it.period.value
                        env."${metricName}" = metricValue
                    }
                    def sonarProjectUrl = "https://sonarqube.silabs.net/dashboard?branch=${env.UTF_WIFI_BRANCH}&id=${env.PROJECT}"

                    println env.bugs                       

                    emailext (mimeType: "text/html",
                    to: "languyen@silabs.com, DL.DevOps.BuildAndRelease.Hyd@silabs.com, DL.Hyd-Connectivity-Automation-Team@silabs.com,DL.Wifi.Build.Reports@silabs.com, Aji.Gerdiman@silabs.com,Nik Von Huben Nik.vonHuben@silabs.com, DL.Hyd-Connectivity-Automation-Team@silabs.com",
                    subject: "SonarQube Analysis Results for repository ${env.PROJECT}, branch ${env.UTF_WIFI_BRANCH}",
                    body: """
                    <p>Dear recipients,</p>
                    <p>Please find the result of utf_wifi sonar scanning below:</p>
                    <p><strong>Branch: ${env.UTF_WIFI_BRANCH}</strong></p>
                    <p>Sonar Project URL: <a href="${sonarProjectUrl}">${sonarProjectUrl}</a></p>
                    <table class="tg" style="border-style: hidden;">
                        <thead>
                            <tr>
                                <th class="tg-0lax"><strong>Metric</strong></th>
                                <th class="tg-0lax">Results</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td class="tg-de2y"><strong>Bugs</strong></td>
                                <td class="tg-de2y" style="text-align: right;">${env.bugs}</td>
                            </tr>
                            <tr>
                                <td class="tg-de2y"><strong>New bugs</strong></td>
                                <td class="tg-de2y" style="text-align: right;">${env.new_bugs}</td>
                            </tr>
                            <tr>
                                <td class="tg-de2y"><strong>Vulnerabilities</strong></td>
                                <td class="tg-de2y" style="text-align: right;">${env.vulnerabilities}</td>
                            </tr>
                            <tr>
                                <td class="tg-de2y"><strong>New vulnerabilities</strong></td>
                                <td class="tg-de2y" style="text-align: right;">${env.new_vulnerabilities}</td>
                            </tr>
                            <tr>
                                <td class="tg-de2y"><strong>Security hotspots</strong></td>
                                <td class="tg-de2y" style="text-align: right;">${env.security_hotspots}</td>
                            </tr>
                            <tr>
                                <td class="tg-de2y"><strong>New security hotspots</strong></td>
                                <td class="tg-de2y" style="text-align: right;">${env.new_security_hotspots}</td>
                            </tr>
                            <tr>
                                <td class="tg-de2y"><strong>Code smells</strong></td>
                                <td class="tg-de2y" style="text-align: right;">${env.code_smells}</td>
                            </tr>
                            <tr>
                                <td class="tg-de2y"><strong>New code smells</strong></td>
                                <td class="tg-de2y" style="text-align: right;">${env.new_code_smells}</td>
                            </tr>
                            <tr>
                                <td class="tg-de2y"><strong>Coverage</strong></td>
                                <td class="tg-de2y" style="text-align: right;">${env.coverage}</td>
                            </tr>
                            <tr>
                                <td class="tg-de2y"><strong>Duplicated lines</strong></td>
                                <td class="tg-de2y" style="text-align: right;">${env.duplicated_lines}</td>
                            </tr>
                            <tr>
                                <td class="tg-de2y"><strong>Duplicated lines density</strong></td>
                                <td class="tg-de2y" style="text-align: right;">${env.duplicated_lines_density}</td>
                            </tr>
                        </tbody>
                    </table>
                    <div>&nbsp;</div>
                    <div>Best regards,</div>
                    <div>The Jenkins Server</div>
                    """
                    )
                }
            }
        }
    }               
}

