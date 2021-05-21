pipeline {
    agent none
    environment {
        TCM_NEXUS_SERVER = "nexus.silabs.com"
    }
    stages {
        stage('Build 9116 Firmware') {
            agent {
                docker {
                    label 'NB00015129'
                    image 'rs911x/build'
                }
            }
            steps {
                dir('rs911x') {
                    sh '''
                        #./Utils/ci/build_scripts/iot/build_a10_firmware.sh
                    '''
                }
            }
        }
        stage('Build Test Agent') {
            agent {
                label 'NB00015129'
            }
            stages {
                stage('Setup Environment') {
                    steps {
                        sh './setup.sh'
                    }
                }
                stage('Build Test Package') {
                    steps {
                        dir('rs911x') {
                            sh '''
                                . ../projenv.sh
                                export GECKO_SDK="${WORKSPACE}/mini_gecko_sdk"
                                slc configuration --sdk $GECKO_SDK
                                ./Utils/ci/build_scripts/iot/build_test_package.sh
                            '''
                            stash includes: 'test_package/**', name: 'test_package'
                            
                        }
                    }
                }
                stage('Run Tests') {
                    steps {
                        dir('utf_pytest') {
                            unstash name: 'test_package'
                            sh """
                                # fix problem in one of the test cases
                                sed -i 's/test_wifi_dhcp(wifi_dut)/test_wifi_dhcp(wifi_accesspoint, wifi_dut)/' test_package/test_cases/test_wifi.py

                                # call script to run tests on raspi "rs9116test.local"
                                # using harness "rs9116test-joes"
                                ./load_tests_docker.sh rs9116test.local rs9116test-joes
                            """
                            archiveArtifacts 'test_package/**'
                            archiveArtifacts 'reports/**'
                            junit allowEmptyResults: false, testResults: 'reports/junit_report.xml'
                        }
                    }
                }
            }
        }
    }
}