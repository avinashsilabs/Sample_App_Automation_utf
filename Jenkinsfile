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
                    exit 0
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
                            uc configuration --sdk $GECKO_SDK
                            ./Utils/ci/build_scripts/iot/build_test_package.sh
                            '''
                        }
                    }
                }
                stage('Run Tests') {
                    steps {
                        dir('utf_pytest') {
                            sh """
                            exit 0
                            """
                        }
                    }
                }
            }
        }
    }
}