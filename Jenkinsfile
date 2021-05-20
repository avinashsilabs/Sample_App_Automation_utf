pipeline {
    agent {
        node 'NB00015129'
    }
    environment {
        GECKO_SDK = "${WORKSPACE}/mini_gecko_sdk"
    }
    stages {
        stage('Checkout Source') {
            steps {
                checkout scm
            }
        }
        stage('Build Test Agent') {
            steps {
                sh 'uc configuration --sdk $GECKO_SDK'
            }
        }
        stage('Build 9116 Firmware') {
            steps {
                dir('rs911x') {
                    sh './Utils/ci/build_scripts/iot/build_a10_firmware.sh'
                }
            }
        }
        stage('Build Test Package') {
            steps {
                dir('rs911x') {
                    sh './Utils/ci/build_scripts/iot/build_test_package.sh'
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