@Library('gematik-jenkins-shared-library') _

// GitHub
def REPO_URL = 'https://github.com/gematik/app-gemRAS.git'
def BRANCH = 'main'
def POM_PATH = 'pom.xml'

pipeline {

    options {
        disableConcurrentBuilds()
        skipDefaultCheckout()
        buildDiscarder logRotator(artifactDaysToKeepStr: '', artifactNumToKeepStr: '', daysToKeepStr: '', numToKeepStr: '5')
    }
    agent { label 'k8-publish' }

    stages {

        stage('Checkout') {
            steps {
                git branch: BRANCH,
                        url: REPO_URL
            }
        }

        stage('Build/Unit Tests') {
            steps {
                useJdk('OPENJDK21')
                sh """
                      mvn package --no-transfer-progress
                      """

            }

        }

        stage('Build/Unit Tests') {
            steps {
                useJdk('OPENJDK21')
                sh """
                       export TIGER_TESTENV_CFGFILE=tiger-external.yaml
                       mvn clean verify -Dskip.unittests=true -Dcucumber.filter.tags="@EntityStatement or @SignedJwks"
                      """

            }

        }

    }

    post {
        always {
            sendEMailNotification(getIdpEMailList())
        }
    }
}
