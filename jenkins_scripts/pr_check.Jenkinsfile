@Library('utf-pipeline-libraries@main') _
import groovy.json.JsonSlurper
import main.groovy.HWMuxUtils
import groovy.json.JsonSlurperClassic
import groovy.json.JsonOutput
// This file describes the pipelines steps that Jenkins runs on every pull-request (PR) commit raised against the rs911x repository.

pipeline
{
    // Each stage defines its own agent.
    agent {
        label 'nomadagent'
    }
    environment
    {
        CREDENTIALS = credentials('wifi-ci-agent-stash-jira')
        LOGS_HYPERLINK = "[Logs](${env.BUILD_URL}console)"
        BUILD_HYPERLINK = "[Build #${env.BUILD_ID}](${env.JOB_URL})"
        UTF_HWMUX_TOKEN = credentials('utf-sqa-hwmux-token')
    }
    options
    {    
        skipDefaultCheckout(true)
        // Default checkout is skipped. `SCM checkout` stage runs after pre-build checks.
    }
    stages
    {
        // When a PR is raised/updated, Jenkins uses Bitbucket's feature called Lightweight Checkout
        // to pull Jenkinsfile from the repository via REST API.
        // It takes advantage of this feature to quickly run a set of pre-build checks to determine if builds can continue.
        // This stage runs on Jenkins master, therefore, it doesn't have to wait for available worker node.

        // If it passes pre-built checks, clones and checks out the repository to one of the Linux nodes.
        // From this point onwards, all steps are run on the same node.
        stage('Pre-build Check')
        {
           
            steps
            {
                echo 'Running pre-build checks ...'
                script
                {
                    if (prebuild_checks( ) == false)
                    {
                        error "Pre-build checks failed"
                    }
                }
            }
        }
        stage('SCM Checkout')
        {            
            when {
                anyOf {
                    changeRequest()
                }
            }            
            steps
            {
                echo 'Checkout repository ...'
                checkout scm
                hwmuxReserveAnyGroupFromLabel('utf_wifi_sqa_pr_hyd_jenkins_label', "HWMUX_RESERVED_GROUP_ID", UTF_HWMUX_TOKEN,"HWMUX_RESERVED_GROUP")  {
                    script
                    {
                        def hwmuxUtils = new HWMuxUtils()
                        echo "Group reservation succeeded"
                        echo "My pipeline block can now use group ID " + env.HWMUX_RESERVED_GROUP_ID
                        echo "Group JSON: " + env.HWMUX_RESERVED_GROUP
                        configString = env.HWMUX_RESERVED_GROUP.trim()
                        def configJSON = jsonParsefun(configString)
                        
                        env.SSH_TARGET = configJSON["metadata"]["host_ip"]
                        env.SSH_TARGET = configJSON["metadata"]["host_ip"]
                        env.HARNESS_NAME = configJSON["metadata"]["HARNESS_NAME"]
                        env.UTF_PYTEST_COMMAND = configJSON["metadata"]["UTF_PYTEST_COMMAND"]
                        env.BUILD_LOCATION = configJSON["metadata"]["BUILD_LOCATION"]
                        env.SQA_TEST_AGENT = configJSON["metadata"]["SQA_TEST_AGENT"]
                        env.FLASH_EFR32 = configJSON["metadata"]["FLASH_EFR32"]
                        env.FLASH_RS9116 = configJSON["metadata"]["FLASH_RS9116"]
                        env.DEVICE_GROUP_NAME = configJSON["name"]
                        println(env.SSH_TARGET)
                        println(env.HARNESS_NAME)
                        
                        url= "https://hwmux.silabs.net/api/labels/228"
                        def responseJson = getResponse(url)
                      
                        println(responseJson['metadata']['RS9116_FIRMWARE'])
                        env.RS9116_FIRMWARE = responseJson['metadata']['RS9116_FIRMWARE']
                        responseJson = null
                        
                        changedFiles = sh (
                            script: "git --no-pager diff HEAD refs/remotes/upstream/$CHANGE_TARGET --name-only",
                            returnStdout: true
                        )
                        println(changedFiles)
                        
                    }
                }    
            }
                       
        }
        stage('Run Sanity Test') {
            when {
                anyOf {
                    changeRequest()
                }
            }
            steps {
                script {

                    try{
                        prJob = build job: 'UTF_WiFi_SQA', parameters: [
                                                string(name: 'UTF_WIFI_BRANCH', value: env.CHANGE_BRANCH),
                                                string(name: 'SSH_TARGET', value: env.SSH_TARGET),
                                                string(name: 'RS9116_FIRMWARE', value: env.RS9116_FIRMWARE),
                                                booleanParam(name: 'FLASH_RS9116', value: env.FLASH_RS9116),
                                                booleanParam(name: 'FLASH_EFR32', value: env.FLASH_EFR32),
                                                string(name: 'HARNESS_NAME', value: env.HARNESS_NAME),
                                                string(name: 'device_group_name', value: env.DEVICE_GROUP_NAME),
                                                string(name: 'device_group_label', value: ""),
                                                string(name: 'BUILD_LOCATION', value: env.BUILD_LOCATION),
                                                string(name: 'UTF_PYTEST_COMMAND', value: env.UTF_PYTEST_COMMAND)],
                                                propagate: false
                    }                 
                    catch (err ) {
                        echo 'pr job failed'
                    }
                    env.RS9116_FIRMWARE = null
                    env.build_num = prJob.getNumber()
                    PR_TEST_LOG = "[Logs](${env.JENKINS_URL}job/UTF_WiFi_SQA/$build_num/console)"
                    if( prJob.getCurrentResult() != 'SUCCESS' )  {
                                    
                        post_pr_message("$BUILD_HYPERLINK PR test build failed. See $PR_TEST_LOG")
                        error "PR test build failed"
                    } 
                    else{
                        post_pr_message("$BUILD_HYPERLINK successful.")
                    }
                }       
            }
            post
            {
                always
                {
                    // Always wipes the workspace at the end.
                    echo "Clean-up"
                    cleanWs(cleanWhenAborted: true,
                            cleanWhenFailure: true,
                            cleanWhenNotBuilt: true,
                            cleanWhenSuccess: true,
                            cleanWhenUnstable: true,
                            deleteDirs: true,
                            disableDeferredWipeout: true)
                }
            }

        }
    }
}

// WARNING: The following methods are helper functions. Ideally, these should be stored in a different script file.
// However, we rely on Lightweight Checkout feture of Bitbucket which mandates that all codes are contained within this file.

import groovy.json.JsonSlurperClassic

@NonCPS
def jsonParsefun(String configString) {
    def configJSON = readJSON text: configString
    return configJSON
}

@NonCPS
def getResponse(String url) {
    def hwmuxUtils = new HWMuxUtils()
    def responseJson = hwmuxUtils.httpCallToJson(url, 'GET', '200', null, UTF_HWMUX_TOKEN)
    return responseJson
}
// Post 'message' back to the PR page in Stash web UI
def post_pr_message( message )
{
    PR_REST_URL = get_pr_rest_url()
    echo PR_REST_URL
    sh('curl -u $CREDENTIALS_USR:$CREDENTIALS_PSW' + " --request POST --header 'Content-Type: application/json' --data '{ \"text\": \"$message\"}' ${PR_REST_URL}comments")
}

// Return the PR Rest API URL
def get_pr_rest_url()
{
    job_name = JOB_NAME.replace('/' + JOB_BASE_NAME, '')
    return "https://stash.silabs.com/rest/api/latest/projects/IOT_INFRA_SW/repos/utf_wifi/pull-requests/${env.CHANGE_ID}/"
}

// Runs pre-build checks.
def prebuild_checks()
{
    boolean pr_up_to_date = false;
    boolean passed = true;
    boolean last_page = false;
    boolean previous_build_found_in_scm = false;
    int start = 0
    pr_response = "$BUILD_HYPERLINK failed. Pre-build check error(s) found:\\n"

    PR_REST_URL = get_pr_rest_url()
    response = sh(returnStdout: true, script: 'curl -u $CREDENTIALS_USR:$CREDENTIALS_PSW' + " --request GET --header 'Content-Type: application/json' ${PR_REST_URL}")
    pr = new JsonSlurperClassic().parseText(response)

    // WARNING: This following check is a workaround.
    // Check if current build is the first branch indexing build after jenkins deployment.
    // Upon redeployment, the cbs-wifi jenkins server has no knowledge of previous build results.
    // Consequently, it thinks that all PRs are newly created and triggers unecessary builds.
    while(last_page == false && previous_build_found_in_scm == false)
    {
        curl_response = sh(returnStdout: true, script: 'curl -u $CREDENTIALS_USR:$CREDENTIALS_PSW' + " --request GET --header 'Content-Type: application/json' '${PR_REST_URL}activities?start=${start}'")
        json_response = new JsonSlurperClassic().parseText(curl_response)

        for (value in json_response['values'])
        {
            if (value['user']['name'] == 'wifi-ci-agent')
            {
                previous_build_found_in_scm = true
                echo "previous_build_found_in_scm: ${previous_build_found_in_scm}"
                break
            }
        }
        if(previous_build_found_in_scm == true)
        {
            break
        }
        last_page = json_response['isLastPage']
        if (last_page == false)
        {
            start = json_response['nextPageStart']
        }
    }

    def is_triggered_by_indexing = currentBuild.getBuildCauses('jenkins.branch.BranchIndexingCause').size() > 0
    echo "is_triggered_by_indexing: ${is_triggered_by_indexing}"

    def previous_build_found_in_jenkins = currentBuild.previousBuild != null
    echo "previous_build_found_in_jenkins: ${previous_build_found_in_jenkins}"

    if (is_triggered_by_indexing && !previous_build_found_in_jenkins && previous_build_found_in_scm)
    {
        echo "cbs-wifi was redeployed"
        currentBuild.result = 'ABORTED'
        post_pr_message("$BUILD_HYPERLINK aborted because Jenkins was redeployed. Click `Build Now` to manually rebuild your PR.\\n")
        return false
    }

    post_pr_message("$BUILD_HYPERLINK started.")

    // Check if PR is up-to-date
    pr_up_to_date = false;
    last_page = false;
    start = 0
    while(last_page == false && pr_up_to_date == false)
    {
        response2 = sh(returnStdout: true, script: 'curl -u $CREDENTIALS_USR:$CREDENTIALS_PSW' + " --request GET --header 'Content-Type: application/json' '${PR_REST_URL}commits?start=${start}'")
        commits = new JsonSlurperClassic().parseText(response2)
        for (commit in commits['values'])
        {
            for (parent in commit['parents'])
            {
                if (parent['id'] == pr['toRef']['latestCommit'])
                {
                    pr_up_to_date = true
                    echo "pr_up_to_date: ${pr_up_to_date}"
                    break
                }
            }
            if(pr_up_to_date == true)
            {
                break
            }
        }
        if(pr_up_to_date == true)
        {
            break
        }
        last_page = commits['isLastPage']
        if (last_page == false)
        {
            start = commits['nextPageStart']
        }
    }

    if (pr_up_to_date == false)
    {
        passed = false
        echo "PR branch outdated"
        pr_response = pr_response + "- `${env.CHANGE_BRANCH}` is out-of-date with `${CHANGE_TARGET}`. Please merge `${CHANGE_TARGET}` into `${env.CHANGE_BRANCH}` and push.\\n"
    }

    // Post error message to PR page if any of the PR check failed
    if (passed == false)
    {
        post_pr_message(pr_response)
    }
    return passed
}