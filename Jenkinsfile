// =============================================================================
// Jenkinsfile
// Cavisson Security Pipeline (converted from Azure DevOps task
// CavSecurityPipelineCP100 -> declarative Jenkins pipeline)
//
// Requires on the agent: bash, docker, curl, jq, tar, python3 (only if you
// still want the Trivy JSON->HTML conversion step -- optional, see note in
// "Collect Reports" stage).
//
// Requires in Jenkins Credentials store:
//   - Secret Text credential, ID "cavisson-api-token"
//     (equivalent to the Azure DevOps Service Connection's "apitoken"
//      endpoint authorization parameter)
// =============================================================================

pipeline {

    agent any

    // options {
    //     timestamps()
    //     disableConcurrentBuilds()
    //     timeout(time: 90, unit: 'MINUTES')
    //     buildDiscarder(logRotator(numToKeepStr: '30'))
    //     ansiColor('xterm')
    // }

    options {
    disableConcurrentBuilds()
    buildDiscarder(logRotator(numToKeepStr: '20'))
    timeout(time: 120, unit: 'MINUTES')
}

    parameters {
        choice(
            name: 'SCAN_TYPE',
            choices: ['static', 'container', 'dynamic'],
            description: 'Which scan to run. static=SonarQube, container=Trivy, dynamic=ZAP.'
        )
        choice(
            name: 'CONTAINER_RUN_MODE',
            choices: ['standalone', 'kubernetes'],
            description: 'Only used when SCAN_TYPE=container.'
        )
        choice(
            name: 'DYNAMIC_RUN_MODE',
            choices: ['standalone', 'kubernetes'],
            description: 'Only used when SCAN_TYPE=dynamic.'
        )
        choice(
            name: 'TRIVY_MODE',
            choices: ['image', 'container', 'fs', 'repo'],
            description: 'Only used when SCAN_TYPE=container and CONTAINER_RUN_MODE=standalone.'
        )
        string(
            name: 'TRIVY_TARGET',
            defaultValue: '',
            description: 'Image name / container name / repo path or URL, depending on TRIVY_MODE.'
        )
        choice(
            name: 'ZAP_MODE',
            choices: ['baseline', 'full', 'api'],
            description: 'Only used when SCAN_TYPE=dynamic and DYNAMIC_RUN_MODE=standalone.'
        )
        string(
            name: 'ZAP_TARGET',
            defaultValue: '',
            description: 'Running application URL for ZAP to scan.'
        )
        string(
            name: 'PROJECT_KEY',
            defaultValue: '',
            description: 'SonarQube project key. Required when SCAN_TYPE=static.'
        )
        string(
            name: 'TARGET_PATH',
            defaultValue: '',
            description: 'Optional sub-path to scan for the static scan. Empty = full repo.'
        )
        string(
            name: 'BASE_URL',
            defaultValue: '',
            description: 'Cavisson/Sonar base URL. Same URL used for static token exchange AND Kubernetes REST orchestration calls.'
        )
    }

    environment {
        // Equivalent of Azure "$(System.DefaultWorkingDirectory)"
        WORKDIR              = "${WORKSPACE}"
        // SCRIPTS_DIR           = "${WORKSPACE}/scripts"
        SCRIPT_DIR = "${WORKSPACE}"

        // Raw, tool-native output locations (mirrors Azure task defaults:
        // trivy-reports / zap-reports directly under the working directory)
        TRIVY_RAW_REPORT_DIR = "${WORKSPACE}/trivy-reports"
        ZAP_RAW_REPORT_DIR   = "${WORKSPACE}/zap-reports"

        // Unique per-execution report folder:
        // security-reports/<JOB_NAME>/<BUILD_NUMBER>/<timestamp>/
        REPORT_TIMESTAMP     = "${new Date().format('yyyyMMdd-HHmmss')}"
    }

    stages {

        // ---------------------------------------------------------------
        // STAGE 1: Validate Inputs
        // Equivalent of validateRequiredInput()/validateKubernetesInputs()
        // in the original index.js
        // ---------------------------------------------------------------
        stage('Validate Inputs') {
            steps {
                script {
                    echo "========== Cavisson Security Pipeline (Jenkins) =========="
                    echo "Scan Type : ${params.SCAN_TYPE}"
                    echo "Base URL  : ${params.BASE_URL}"
                    echo "============================================================"

                    if (!params.BASE_URL?.trim()) {
                        error("BASE_URL is required for all scan types (static token exchange + Kubernetes REST orchestration).")
                    }

                    if (params.SCAN_TYPE == 'static') {
                        if (!params.PROJECT_KEY?.trim()) {
                            error("PROJECT_KEY is required when SCAN_TYPE=static.")
                        }
                    }

                    if (params.SCAN_TYPE == 'container') {
                        if (params.CONTAINER_RUN_MODE == 'standalone') {
                            if (!params.TRIVY_TARGET?.trim()) {
                                error("TRIVY_TARGET is required when SCAN_TYPE=container and CONTAINER_RUN_MODE=standalone.")
                            }
                            def allowedTrivyModes = ['image', 'container', 'fs', 'repo']
                            if (!allowedTrivyModes.contains(params.TRIVY_MODE)) {
                                error("Invalid TRIVY_MODE '${params.TRIVY_MODE}'. Allowed: ${allowedTrivyModes}")
                            }
                            // Requirement 10: Docker must be checked before running Trivy standalone.
                            sh "bash '${env.SCRIPT_DIR}/check-docker.sh'"
                        }
                        // Kubernetes mode needs no docker/cluster inputs beyond BASE_URL,
                        // per the fixed payload contract in this pipeline.
                    }

                    if (params.SCAN_TYPE == 'dynamic') {
                        if (params.DYNAMIC_RUN_MODE == 'standalone') {
                            if (!params.ZAP_TARGET?.trim()) {
                                error("ZAP_TARGET is required when SCAN_TYPE=dynamic and DYNAMIC_RUN_MODE=standalone.")
                            }
                            def allowedZapModes = ['baseline', 'full', 'api']
                            if (!allowedZapModes.contains(params.ZAP_MODE)) {
                                error("Invalid ZAP_MODE '${params.ZAP_MODE}'. Allowed: ${allowedZapModes}")
                            }
                            // Requirement 10: Docker must be checked before running ZAP standalone.
                            sh "bash '${env.SCRIPT_DIR}/check-docker.sh'"
                        }
                    }

                    echo "========== Cavisson Security Pipeline (Jenkins) =========="
                    echo "Scan Type : ${params.SCAN_TYPE}"
                    echo "Base URL  : ${params.BASE_URL}"
                    echo "============================================================"

                    
                    // Make scripts executable regardless of how they arrived in the repo.
                    sh "chmod +x '${env.SCRIPT_DIR}'/*.sh"

                    if (!params.BASE_URL?.trim()) {
                        error("BASE_URL is required for all scan types (static token exchange + Kubernetes REST orchestration).")
                    }
                }
            }
        }

        // ---------------------------------------------------------------
        // STAGE 2: Static Scan (SonarQube via cav_scanner.sh)
        // Equivalent of scanType === "static" branch -> runCodeAnalyzer()
        // ---------------------------------------------------------------
        stage('Static Scan') {
            when { expression { params.SCAN_TYPE == 'static' } }
            environment {
                BASE_URL    = "${params.BASE_URL}"
                PROJECT_KEY = "${params.PROJECT_KEY}"
                TARGET_PATH = "${params.TARGET_PATH}"
            }
            steps {
                withCredentials([string(credentialsId: 'cavisson-api-token', variable: 'CAV_TOKEN')]) {
                    script {
                        // Step A: exchange the Cavisson API token for Sonar admin/user tokens.
                        // sh """
                        //     bash '${env.SCRIPT_DIR}/get-cav-tokens.sh' '${params.BASE_URL}' '${CAV_TOKEN}' '${WORKSPACE}/cav-tokens.env'
                        // """
                        sh '''
                            set +x
                            BASE_URL_CLEAN="${BASE_URL%/}"
                            bash "${SCRIPT_DIR}/get-cav-tokens.sh" "$BASE_URL_CLEAN" "$CAV_TOKEN" "$WORKSPACE/cav-tokens.env"
                        '''

                        def tokens = readProperties(file: "${WORKSPACE}/cav-tokens.env")

                        withEnv([
                            "CAV_SONAR_TOKEN=${tokens.SONAR_TOKEN}",
                            "CAV_USER_TOKEN=${tokens.USER_TOKEN}",
                            "CAV_USER_NAME=${tokens.USER_NAME}"
                        ]) {
                            // Step B: run the same cav_scanner.sh used by the Azure task.
                            sh '''
                                set +x
                                set -e
                                
                                BASE_URL_CLEAN="${BASE_URL%/}"
                                HOST_URL="${BASE_URL_CLEAN}/cav-analysis/userName/${CAV_USER_NAME}/cavToken/${CAV_TOKEN}"

                                SOLUTION_ARGS=""
                                if [ -n "${TARGET_PATH}" ]; then
                                    SOLUTION_ARGS="--solution ${TARGET_PATH}"
                                fi

                                bash "${SCRIPT_DIR}/cav_scanner.sh" \\
                                    --hostUrl "$HOST_URL" \\
                                    --sonarToken "$CAV_SONAR_TOKEN" \\
                                    --projectKey "$PROJECT_KEY" \\
                                    --userToken "$CAV_USER_TOKEN" \\
                                    --userName "$CAV_USER_NAME" \\
                                    --token "$CAV_TOKEN" \\
                                    --isSonarCloud false \\
                                    $SOLUTION_ARGS
                            '''
                        }

                        // Clean up the on-disk token file immediately; it's no longer needed.
                        sh "rm -f '${WORKSPACE}/cav-tokens.env'"
                    }
                }
            }
        }

        // ---------------------------------------------------------------
        // STAGE 3: Container Scan (Trivy)
        // standalone -> trivy-standalone-wrapper.sh, generates JSON report
        // kubernetes -> REST call only, {"scanDast": false, "scanSca": true}
        // ---------------------------------------------------------------
        stage('Container Scan') {
            when { expression { params.SCAN_TYPE == 'container' } }
            steps {
                script {
                    if (params.CONTAINER_RUN_MODE == 'standalone') {
                        echo "Container Run Mode is standalone. Running Trivy shell scan only."
                        sh """
                            mkdir -p '${TRIVY_RAW_REPORT_DIR}'
                            bash '${env.SCRIPT_DIR}/trivy-standalone-wrapper.sh' \\
                                --mode '${params.TRIVY_MODE}' \\
                                --target '${params.TRIVY_TARGET}' \\
                                --report-dir '${TRIVY_RAW_REPORT_DIR}'
                        """
                        echo "Standalone Trivy scan completed. REST API call skipped for standalone mode (per pipeline contract)."
                    } else {
                        echo "Container Run Mode is kubernetes. Calling Trivy REST API only."
                        withCredentials([string(credentialsId: 'cavisson-api-token', variable: 'CAV_TOKEN')]) {
                            withEnv(["BASE_URL_PARAM=${params.BASE_URL}"]) {
                                sh '''
                                    set +x
                                    BASE_URL_CLEAN="${BASE_URL_PARAM%/}"
                                    bash "${SCRIPT_DIR}/call-security-scan-api.sh" "$BASE_URL_CLEAN" "$CAV_TOKEN" false true "Trivy Container Scan"
                                '''
                            }
                        }
                    }
                }
            }
        }

        // ---------------------------------------------------------------
        // STAGE 4: Dynamic Scan (ZAP)
        // standalone -> zap-standalone-wrapper.sh, generates HTML/JSON/XML
        // kubernetes -> REST call only, {"scanDast": true, "scanSca": false}
        // ---------------------------------------------------------------
        stage('Dynamic Scan') {
            when { expression { params.SCAN_TYPE == 'dynamic' } }
            steps {
                script {
                    if (params.DYNAMIC_RUN_MODE == 'standalone') {
                        echo "Dynamic Run Mode is standalone. Running ZAP shell scan only."

                        // Requirement 9: ZAP warning exit codes must not fail the build
                        // when warnings are ignored. zap-standalone-wrapper.sh already
                        // implements this internally (IGNORE_WARNINGS=true by default,
                        // exit codes 0/1/2 -> success). We use returnStatus here as a
                        // second, explicit safety net at the Jenkins level.
                        sh "mkdir -p '${ZAP_RAW_REPORT_DIR}'"

                        def zapExit = sh(
                            script: """
                                bash '${env.SCRIPT_DIR}/zap-standalone-wrapper.sh' \\
                                    --mode '${params.ZAP_MODE}' \\
                                    --target '${params.ZAP_TARGET}' \\
                                    --report-dir '${ZAP_RAW_REPORT_DIR}'
                            """,
                            returnStatus: true
                        )

                        if (zapExit != 0) {
                            // The wrapper only returns non-zero here for a genuine
                            // failure (e.g. no reports generated, or IGNORE_WARNINGS=false
                            // and ZAP reported real errors) — warnings are already absorbed.
                            error("ZAP standalone scan failed with exit code ${zapExit}.")
                        }

                        echo "Standalone ZAP scan completed. REST API call skipped for standalone mode (per pipeline contract)."
                    } else {
                        echo "Dynamic Run Mode is kubernetes. Calling ZAP REST API only."
                        withCredentials([string(credentialsId: 'cavisson-api-token', variable: 'CAV_TOKEN')]) {
                            withEnv(["BASE_URL_PARAM=${params.BASE_URL}"]) {
                                sh '''
                                    set +x
                                    BASE_URL_CLEAN="${BASE_URL_PARAM%/}"
                                    bash "${SCRIPT_DIR}/call-security-scan-api.sh" "$BASE_URL_CLEAN" "$CAV_TOKEN" true false "ZAP Dynamic Scan"
                                '''
                            }
                        }
                    }
                }
            }
        }

        // ---------------------------------------------------------------
        // STAGE 5: Collect Reports
        // Equivalent of collectAndPublishSecurityReports() in index.js.
        // Builds: security-reports/<JOB_NAME>/<BUILD_NUMBER>/<timestamp>/
        // ---------------------------------------------------------------
        stage('Collect Reports') {
            when { expression { params.SCAN_TYPE in ['container', 'dynamic'] } }
            steps {
                script {
                    def safeJobName = env.JOB_NAME.replaceAll('[^a-zA-Z0-9._-]', '_')
                    env.FINAL_REPORT_ROOT = "security-reports/${safeJobName}/${env.BUILD_NUMBER}/${env.REPORT_TIMESTAMP}"

                    sh "mkdir -p '${env.FINAL_REPORT_ROOT}'"

                    if (params.SCAN_TYPE == 'container' && params.CONTAINER_RUN_MODE == 'standalone') {
                        sh """
                            mkdir -p '${env.FINAL_REPORT_ROOT}/trivy'
                            if [ -d '${TRIVY_RAW_REPORT_DIR}' ] && [ -n "\$(ls -A '${TRIVY_RAW_REPORT_DIR}' 2>/dev/null)" ]; then
                                cp -R '${TRIVY_RAW_REPORT_DIR}'/. '${env.FINAL_REPORT_ROOT}/trivy/'
                            else
                                echo "[WARN] No Trivy reports found in ${TRIVY_RAW_REPORT_DIR}"
                            fi
                        """
                    }

                    if (params.SCAN_TYPE == 'dynamic' && params.DYNAMIC_RUN_MODE == 'standalone') {
                        sh """
                            mkdir -p '${env.FINAL_REPORT_ROOT}/zap'
                            if [ -d '${ZAP_RAW_REPORT_DIR}' ] && [ -n "\$(ls -A '${ZAP_RAW_REPORT_DIR}' 2>/dev/null)" ]; then
                                cp -R '${ZAP_RAW_REPORT_DIR}'/. '${env.FINAL_REPORT_ROOT}/zap/'
                            else
                                echo "[WARN] No ZAP reports found in ${ZAP_RAW_REPORT_DIR}"
                            fi
                        """
                    }

                    // Small manifest, mirrors security-report-summary.json from index.js
                    def summaryJson = """{
  "scanType": "${params.SCAN_TYPE}",
  "containerMode": "${params.CONTAINER_RUN_MODE}",
  "dynamicMode": "${params.DYNAMIC_RUN_MODE}",
  "buildNumber": "${env.BUILD_NUMBER}",
  "jobName": "${env.JOB_NAME}",
  "generatedAt": "${env.REPORT_TIMESTAMP}",
  "reportRoot": "${env.FINAL_REPORT_ROOT}"
}
"""
                    writeFile file: "${env.FINAL_REPORT_ROOT}/security-report-summary.json", text: summaryJson

                    sh "find '${env.FINAL_REPORT_ROOT}' -type f"
                }
            }
        }

        // ---------------------------------------------------------------
        // STAGE 6: Publish Artifacts
        // Equivalent of publishSingleArchiveAsAzureArtifact() ->
        // ##vso[artifact.upload] in index.js
        // ---------------------------------------------------------------
        stage('Publish Artifacts') {
            when { expression { params.SCAN_TYPE in ['container', 'dynamic'] } }
            steps {
                script {
                    def hasFiles = sh(
                        script: "find '${env.FINAL_REPORT_ROOT}' -type f | grep -q . && echo yes || echo no",
                        returnStdout: true
                    ).trim()

                    if (hasFiles == 'yes') {
                        archiveArtifacts(
                            artifacts: "${env.FINAL_REPORT_ROOT}/**",
                            fingerprint: true,
                            allowEmptyArchive: false
                        )
                        echo "Reports published as Jenkins build artifact under: ${env.FINAL_REPORT_ROOT}"
                    } else {
                        echo "No report files were collected. Artifact publishing skipped."
                    }
                }
            }
        }
    }

    post {
        // Requirement: publish whatever reports exist even if a scan stage failed,
        // mirroring the catch-block behavior in the original index.js.
        always {
            script {
                if (params.SCAN_TYPE in ['container', 'dynamic'] && env.FINAL_REPORT_ROOT) {
                    def anyFiles = sh(
                        script: "test -d '${env.FINAL_REPORT_ROOT}' && find '${env.FINAL_REPORT_ROOT}' -type f | grep -q . && echo yes || echo no",
                        returnStdout: true
                    ).trim()
                    if (anyFiles == 'yes') {
                        archiveArtifacts(
                            artifacts: "${env.FINAL_REPORT_ROOT}/**",
                            fingerprint: true,
                            allowEmptyArchive: true
                        )
                    }
                }
            }
            echo "Pipeline finished. Result: ${currentBuild.currentResult}"
        }
        success {
            echo "Cavisson security scan completed successfully."
        }
        failure {
            echo "Cavisson security scan FAILED. Check stage logs above for details."
        }
        cleanup {
            // Remove any leftover token file even on abnormal termination.
            sh "rm -f '${WORKSPACE}/cav-tokens.env' || true"
        }
    }
}
