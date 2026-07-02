// =============================================================================
// Jenkinsfile
// Cavisson Security Pipeline - Jenkins mixed mode
//
// Static scan    : Jenkins HPI plugin step cavissonScan(...)
// Container scan : Jenkinsfile shell/REST logic
// Dynamic scan   : Jenkinsfile shell/REST logic
//
// Required Jenkins plugin for static scan:
//   cavisson-scanner.hpi must be installed in Jenkins.
//
// Required Jenkins credential:
//   Kind: Secret text
//   ID  : cavisson-api-token
//   Secret: Cavisson API token
// =============================================================================

pipeline {
    agent any

    options {
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '20'))
        timeout(time: 120, unit: 'MINUTES')
    }

    parameters {
        choice(
            name: 'SCAN_TYPE',
            choices: ['static', 'container', 'dynamic'],
            description: 'Which scan to run. static=SonarQube/Cavisson plugin, container=Trivy, dynamic=ZAP.'
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
            description: 'SonarQube/Cavisson project key. Required when SCAN_TYPE=static.'
        )
        string(
            name: 'TARGET_PATH',
            defaultValue: '',
            description: 'Optional sub-path to scan for static scan. Empty = full workspace.'
        )
        string(
            name: 'BASE_URL',
            defaultValue: '',
            description: 'Cavisson/Sonar base URL. Required for static and Kubernetes REST orchestration.'
        )
    }

    environment {
        WORKDIR = "${WORKSPACE}"
        SCRIPT_DIR = "${WORKSPACE}"

        TRIVY_RAW_REPORT_DIR = "${WORKSPACE}/trivy-reports"
        ZAP_RAW_REPORT_DIR   = "${WORKSPACE}/zap-reports"

        REPORT_TIMESTAMP = "${new Date().format('yyyyMMdd-HHmmss')}"
    }

    stages {
        stage('Validate Inputs') {
            steps {
                script {
                    echo "========== Cavisson Security Pipeline (Jenkins) =========="
                    echo "Scan Type : ${params.SCAN_TYPE}"
                    echo "Base URL  : ${params.BASE_URL}"
                    echo "Workspace : ${env.WORKSPACE}"
                    echo "============================================================"

                    // Make all root-level shell scripts executable.
                    sh "chmod +x '${env.SCRIPT_DIR}'/*.sh || true"

                    def needsBaseUrl =
                        params.SCAN_TYPE == 'static' ||
                        (params.SCAN_TYPE == 'container' && params.CONTAINER_RUN_MODE == 'kubernetes') ||
                        (params.SCAN_TYPE == 'dynamic' && params.DYNAMIC_RUN_MODE == 'kubernetes')

                    if (needsBaseUrl && !params.BASE_URL?.trim()) {
                        error('BASE_URL is required for static scan and Kubernetes REST orchestration.')
                    }

                    if (params.SCAN_TYPE == 'static') {
                        if (!params.PROJECT_KEY?.trim()) {
                            error('PROJECT_KEY is required when SCAN_TYPE=static.')
                        }
                        echo 'Static scan will run through Jenkins HPI plugin step: cavissonScan(...)'
                    }

                    if (params.SCAN_TYPE == 'container') {
                        if (params.CONTAINER_RUN_MODE == 'standalone') {
                            if (!params.TRIVY_TARGET?.trim()) {
                                error('TRIVY_TARGET is required when SCAN_TYPE=container and CONTAINER_RUN_MODE=standalone.')
                            }
                            def allowedTrivyModes = ['image', 'container', 'fs', 'repo']
                            if (!allowedTrivyModes.contains(params.TRIVY_MODE)) {
                                error("Invalid TRIVY_MODE '${params.TRIVY_MODE}'. Allowed: ${allowedTrivyModes}")
                            }
                            sh "test -f '${env.SCRIPT_DIR}/trivy-standalone-wrapper.sh' || (echo '[ERROR] trivy-standalone-wrapper.sh not found in repo root' && exit 1)"
                            sh "bash '${env.SCRIPT_DIR}/check-docker.sh'"
                        } else {
                            sh "test -f '${env.SCRIPT_DIR}/call-security-scan-api.sh' || (echo '[ERROR] call-security-scan-api.sh not found in repo root' && exit 1)"
                        }
                    }

                    if (params.SCAN_TYPE == 'dynamic') {
                        if (params.DYNAMIC_RUN_MODE == 'standalone') {
                            if (!params.ZAP_TARGET?.trim()) {
                                error('ZAP_TARGET is required when SCAN_TYPE=dynamic and DYNAMIC_RUN_MODE=standalone.')
                            }
                            def allowedZapModes = ['baseline', 'full', 'api']
                            if (!allowedZapModes.contains(params.ZAP_MODE)) {
                                error("Invalid ZAP_MODE '${params.ZAP_MODE}'. Allowed: ${allowedZapModes}")
                            }
                            sh "test -f '${env.SCRIPT_DIR}/zap-standalone-wrapper.sh' || (echo '[ERROR] zap-standalone-wrapper.sh not found in repo root' && exit 1)"
                            sh "bash '${env.SCRIPT_DIR}/check-docker.sh'"
                        } else {
                            sh "test -f '${env.SCRIPT_DIR}/call-security-scan-api.sh' || (echo '[ERROR] call-security-scan-api.sh not found in repo root' && exit 1)"
                        }
                    }
                }
            }
        }

        stage('Static Scan') {
            when { expression { params.SCAN_TYPE == 'static' } }
            steps {
                script {
                    def cleanBaseUrl = params.BASE_URL.trim().replaceAll('/+$', '')

                    echo 'Running static scan through installed Cavisson Jenkins HPI plugin.'
                    echo "Cavisson URL: ${cleanBaseUrl}"
                    echo "Project Key : ${params.PROJECT_KEY}"
                    echo "Target Path : ${params.TARGET_PATH ?: '(full workspace)'}"

                    cavissonScan(
                        cavissonUrl: cleanBaseUrl,
                        cavissonCredentialId: 'cavisson-api-token',
                        projectKey: params.PROJECT_KEY.trim(),
                        targetPath: params.TARGET_PATH ?: ''
                    )
                }
            }
        }

        stage('Container Scan') {
            when { expression { params.SCAN_TYPE == 'container' } }
            steps {
                script {
                    if (params.CONTAINER_RUN_MODE == 'standalone') {
                        echo 'Container Run Mode is standalone. Running Trivy shell scan only.'
                        sh """
                            mkdir -p '${TRIVY_RAW_REPORT_DIR}'
                            bash '${env.SCRIPT_DIR}/trivy-standalone-wrapper.sh' \
                                --mode '${params.TRIVY_MODE}' \
                                --target '${params.TRIVY_TARGET}' \
                                --report-dir '${TRIVY_RAW_REPORT_DIR}'
                        """
                        echo 'Standalone Trivy scan completed. REST API call skipped for standalone mode.'
                    } else {
                        echo 'Container Run Mode is kubernetes. Calling Trivy REST API only.'
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

        stage('Dynamic Scan') {
            when { expression { params.SCAN_TYPE == 'dynamic' } }
            steps {
                script {
                    if (params.DYNAMIC_RUN_MODE == 'standalone') {
                        echo 'Dynamic Run Mode is standalone. Running ZAP shell scan only.'
                        sh "mkdir -p '${ZAP_RAW_REPORT_DIR}'"

                        def zapExit = sh(
                            script: """
                                bash '${env.SCRIPT_DIR}/zap-standalone-wrapper.sh' \
                                    --mode '${params.ZAP_MODE}' \
                                    --target '${params.ZAP_TARGET}' \
                                    --report-dir '${ZAP_RAW_REPORT_DIR}'
                            """,
                            returnStatus: true
                        )

                        if (zapExit != 0) {
                            error("ZAP standalone scan failed with exit code ${zapExit}.")
                        }

                        echo 'Standalone ZAP scan completed. REST API call skipped for standalone mode.'
                    } else {
                        echo 'Dynamic Run Mode is kubernetes. Calling ZAP REST API only.'
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
                                echo '[WARN] No Trivy reports found in ${TRIVY_RAW_REPORT_DIR}'
                            fi
                        """
                    }

                    if (params.SCAN_TYPE == 'dynamic' && params.DYNAMIC_RUN_MODE == 'standalone') {
                        sh """
                            mkdir -p '${env.FINAL_REPORT_ROOT}/zap'
                            if [ -d '${ZAP_RAW_REPORT_DIR}' ] && [ -n "\$(ls -A '${ZAP_RAW_REPORT_DIR}' 2>/dev/null)" ]; then
                                cp -R '${ZAP_RAW_REPORT_DIR}'/. '${env.FINAL_REPORT_ROOT}/zap/'
                            else
                                echo '[WARN] No ZAP reports found in ${ZAP_RAW_REPORT_DIR}'
                            fi
                        """
                    }

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
                        echo 'No report files were collected. Artifact publishing skipped.'
                    }
                }
            }
        }
    }

    post {
        always {
            script {
                if ((params.SCAN_TYPE in ['container', 'dynamic']) && env.FINAL_REPORT_ROOT?.trim()) {
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
            echo 'Cavisson security scan completed successfully.'
        }
        failure {
            echo 'Cavisson security scan FAILED. Check stage logs above for details.'
        }
        cleanup {
            sh "rm -f '${WORKSPACE}/cav-tokens.env' || true"
        }
    }
}
