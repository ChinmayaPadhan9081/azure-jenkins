#!/bin/bash
#
# get-cav-tokens.sh
#
# Jenkins-side replacement for the token-exchange logic that used to live in
# cav-security-pipeline/lib/codeAnalyzerRunner.js.
#
# The Azure task called:
#   POST <BASE_URL>/DashboardServer/v2/web/common/getToken
#   header: cavToken: <apiToken from service connection>
#   body:   {"token":"<apiToken>","validity_ms":0,"generated_time":0}
#
# and received back a JSON envelope whose "tokens" field is itself a
# JSON string containing { adminToken, userToken, userName }.
# adminToken -> SonarQube admin/token used as --sonarToken
# userToken  -> per-user token used as --userToken (sonar.token / sonar.login)
# userName   -> --userName
#
# This script performs the same exchange and writes the results to a
# properties file (KEY=VALUE, one per line) that the Jenkinsfile reads with
# readProperties(). It never echoes the raw token values to the console.
#
# Usage:
#   get-cav-tokens.sh <BASE_URL> <CAV_TOKEN> <OUTPUT_PROPS_FILE>
#
set -euo pipefail

BASE_URL="${1:?BASE_URL is required}"
CAV_TOKEN="${2:?CAV_TOKEN is required}"
OUTPUT_FILE="${3:-cav-tokens.env}"

BASE_URL="${BASE_URL%/}"
API_URL="${BASE_URL}/DashboardServer/v2/web/common/getToken"

echo "=================================================="
echo " Cavisson Token Exchange"
echo "=================================================="
echo " Base URL : ${BASE_URL}"
echo " API URL  : ${API_URL}"
echo "=================================================="

if ! command -v jq >/dev/null 2>&1; then
  echo "[ERROR] 'jq' is required on the Jenkins agent to parse the token response."
  exit 1
fi

HTTP_BODY_FILE="$(mktemp)"
trap 'rm -f "$HTTP_BODY_FILE"' EXIT

# -k mirrors allowInsecureSSL=true from the original task (rejectUnauthorized:false).
# Set CAV_STRICT_TLS=true as an environment variable to enforce certificate validation.
CURL_TLS_FLAG="-k"
if [[ "${CAV_STRICT_TLS:-false}" == "true" ]]; then
  CURL_TLS_FLAG=""
fi

HTTP_CODE=$(curl -s ${CURL_TLS_FLAG} -o "$HTTP_BODY_FILE" -w "%{http_code}" \
  -X POST "${API_URL}" \
  -H "Content-Type: application/json" \
  -H "cavToken: ${CAV_TOKEN}" \
  -d "{\"token\":\"${CAV_TOKEN}\",\"validity_ms\":0,\"generated_time\":0}")

if [[ "$HTTP_CODE" -lt 200 || "$HTTP_CODE" -ge 300 ]]; then
  echo "[ERROR] Token exchange failed with HTTP ${HTTP_CODE}."
  cat "$HTTP_BODY_FILE"
  exit 1
fi

TOKENS_JSON=$(jq -r '.tokens // empty' "$HTTP_BODY_FILE")

if [[ -z "$TOKENS_JSON" ]]; then
  echo "[ERROR] Token exchange response did not contain a 'tokens' field."
  exit 1
fi

SONAR_TOKEN=$(echo "$TOKENS_JSON" | jq -r '.adminToken // empty')
USER_TOKEN=$(echo "$TOKENS_JSON" | jq -r '.userToken // empty')
USER_NAME=$(echo "$TOKENS_JSON" | jq -r '.userName // empty')

if [[ -z "$SONAR_TOKEN" || -z "$USER_TOKEN" || -z "$USER_NAME" ]]; then
  echo "[ERROR] Invalid token payload. adminToken/userToken/userName missing."
  exit 1
fi

{
  echo "SONAR_TOKEN=${SONAR_TOKEN}"
  echo "USER_TOKEN=${USER_TOKEN}"
  echo "USER_NAME=${USER_NAME}"
} > "$OUTPUT_FILE"

echo "[INFO] Cavisson tokens resolved for user '${USER_NAME}' and written to ${OUTPUT_FILE}."
echo "[INFO] Token values are not printed to the console."
