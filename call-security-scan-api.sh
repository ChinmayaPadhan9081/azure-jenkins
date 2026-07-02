#!/bin/bash
#
# call-security-scan-api.sh
#
# Jenkins-side replacement for lib/securityScanApi.js callSecurityScanApi().
# Used ONLY for Kubernetes run mode (container or dynamic). Standalone mode
# never calls this endpoint.
#
# Always calls:
#   POST <BASE_URL>/DashboardServer/v2/web/common/updateSecurityScanLastModified
#
# Payloads (fixed, per pipeline contract):
#   Trivy / container / kubernetes -> {"scanDast": false, "scanSca": true}
#   ZAP   / dynamic   / kubernetes -> {"scanDast": true,  "scanSca": false}
#
# Usage:
#   call-security-scan-api.sh <BASE_URL> <CAV_TOKEN> <SCAN_DAST true|false> <SCAN_SCA true|false> <STAGE_NAME>
#
set -euo pipefail

BASE_URL="${1:?BASE_URL is required}"
CAV_TOKEN="${2:?CAV_TOKEN is required}"
SCAN_DAST="${3:?SCAN_DAST (true|false) is required}"
SCAN_SCA="${4:?SCAN_SCA (true|false) is required}"
STAGE_NAME="${5:-Security Scan}"

BASE_URL="${BASE_URL%/}"
API_URL="${BASE_URL}/DashboardServer/v2/web/common/updateSecurityScanLastModified"

PAYLOAD="{\"scanDast\": ${SCAN_DAST}, \"scanSca\": ${SCAN_SCA}}"

echo "=================================================="
echo " ${STAGE_NAME} REST API Call"
echo "=================================================="
echo " API URL : ${API_URL}"
echo " Payload : ${PAYLOAD}"
echo "=================================================="

CURL_TLS_FLAG="-k"
if [[ "${CAV_STRICT_TLS:-false}" == "true" ]]; then
  CURL_TLS_FLAG=""
fi

RESPONSE_FILE="$(mktemp)"
trap 'rm -f "$RESPONSE_FILE"' EXIT

HTTP_CODE=$(curl -s ${CURL_TLS_FLAG} -o "$RESPONSE_FILE" -w "%{http_code}" \
  -X POST "${API_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${CAV_TOKEN}" \
  -d "${PAYLOAD}")

echo "[INFO] HTTP Status: ${HTTP_CODE}"
cat "$RESPONSE_FILE" || true
echo ""

if [[ "$HTTP_CODE" -lt 200 || "$HTTP_CODE" -ge 300 ]]; then
  echo "[ERROR] ${STAGE_NAME} REST API call failed with HTTP ${HTTP_CODE}."
  exit 1
fi

echo "[INFO] ${STAGE_NAME} REST API call succeeded."
