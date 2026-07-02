#!/bin/bash

set -euo pipefail

MODE="baseline"
TARGET=""
CONTAINER_NAME=""
CONTAINER_PORT=""
SCHEME="http"
API_FORMAT="openapi"

REPORT_DIR="${REPORT_DIR:-$(pwd)/zap-reports}"
ZAP_IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"
ZAP_FALLBACK_IMAGE="${ZAP_FALLBACK_IMAGE:-zaproxy/zap-stable}"

DOCKER_NETWORK=""
USE_HOST_NETWORK="auto"
IGNORE_WARNINGS="true"
TIMEOUT_SECONDS="0"

IMAGE_PULL_RETRIES="${IMAGE_PULL_RETRIES:-5}"
IMAGE_PULL_RETRY_SLEEP="${IMAGE_PULL_RETRY_SLEEP:-30}"
IMAGE_PULL_TIMEOUT="${IMAGE_PULL_TIMEOUT:-20m}"

usage() {
  echo ""
  echo "ZAP Standalone DAST Wrapper"
  echo ""
  echo "Usage:"
  echo "  $0 --mode baseline --target <url>"
  echo "  $0 --mode full     --target <url>"
  echo "  $0 --mode api      --target <swagger/openapi/url> --api-format openapi"
  echo "  $0 --mode baseline --container <container-name>"
  echo ""
  echo "Options:"
  echo "  --mode              baseline | full | api"
  echo "  --target            Running application URL"
  echo "  --container         Running Docker container name"
  echo "  --container-port    Internal container port, example: 3000"
  echo "  --network           Docker network name"
  echo "  --scheme            http or https. Default: http"
  echo "  --api-format        openapi | soap | graphql. Default: openapi"
  echo "  --report-dir        Report output directory"
  echo "  --zap-image         ZAP Docker image"
  echo "  --host-network      true | false | auto. Default: auto"
  echo "  --ignore-warnings   true | false. Default: true"
  echo "  --timeout           Timeout in seconds. Default: 0 means no timeout"
  echo ""
  exit 1
}

require_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "[ERROR] Docker is not installed or not available in PATH."
    exit 1
  fi

  if ! docker version >/dev/null 2>&1; then
    echo "[ERROR] Docker daemon is not running or current user cannot access Docker."
    exit 1
  fi
}

pull_image_with_retry() {
  local image="$1"
  local image_label="$2"

  echo "=================================================="
  echo " Checking Docker image"
  echo " Type         : $image_label"
  echo " Image        : $image"
  echo " Retries      : $IMAGE_PULL_RETRIES"
  echo " Retry Sleep  : ${IMAGE_PULL_RETRY_SLEEP}s"
  echo " Pull Timeout : $IMAGE_PULL_TIMEOUT"
  echo "=================================================="

  if docker image inspect "$image" >/dev/null 2>&1; then
    echo "[INFO] Docker image already available locally: $image"
    return 0
  fi

  for attempt in $(seq 1 "$IMAGE_PULL_RETRIES"); do
    echo "[INFO] Pull attempt $attempt/$IMAGE_PULL_RETRIES for $image_label image: $image"

    if timeout "$IMAGE_PULL_TIMEOUT" docker pull "$image"; then
      echo "[INFO] Docker image pulled successfully: $image"
      return 0
    fi

    echo "[WARN] Docker image pull failed: $image"

    if [[ "$attempt" -lt "$IMAGE_PULL_RETRIES" ]]; then
      echo "[INFO] Retrying in ${IMAGE_PULL_RETRY_SLEEP}s..."
      sleep "$IMAGE_PULL_RETRY_SLEEP"
    fi
  done

  echo "[ERROR] Failed to pull Docker image after $IMAGE_PULL_RETRIES attempts: $image"
  return 1
}

pull_zap_image_with_retry() {
  local primary_image="$1"

  echo "=================================================="
  echo " Checking ZAP Docker image with fallback"
  echo " Primary Image  : $primary_image"
  echo " Fallback Image : $ZAP_FALLBACK_IMAGE"
  echo "=================================================="

  if pull_image_with_retry "$primary_image" "ZAP primary"; then
    ZAP_IMAGE="$primary_image"
    echo "[INFO] Using ZAP image: $ZAP_IMAGE"
    return 0
  fi

  echo "[WARN] Primary ZAP image failed: $primary_image"

  if [[ -n "$ZAP_FALLBACK_IMAGE" && "$ZAP_FALLBACK_IMAGE" != "$primary_image" ]]; then
    echo "[INFO] Trying fallback ZAP image: $ZAP_FALLBACK_IMAGE"

    if pull_image_with_retry "$ZAP_FALLBACK_IMAGE" "ZAP fallback"; then
      ZAP_IMAGE="$ZAP_FALLBACK_IMAGE"
      echo "[INFO] Using fallback ZAP image: $ZAP_IMAGE"
      return 0
    fi
  fi

  echo "[ERROR] Failed to pull ZAP images."
  return 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="$2"; shift 2 ;;
    --target)
      TARGET="$2"; shift 2 ;;
    --container)
      CONTAINER_NAME="$2"; shift 2 ;;
    --container-port)
      CONTAINER_PORT="$2"; shift 2 ;;
    --network)
      DOCKER_NETWORK="$2"; shift 2 ;;
    --scheme)
      SCHEME="$2"; shift 2 ;;
    --api-format)
      API_FORMAT="$2"; shift 2 ;;
    --report-dir)
      REPORT_DIR="$2"; shift 2 ;;
    --zap-image)
      ZAP_IMAGE="$2"; shift 2 ;;
    --host-network)
      USE_HOST_NETWORK="$2"; shift 2 ;;
    --ignore-warnings)
      IGNORE_WARNINGS="$2"; shift 2 ;;
    --timeout)
      TIMEOUT_SECONDS="$2"; shift 2 ;;
    -h|--help)
      usage ;;
    *)
      echo "[ERROR] Unknown option: $1"
      usage ;;
  esac
done

if [[ "$MODE" != "baseline" && "$MODE" != "full" && "$MODE" != "api" ]]; then
  echo "[ERROR] Invalid mode: $MODE"
  usage
fi

if [[ -z "$TARGET" && -z "$CONTAINER_NAME" ]]; then
  echo "[ERROR] Provide either --target or --container"
  usage
fi

require_docker

mkdir -p "$REPORT_DIR"
chmod -R 777 "$REPORT_DIR" 2>/dev/null || true

DOCKER_ARGS=()

resolve_target_from_container() {
  local container="$1"

  if ! docker ps --format '{{.Names}}' | grep -wq "$container"; then
    echo "[ERROR] Container '$container' is not running"
    docker ps
    exit 1
  fi

  if [[ -n "$DOCKER_NETWORK" ]]; then
    if [[ -z "$CONTAINER_PORT" ]]; then
      echo "[ERROR] --container-port is required when using --network"
      exit 1
    fi

    TARGET="${SCHEME}://${container}:${CONTAINER_PORT}"
    DOCKER_ARGS+=(--network "$DOCKER_NETWORK")
    return
  fi

  local port_output=""
  local host_port=""

  if [[ -n "$CONTAINER_PORT" ]]; then
    port_output=$(docker port "$container" "${CONTAINER_PORT}/tcp" 2>/dev/null || true)
  else
    port_output=$(docker port "$container" 2>/dev/null | head -n 1 || true)
  fi

  if [[ -z "$port_output" ]]; then
    echo "[ERROR] Could not find published port for container '$container'"
    echo "Run container with -p hostPort:containerPort or use --network."
    exit 1
  fi

  host_port=$(echo "$port_output" | head -n 1 | awk -F ':' '{print $NF}')

  if [[ -z "$host_port" ]]; then
    echo "[ERROR] Could not detect host port from: $port_output"
    exit 1
  fi

  TARGET="${SCHEME}://127.0.0.1:${host_port}"
  DOCKER_ARGS+=(--network host)
}

if [[ -n "$CONTAINER_NAME" && -z "$TARGET" ]]; then
  resolve_target_from_container "$CONTAINER_NAME"
else
  if [[ -n "$DOCKER_NETWORK" ]]; then
    DOCKER_ARGS+=(--network "$DOCKER_NETWORK")
  else
    if [[ "$USE_HOST_NETWORK" == "true" ]]; then
      DOCKER_ARGS+=(--network host)
    elif [[ "$USE_HOST_NETWORK" == "auto" ]]; then
      if [[ "$TARGET" == http://localhost* || "$TARGET" == https://localhost* || "$TARGET" == http://127.0.0.1* || "$TARGET" == https://127.0.0.1* ]]; then
        DOCKER_ARGS+=(--network host)
      fi
    fi
  fi
fi

pull_zap_image_with_retry "$ZAP_IMAGE"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_PREFIX="zap-${MODE}-${TIMESTAMP}"

HTML_REPORT="${REPORT_PREFIX}.html"
JSON_REPORT="${REPORT_PREFIX}.json"
XML_REPORT="${REPORT_PREFIX}.xml"

ZAP_COMMON_ARGS=()

if [[ "$IGNORE_WARNINGS" == "true" ]]; then
  ZAP_COMMON_ARGS+=("-I")
fi

echo ""
echo "=========================================="
echo "ZAP Standalone DAST Scan"
echo "=========================================="
echo "Mode            : $MODE"
echo "Target          : $TARGET"
echo "Container       : ${CONTAINER_NAME:-not used}"
echo "Docker Network  : ${DOCKER_NETWORK:-not used}"
echo "Docker Args     : ${DOCKER_ARGS[*]:-not used}"
echo "Report Directory: $REPORT_DIR"
echo "ZAP Image       : $ZAP_IMAGE"
echo "Fallback Image  : $ZAP_FALLBACK_IMAGE"
echo "Ignore Warnings : $IGNORE_WARNINGS"
echo "Timeout Seconds : $TIMEOUT_SECONDS"
echo "=========================================="
echo ""

run_docker_zap() {
  if [[ "$TIMEOUT_SECONDS" != "0" ]]; then
    timeout "$TIMEOUT_SECONDS" docker run --rm \
      "${DOCKER_ARGS[@]}" \
      -v "$REPORT_DIR:/zap/wrk/:rw" \
      -t "$ZAP_IMAGE" \
      "$@"
  else
    docker run --rm \
      "${DOCKER_ARGS[@]}" \
      -v "$REPORT_DIR:/zap/wrk/:rw" \
      -t "$ZAP_IMAGE" \
      "$@"
  fi
}

ZAP_EXIT_CODE=0

set +e

case "$MODE" in
  baseline)
    echo "Running ZAP baseline scan..."
    run_docker_zap zap-baseline.py \
      -t "$TARGET" \
      -r "$HTML_REPORT" \
      -J "$JSON_REPORT" \
      -x "$XML_REPORT" \
      "${ZAP_COMMON_ARGS[@]}"
    ZAP_EXIT_CODE=$?
    ;;

  full)
    echo "WARNING: ZAP full scan performs active attacks."
    echo "Use full scan only on test/staging applications."
    echo ""
    run_docker_zap zap-full-scan.py \
      -t "$TARGET" \
      -r "$HTML_REPORT" \
      -J "$JSON_REPORT" \
      -x "$XML_REPORT" \
      "${ZAP_COMMON_ARGS[@]}"
    ZAP_EXIT_CODE=$?
    ;;

  api)
    echo "Running ZAP API scan..."
    run_docker_zap zap-api-scan.py \
      -t "$TARGET" \
      -f "$API_FORMAT" \
      -r "$HTML_REPORT" \
      -J "$JSON_REPORT" \
      -x "$XML_REPORT" \
      "${ZAP_COMMON_ARGS[@]}"
    ZAP_EXIT_CODE=$?
    ;;
esac

set -e

echo ""
echo "=========================================="
echo "ZAP Scan Completed"
echo "=========================================="
echo "ZAP Exit Code: $ZAP_EXIT_CODE"
echo "HTML Report  : $REPORT_DIR/$HTML_REPORT"
echo "JSON Report  : $REPORT_DIR/$JSON_REPORT"
echo "XML Report   : $REPORT_DIR/$XML_REPORT"
echo "=========================================="
echo ""

ls -lh "$REPORT_DIR" || true

REPORT_COUNT=0
[[ -f "$REPORT_DIR/$HTML_REPORT" ]] && REPORT_COUNT=$((REPORT_COUNT + 1))
[[ -f "$REPORT_DIR/$JSON_REPORT" ]] && REPORT_COUNT=$((REPORT_COUNT + 1))
[[ -f "$REPORT_DIR/$XML_REPORT" ]] && REPORT_COUNT=$((REPORT_COUNT + 1))

if [[ "$REPORT_COUNT" -eq 0 ]]; then
  echo "[ERROR] ZAP did not generate any report files."
  exit 2
fi

if [[ "$IGNORE_WARNINGS" == "true" ]]; then
  if [[ "$ZAP_EXIT_CODE" -eq 0 || "$ZAP_EXIT_CODE" -eq 1 || "$ZAP_EXIT_CODE" -eq 2 ]]; then
    echo "[INFO] ZAP completed. Warnings are ignored. Returning success."
    exit 0
  fi
else
  if [[ "$ZAP_EXIT_CODE" -eq 0 ]]; then
    echo "[INFO] ZAP completed with no warnings/failures."
    exit 0
  fi
fi

echo "[ERROR] ZAP scan failed with exit code: $ZAP_EXIT_CODE"
exit "$ZAP_EXIT_CODE"
