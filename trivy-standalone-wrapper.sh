#!/bin/bash

set -euo pipefail

MODE=""
TARGET=""

REPORT_DIR="${REPORT_DIR:-$HOME/work/trivy-reports}"
SCANNERS="${SCANNERS:-vuln}"
SEVERITY="${SEVERITY:-UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL}"
EXIT_CODE="${EXIT_CODE:-0}"
TIMEOUT="${TIMEOUT:-30m}"

TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy:latest}"
DB_REPOSITORY="${DB_REPOSITORY:-public.ecr.aws/aquasecurity/trivy-db:2}"

IMAGE_PULL_RETRIES="${IMAGE_PULL_RETRIES:-5}"
IMAGE_PULL_RETRY_SLEEP="${IMAGE_PULL_RETRY_SLEEP:-30}"
IMAGE_PULL_TIMEOUT="${IMAGE_PULL_TIMEOUT:-20m}"

usage() {
  echo "Usage:"
  echo "  $0 --mode image     --target <docker-image>"
  echo "  $0 --mode container --target <container-name-or-id>"
  echo "  $0 --mode fs        --target <project-folder-path>"
  echo "  $0 --mode repo      --target <git-repo-url-or-local-repo-path>"
  echo "  $0 --mode image     --target alpine:3.20 --report-dir ./trivy-reports"
  echo ""
  echo "Examples:"
  echo "  $0 --mode image --target alpine:3.20"
  echo "  $0 --mode image --target cavissonsystem/gpt-node-server:4.15.0.B119"
  echo "  $0 --mode container --target gpt-node-server"
  echo "  $0 --mode fs --target /home/cavisson/work/my-project"
  echo "  $0 --mode repo --target https://github.com/aquasecurity/trivy-ci-test.git"
  echo ""
  echo "Optional environment variables:"
  echo "  REPORT_DIR=$HOME/work/trivy-reports"
  echo "  SCANNERS=vuln"
  echo "  SCANNERS=vuln,secret,misconfig"
  echo "  SEVERITY=HIGH,CRITICAL"
  echo "  EXIT_CODE=1"
  echo "  TIMEOUT=30m"
  echo "  TRIVY_IMAGE=aquasec/trivy:latest"
  echo "  DB_REPOSITORY=public.ecr.aws/aquasecurity/trivy-db:2"
  echo "  IMAGE_PULL_RETRIES=5"
  echo "  IMAGE_PULL_RETRY_SLEEP=30"
  echo "  IMAGE_PULL_TIMEOUT=20m"
  echo ""
  echo "Options:"
  echo "  --mode        image | container | fs | repo"
  echo "  --target      scan target"
  echo "  --report-dir  report output directory"
  exit 1
}

sanitize_name() {
  echo "$1" | sed 's#^[/.]*##' | sed 's#[/:@?=& ]#-#g'
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

pull_docker_image_with_retry() {
  local image="$1"
  local attempts="$IMAGE_PULL_RETRIES"
  local sleep_seconds="$IMAGE_PULL_RETRY_SLEEP"
  local pull_timeout="$IMAGE_PULL_TIMEOUT"

  echo "=================================================="
  echo " Checking Docker image"
  echo " Image        : $image"
  echo " Retries      : $attempts"
  echo " Retry Sleep  : ${sleep_seconds}s"
  echo " Pull Timeout : $pull_timeout"
  echo "=================================================="

  if docker image inspect "$image" >/dev/null 2>&1; then
    echo "[INFO] Docker image already available locally: $image"
    return 0
  fi

  echo "[INFO] Docker image not found locally. Pulling with retry..."

  for attempt in $(seq 1 "$attempts"); do
    echo "[INFO] Pull attempt $attempt/$attempts: $image"

    if timeout "$pull_timeout" docker pull "$image"; then
      echo "[INFO] Docker image pulled successfully: $image"
      return 0
    fi

    echo "[WARN] Docker image pull failed: $image"

    if [[ "$attempt" -lt "$attempts" ]]; then
      echo "[INFO] Retrying in ${sleep_seconds}s..."
      sleep "$sleep_seconds"
    fi
  done

  echo "[ERROR] Failed to pull Docker image after $attempts attempts: $image"
  return 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="$2"
      shift 2
      ;;
    --target)
      TARGET="$2"
      shift 2
      ;;
    --report-dir)
      REPORT_DIR="$2"
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "Unknown argument: $1"
      usage
      ;;
  esac
done

if [[ -z "$MODE" || -z "$TARGET" ]]; then
  usage
fi

case "$MODE" in
  image|container|fs|repo)
    ;;
  *)
    echo "[ERROR] Invalid mode: $MODE"
    usage
    ;;
esac

require_docker

mkdir -p "$REPORT_DIR"
mkdir -p "$HOME/.cache/trivy"
chmod 777 "$REPORT_DIR" 2>/dev/null || true

SAFE_TARGET_NAME=$(sanitize_name "$TARGET")
REPORT_FILE="${MODE}-${SAFE_TARGET_NAME}-trivy-report.json"

echo "=================================================="
echo " Trivy Standalone Wrapper"
echo "=================================================="
echo " Mode          : $MODE"
echo " Target        : $TARGET"
echo " Report Dir    : $REPORT_DIR"
echo " Report        : $REPORT_FILE"
echo " Scanners      : $SCANNERS"
echo " Severity      : $SEVERITY"
echo " Timeout       : $TIMEOUT"
echo " Trivy Image   : $TRIVY_IMAGE"
echo " DB Repository : $DB_REPOSITORY"
echo "=================================================="

pull_docker_image_with_retry "$TRIVY_IMAGE"

case "$MODE" in

  image)
    echo "[INFO] Scanning Docker image: $TARGET"

    docker run --rm --network host \
      -v /var/run/docker.sock:/var/run/docker.sock \
      -v "$HOME/.cache/trivy":/root/.cache \
      -v "$REPORT_DIR":/reports \
      "$TRIVY_IMAGE" image \
      --db-repository "$DB_REPOSITORY" \
      --scanners "$SCANNERS" \
      --severity "$SEVERITY" \
      --timeout "$TIMEOUT" \
      --exit-code "$EXIT_CODE" \
      --format json \
      --output "/reports/$REPORT_FILE" \
      "$TARGET"
    ;;

  container)
    echo "[INFO] Scanning running container filesystem: $TARGET"

    if ! docker inspect "$TARGET" >/dev/null 2>&1; then
      echo "[ERROR] Container not found: $TARGET"
      exit 1
    fi

    TMP_DIR=$(mktemp -d)
    ROOTFS_DIR="$TMP_DIR/rootfs"
    mkdir -p "$ROOTFS_DIR"

    cleanup() {
      rm -rf "$TMP_DIR"
    }
    trap cleanup EXIT

    echo "[INFO] Exporting container filesystem..."
    docker export "$TARGET" | tar -C "$ROOTFS_DIR" -xf -

    echo "[INFO] Running Trivy rootfs scan..."
    docker run --rm --network host \
      -v "$HOME/.cache/trivy":/root/.cache \
      -v "$REPORT_DIR":/reports \
      -v "$ROOTFS_DIR":/scan-rootfs:ro \
      "$TRIVY_IMAGE" rootfs \
      --db-repository "$DB_REPOSITORY" \
      --scanners "$SCANNERS" \
      --severity "$SEVERITY" \
      --timeout "$TIMEOUT" \
      --exit-code "$EXIT_CODE" \
      --format json \
      --output "/reports/$REPORT_FILE" \
      /scan-rootfs
    ;;

  fs)
    echo "[INFO] Scanning filesystem/project folder: $TARGET"

    if [[ ! -e "$TARGET" ]]; then
      echo "[ERROR] Path not found: $TARGET"
      exit 1
    fi

    ABS_TARGET=$(realpath "$TARGET")

    docker run --rm --network host \
      -v "$HOME/.cache/trivy":/root/.cache \
      -v "$REPORT_DIR":/reports \
      -v "$ABS_TARGET":/scan-target:ro \
      "$TRIVY_IMAGE" fs \
      --db-repository "$DB_REPOSITORY" \
      --scanners "$SCANNERS" \
      --severity "$SEVERITY" \
      --timeout "$TIMEOUT" \
      --exit-code "$EXIT_CODE" \
      --format json \
      --output "/reports/$REPORT_FILE" \
      /scan-target
    ;;

  repo)
    echo "[INFO] Scanning Git repository: $TARGET"

    if [[ -d "$TARGET" ]]; then
      ABS_TARGET=$(realpath "$TARGET")

      docker run --rm --network host \
        -v "$HOME/.cache/trivy":/root/.cache \
        -v "$REPORT_DIR":/reports \
        -v "$ABS_TARGET":/scan-repo:ro \
        "$TRIVY_IMAGE" repo \
        --db-repository "$DB_REPOSITORY" \
        --scanners "$SCANNERS" \
        --severity "$SEVERITY" \
        --timeout "$TIMEOUT" \
        --exit-code "$EXIT_CODE" \
        --format json \
        --output "/reports/$REPORT_FILE" \
        /scan-repo
    else
      docker run --rm --network host \
        -v "$HOME/.cache/trivy":/root/.cache \
        -v "$REPORT_DIR":/reports \
        "$TRIVY_IMAGE" repo \
        --db-repository "$DB_REPOSITORY" \
        --scanners "$SCANNERS" \
        --severity "$SEVERITY" \
        --timeout "$TIMEOUT" \
        --exit-code "$EXIT_CODE" \
        --format json \
        --output "/reports/$REPORT_FILE" \
        "$TARGET"
    fi
    ;;

esac

echo "=================================================="
echo " Scan completed"
echo " Report saved at:"
echo " $REPORT_DIR/$REPORT_FILE"
echo "=================================================="

if command -v ls >/dev/null 2>&1; then
  ls -lh "$REPORT_DIR" || true
fi
