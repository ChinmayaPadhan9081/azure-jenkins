#!/bin/bash
#
# check-docker.sh
#
# Preflight check used by the Jenkinsfile before any Trivy/ZAP standalone
# scan is launched. This is a Jenkins-side fail-fast check; the individual
# wrapper scripts (trivy-standalone-wrapper.sh / zap-standalone-wrapper.sh)
# ALSO run their own require_docker() check internally, so this is
# defense-in-depth and gives a clearer, earlier pipeline failure.
#
set -euo pipefail

echo "=================================================="
echo " Docker Preflight Check"
echo "=================================================="

if ! command -v docker >/dev/null 2>&1; then
  echo "[ERROR] Docker CLI is not installed or not available in PATH on this Jenkins agent."
  echo "        Install Docker on the agent, or route this job to an agent/label that has Docker."
  exit 1
fi

if ! docker version >/dev/null 2>&1; then
  echo "[ERROR] Docker daemon is not reachable, or the Jenkins agent user cannot access it."
  echo "        Typical fix: add the Jenkins service user to the 'docker' group:"
  echo "          sudo usermod -aG docker jenkins && sudo systemctl restart jenkins"
  exit 1
fi

echo "[INFO] Docker is available:"
docker --version
echo "=================================================="
