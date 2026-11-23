#!/usr/bin/env bash
# Build the bootstrapped wazuh-dashboard dev image (docker/dev/Dockerfile) for
# the version common.sh / env-5.0.sh selects. Slow (yarn osd bootstrap).
#   scripts/dev/build-dev-image.sh                                  # wam-dev:4.14.10
#   source scripts/dev/env-5.0.sh && scripts/dev/build-dev-image.sh # wam-dev:5.0.0-rc2
set -euo pipefail
. "$(dirname "$0")/common.sh"
cd "$REPO_DIR"
docker build -f docker/dev/Dockerfile \
  --build-arg DASHBOARD_REF="$DASHBOARD_REF" --build-arg NODE_VERSION="$NODE_VERSION" \
  -t "$DEV_IMAGE" docker/dev
