#!/usr/bin/env bash
# Bake build/wazuhAlertManager-<osd>.zip into a dashboard image and swap it into
# the local wazuh-docker single-node stack, then wait for the dashboard.
set -euo pipefail
. "$(dirname "$0")/common.sh"
cd "$REPO_DIR"
zip="build/wazuhAlertManager-${OSD_VERSION}.zip"
[ -f "$zip" ] || { echo "missing $zip (run scripts/dev/build.sh first)" >&2; exit 1; }
docker build -f docker/dev/Dockerfile.local --build-arg WAZUH_VERSION="$WAZUH_VERSION" --build-arg ZIP="$zip" -t "$E2E_IMAGE" .
cat > "$STACK_DIR/docker-compose.override.yml" <<YML
services:
  wazuh.dashboard:
    image: ${E2E_IMAGE}
YML
(cd "$STACK_DIR" && docker compose up -d --force-recreate wazuh.dashboard)
for i in $(seq 1 90); do
  code="$(curl -sk -o /dev/null -w '%{http_code}' https://localhost:8443/app/login || true)"
  if [ "$code" = "200" ]; then echo "dashboard ready (${i}x5s)"; exit 0; fi
  sleep 5
done
echo "dashboard did not become ready" >&2; exit 1
