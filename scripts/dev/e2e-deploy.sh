#!/usr/bin/env bash
# Bake build/wazuhAlertManager-<osd>.zip into a dashboard image and swap it into
# the local wazuh-docker single-node stack, then wait for the dashboard.
#
#   scripts/dev/e2e-deploy.sh                                   # 4.14.10 stack, https://localhost:8443
#   source scripts/dev/env-5.0.sh && scripts/dev/e2e-deploy.sh  # 5.0.0-rc2 stack, https://localhost:8444
#
# The stack must already have been started once (certificates + credentials in
# place); this only recreates the wazuh.dashboard service.
set -euo pipefail
. "$(dirname "$0")/common.sh"
cd "$REPO_DIR"
zip="build/wazuhAlertManager-${OSD_VERSION}.zip"
[ -f "$zip" ] || { echo "missing $zip (run scripts/dev/build.sh first)" >&2; exit 1; }
[ -f "$STACK_DIR/docker-compose.yml" ] || { echo "no docker-compose.yml in STACK_DIR=$STACK_DIR" >&2; exit 1; }
docker build -f docker/dev/Dockerfile.local \
  --build-arg WAZUH_VERSION="$WAZUH_VERSION" --build-arg ZIP="$zip" \
  --build-arg PLUGIN_UID="$PLUGIN_UID" --build-arg PLUGIN_GID="$PLUGIN_GID" \
  -t "$E2E_IMAGE" .
{
  echo "services:"
  echo "  wazuh.dashboard:"
  echo "    image: ${E2E_IMAGE}"
  # The lab MISP (lab/misp, host port 8445) is reached from the container as
  # misp.internal = the Docker host; the name is on the egress allow list
  # (local-suffix names are the private-receiver escape hatch, Q9).
  echo "    extra_hosts:"
  echo "      - \"misp.internal:host-gateway\""
  echo "    environment:"
  if [ -n "$EGRESS_ALLOWED_HOSTS" ]; then
    echo "      - WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS=${EGRESS_ALLOWED_HOSTS}"
  fi
  if [ -n "$ENCRYPTION_KEY" ]; then
    echo "      - WAZUH_ALERT_MANAGER_ENCRYPTION_KEY=${ENCRYPTION_KEY}"
  fi
} > "$STACK_DIR/docker-compose.override.yml"
(cd "$STACK_DIR" && docker compose up -d --force-recreate wazuh.dashboard)
for i in $(seq 1 90); do
  code="$(curl -sk -o /dev/null -w '%{http_code}' "${DASHBOARD_URL}/app/login" || true)"
  if [ "$code" = "200" ]; then echo "dashboard ready at ${DASHBOARD_URL} (${i}x5s)"; exit 0; fi
  sleep 5
done
echo "dashboard at ${DASHBOARD_URL} did not become ready" >&2; exit 1
