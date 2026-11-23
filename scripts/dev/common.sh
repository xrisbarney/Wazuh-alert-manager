# Shared settings for the local Docker dev loop (sourced by the other scripts).
#
# Every value can be overridden through a WAM_* environment variable; the
# defaults target the Wazuh 4.14.10 stack. `source scripts/dev/env-5.0.sh`
# switches all of them to the Wazuh 5.0.0-rc2 stack.
DEV_IMAGE="${WAM_DEV_IMAGE:-wam-dev:4.14.10}"          # bootstrapped wazuh-dashboard tree (docker/dev/Dockerfile)
OSD_VERSION="${WAM_OSD_VERSION:-2.19.6}"               # OSD version the zip is stamped with
WAZUH_VERSION="${WAM_WAZUH_VERSION:-4.14.10}"          # wazuh/wazuh-dashboard image tag the E2E image is built on
DASHBOARD_REF="${WAM_DASHBOARD_REF:-v${WAZUH_VERSION}}" # git ref of wazuh/wazuh-dashboard baked into the dev image
NODE_VERSION="${WAM_NODE_VERSION:-18.19.0}"            # .nvmrc of that ref (22.22.0 for 5.0)
STACK_DIR="${WAM_STACK_DIR:-/c/Users/Chris/projects/wazuh-docker/single-node}"
E2E_IMAGE="${WAM_E2E_IMAGE:-wam-e2e-dashboard:dev}"
DASHBOARD_URL="${WAM_DASHBOARD_URL:-https://localhost:8443}" # host-side URL the readiness probe polls
# Owner of the plugin files inside the dashboard image: 4.x images run as
# uid/gid 1000 (wazuh-dashboard); 5.0 images start as root and drop to the
# wazuh-dashboard service user themselves, so 0:0 is right there.
PLUGIN_UID="${WAM_PLUGIN_UID:-1000}"
PLUGIN_GID="${WAM_PLUGIN_GID:-1000}"
# Hosts the plugin's AI/enrichment egress may reach from inside the container;
# written into the stack's docker-compose.override.yml. Empty disables it.
# Dev-only egress allow list: the host-side Playwright mocks plus the public
# enrichment sources used for manual testing, plus the lab MISP behind
# `misp.internal` (host-gateway, see e2e-deploy.sh). Unset on a real install = any public host.
EGRESS_ALLOWED_HOSTS="${WAM_EGRESS_ALLOWED_HOSTS-host.docker.internal,api.abuseipdb.com,misp.internal}"
# Dev-only secret encryption key (>= 32 chars) so settings with secrets (AI,
# enrichment sources, webhook channels) work in the stack; override per shell.
ENCRYPTION_KEY="${WAM_ENCRYPTION_KEY-wam-dev-only-encryption-key-0123456789abcdef}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# Windows (Git Bash) needs a native path for the bind mount and no path mangling.
if command -v cygpath >/dev/null 2>&1; then
  MOUNT_SRC="$(cygpath -w "$REPO_DIR")"
  export MSYS_NO_PATHCONV=1
else
  MOUNT_SRC="$REPO_DIR"
fi
in_dev() {
  docker run --rm -v "${MOUNT_SRC}:/osd/plugins/wazuhAlertManager" -w /osd/plugins/wazuhAlertManager \
    -e NODE_OPTIONS=--max-old-space-size=6144 "$DEV_IMAGE" bash -lc "$*"
}
