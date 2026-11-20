# Shared settings for the local Docker dev loop (sourced by the other scripts).
DEV_IMAGE="${WAM_DEV_IMAGE:-wam-dev:4.14.10}"
OSD_VERSION="${WAM_OSD_VERSION:-2.19.6}"
WAZUH_VERSION="${WAM_WAZUH_VERSION:-4.14.10}"
STACK_DIR="${WAM_STACK_DIR:-/c/Users/Chris/projects/wazuh-docker/single-node}"
E2E_IMAGE="${WAM_E2E_IMAGE:-wam-e2e-dashboard:dev}"
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
