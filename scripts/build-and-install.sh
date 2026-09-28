#!/usr/bin/env bash
#
# Wazuh Alert Manager - build from this checkout and install, in one step.
#
# For when no published release is available (or you are testing a branch):
# builds the plugin exactly the way CI does (.github/workflows/build-and-release.yml)
# and then hands the artifact to install.sh, so you still get the backup,
# checksum verification, readiness check and automatic rollback.
#
#   1. Detects the installed Wazuh Dashboard / OpenSearch Dashboards version.
#   2. Checks out the matching wazuh-dashboard source tree into a work dir.
#   3. Downloads the Node.js version that tree pins (.nvmrc), SHA-256 verified,
#      into the work dir - the system Node is never touched.
#   4. Copies this checkout into <wazuh-dashboard>/plugins/wazuhAlertManager,
#      builds as an unprivileged user (OSD refuses to bootstrap as root),
#      targets the detected version, and runs `yarn osd bootstrap` + `yarn build`.
#   5. Runs install.sh --artifact <zip> --checksum <zip>.sha256.
#
# Your checkout is never modified: version targeting and generated build info
# are applied to the copy inside the work dir.
#
# Usage (from the repository root, on the Wazuh dashboard host):
#   sudo bash scripts/build-and-install.sh
#   sudo bash scripts/build-and-install.sh --install-deps      # apt-get build prerequisites first
#   sudo bash scripts/build-and-install.sh --build-only        # produce the zip, don't install
#
# The first build is slow (a full OpenSearch Dashboards monorepo bootstrap:
# typically 30-90 min, several GB of downloads) and needs ~8 GB RAM and ~25 GB
# free disk. Re-runs reuse the work dir and are much faster.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DASHBOARD_ROOT="/usr/share/wazuh-dashboard"
WORK_DIR="${WAM_BUILD_DIR:-/var/tmp/wazuh-alert-manager-build}"
OSD_VERSION=""
INSTALL_DEPS=0
BUILD_ONLY=0
WITH_TESTS=0
BUILD_PHASE=0       # internal: set when re-invoked as the unprivileged build user
BUILD_USER="${WAM_BUILD_USER:-}"
INSTALL_ARGS=()

# OSD version -> wazuh-dashboard tag. Keep in sync with the CI build matrix.
dashboard_ref_for() {
  case "$1" in
    2.19.1) echo "v4.12.0" ;;
    2.19.2) echo "v4.13.1" ;;
    2.19.5) echo "v4.14.7" ;;
    *) return 1 ;;
  esac
}

log() { printf '%s\n' "==> $*" >&2; }
warn() { printf '%s\n' "!! $*" >&2; }
die() { printf '%s\n' "ERROR: $*" >&2; exit 1; }

usage() {
  cat >&2 <<EOF
Build Wazuh Alert Manager from this checkout and install it.

  sudo bash scripts/build-and-install.sh [options]

  --osd-version V      Build for this OpenSearch Dashboards version instead of
                       detecting it (2.19.1, 2.19.2 or 2.19.5).
  --work-dir DIR       Build directory (default $WORK_DIR, or WAM_BUILD_DIR).
  --dashboard-root DIR Dashboard install root (default $DASHBOARD_ROOT).
  --install-deps       apt-get install git, curl, rsync, xz-utils, build tools.
  --with-tests         Run the plugin's unit tests after building.
  --build-only         Build the zip and stop; print the install command.
  --no-restart         Passed to install.sh: install but don't restart the dashboard.
  --build-user USER    Unprivileged user to build as when run as root (default:
                       the sudo caller, else a 'wam-build' system user is created).
  -h, --help           Show this help.
EOF
  exit 1
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --osd-version) OSD_VERSION="${2:-}"; [ -n "$OSD_VERSION" ] || die "--osd-version requires a value"; shift 2 ;;
      --work-dir) WORK_DIR="${2:-}"; [ -n "$WORK_DIR" ] || die "--work-dir requires a path"; shift 2 ;;
      --dashboard-root) DASHBOARD_ROOT="${2:-}"; [ -n "$DASHBOARD_ROOT" ] || die "--dashboard-root requires a path"; shift 2 ;;
      --install-deps) INSTALL_DEPS=1; shift ;;
      --with-tests) WITH_TESTS=1; shift ;;
      --build-only) BUILD_ONLY=1; shift ;;
      --no-restart) INSTALL_ARGS+=(--no-restart); shift ;;
      --build-user) BUILD_USER="${2:-}"; [ -n "$BUILD_USER" ] || die "--build-user requires a user name"; shift 2 ;;
      --_build-phase) BUILD_PHASE=1; shift ;;
      -h|--help) usage ;;
      *) die "Unknown argument: $1" ;;
    esac
  done
}

install_deps() {
  command -v apt-get >/dev/null 2>&1 || die "--install-deps supports apt-based systems only; install git curl rsync xz-utils make g++ python3 manually"
  log "Installing build prerequisites"
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y git curl rsync xz-utils tar ca-certificates build-essential python3
}

check_prereqs() {
  local missing=() c
  for c in git curl rsync tar xz sha256sum make g++ python3; do
    command -v "$c" >/dev/null 2>&1 || missing+=("$c")
  done
  [ ${#missing[@]} -eq 0 ] || die "Missing tools: ${missing[*]}. Re-run with --install-deps (apt) or install them manually."
  [ -f "$REPO_ROOT/opensearch_dashboards.json" ] && [ -f "$REPO_ROOT/install.sh" ] \
    || die "Run this from a Wazuh-alert-manager checkout (expected opensearch_dashboards.json and install.sh in $REPO_ROOT)"
}

check_resources() {
  local mem_kb avail_kb
  mem_kb="$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
  if [ "$mem_kb" -gt 0 ] && [ "$mem_kb" -lt 7500000 ]; then
    warn "Only $((mem_kb / 1024)) MB RAM. The build needs ~8 GB; it may be killed by the OOM killer."
    warn "Adding swap usually helps, e.g.: fallocate -l 8G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile"
  fi
  mkdir -p "$WORK_DIR"
  avail_kb="$(df -Pk "$WORK_DIR" | awk 'NR==2 {print $4}')"
  if [ "${avail_kb:-0}" -lt 20000000 ]; then
    warn "Only $((avail_kb / 1024 / 1024)) GB free under $WORK_DIR; the build needs ~25 GB. Use --work-dir to pick another disk."
  fi
}

detect_osd_version() {
  if [ -n "$OSD_VERSION" ]; then
    log "Building for OpenSearch Dashboards $OSD_VERSION (from --osd-version)"
    return
  fi
  local pkg="$DASHBOARD_ROOT/package.json"
  [ -f "$pkg" ] || die "Dashboard package.json not found at $pkg. Is Wazuh Dashboard installed here? Use --osd-version with --build-only to build elsewhere."
  OSD_VERSION="$(grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$pkg" | head -1 | sed 's/.*"\([^"]*\)"$/\1/')"
  [ -n "$OSD_VERSION" ] || die "Could not read the dashboard version from $pkg"
  log "Detected OpenSearch Dashboards $OSD_VERSION"
}

checkout_dashboard() {
  DASHBOARD_REF="$(dashboard_ref_for "$OSD_VERSION")" \
    || die "Unsupported OpenSearch Dashboards version '$OSD_VERSION' (supported: 2.19.1, 2.19.2, 2.19.5)"
  SRC="$WORK_DIR/wazuh-dashboard-$DASHBOARD_REF"
  if [ -d "$SRC/.git" ]; then
    log "Reusing wazuh-dashboard $DASHBOARD_REF source at $SRC"
  else
    log "Cloning wazuh-dashboard $DASHBOARD_REF into $SRC"
    rm -rf "$SRC"
    git clone --quiet --depth 1 --branch "$DASHBOARD_REF" https://github.com/wazuh/wazuh-dashboard.git "$SRC"
  fi
}

setup_node() {
  local version arch dist tarball
  version="$(tr -d ' \r\nv' < "$SRC/.nvmrc")"
  [ -n "$version" ] || die "Could not read Node version from $SRC/.nvmrc"
  case "$(uname -m)" in
    x86_64|amd64) arch="x64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) die "Unsupported CPU architecture: $(uname -m)" ;;
  esac
  NODE_HOME="$WORK_DIR/node-v$version-linux-$arch"
  if [ ! -x "$NODE_HOME/bin/node" ]; then
    dist="https://nodejs.org/dist/v$version"
    tarball="node-v$version-linux-$arch.tar.xz"
    log "Downloading Node.js $version ($arch)"
    curl -fsSL -o "$WORK_DIR/$tarball" "$dist/$tarball"
    curl -fsSL -o "$WORK_DIR/SHASUMS256.txt" "$dist/SHASUMS256.txt"
    (cd "$WORK_DIR" && grep " $tarball\$" SHASUMS256.txt | sha256sum -c -) >/dev/null \
      || die "Node.js download failed SHA-256 verification"
    tar -xJf "$WORK_DIR/$tarball" -C "$WORK_DIR"
    rm -f "$WORK_DIR/$tarball" "$WORK_DIR/SHASUMS256.txt"
  fi
  export PATH="$NODE_HOME/bin:$PATH"
  export COREPACK_ENABLE_DOWNLOAD_PROMPT=0
  # corepack honours wazuh-dashboard's own "packageManager" yarn pin, like CI.
  corepack enable --install-directory "$NODE_HOME/bin"
  log "Using Node $(node --version), yarn $(cd "$SRC" && yarn --version)"
}

# Snapshot this checkout into the work dir. Runs before dropping privileges, so
# the build user never needs read access to the checkout itself (e.g. /root).
snapshot_source() {
  PLUGIN_SRC="$WORK_DIR/plugin-src"
  local label
  label="$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')@$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo '?')"
  log "Snapshotting $REPO_ROOT ($label)"
  mkdir -p "$PLUGIN_SRC"
  rsync -a --delete --exclude='.git' --exclude='.github' --exclude='node_modules' --exclude='/build' \
    --exclude='/target' --exclude='/runtime-evidence' "$REPO_ROOT/" "$PLUGIN_SRC/"
  printf '%s\n' "$label" > "$WORK_DIR/plugin-src.label"
}

# OpenSearch Dashboards refuses to bootstrap as root, so when invoked as root
# the build runs as the sudo caller or a dedicated system user.
pick_build_user() {
  if [ -z "$BUILD_USER" ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    BUILD_USER="$SUDO_USER"
  fi
  if [ -z "$BUILD_USER" ]; then
    BUILD_USER="wam-build"
    if ! id "$BUILD_USER" >/dev/null 2>&1; then
      log "Creating unprivileged build user '$BUILD_USER'"
      useradd --system --home-dir "$WORK_DIR/home" --no-create-home --shell /usr/sbin/nologin "$BUILD_USER"
    fi
  fi
  id "$BUILD_USER" >/dev/null 2>&1 || die "Build user '$BUILD_USER' does not exist"
  [ "$(id -u "$BUILD_USER")" -ne 0 ] || die "The build user must not be root"
  BUILD_HOME="$WORK_DIR/home"
  mkdir -p "$BUILD_HOME"
  chown -R "$BUILD_USER" "$WORK_DIR"
  log "Building as unprivileged user '$BUILD_USER'"
}

stage_plugin() {
  PLUGIN_BUILD_DIR="$SRC/plugins/wazuhAlertManager"
  log "Copying $(cat "$WORK_DIR/plugin-src.label" 2>/dev/null || echo 'source') into the build tree"
  mkdir -p "$PLUGIN_BUILD_DIR"
  rsync -a --delete "$WORK_DIR/plugin-src/" "$PLUGIN_BUILD_DIR/"
  PLUGIN_VERSION="$(node -p "require('$PLUGIN_BUILD_DIR/package.json').version")"
  (cd "$PLUGIN_BUILD_DIR" && node scripts/set-target-version.js --osd-version "$OSD_VERSION" --plugin-version "$PLUGIN_VERSION")
}

build_plugin() {
  # Same environment as CI: skip test-only binary downloads that can hang, and
  # give the tsc project-reference build a larger V8 heap.
  export CYPRESS_INSTALL_BINARY=0 CHROMEDRIVER_SKIP_DOWNLOAD=true PUPPETEER_SKIP_DOWNLOAD=true PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
  export NODE_OPTIONS="--max-old-space-size=6144"

  log "yarn osd bootstrap (slow on the first run)"
  (cd "$SRC" && yarn osd bootstrap < /dev/null)

  log "yarn build"
  rm -rf "$PLUGIN_BUILD_DIR/build"
  (cd "$PLUGIN_BUILD_DIR" && yarn build < /dev/null)

  if [ "$WITH_TESTS" -eq 1 ]; then
    log "yarn test"
    (cd "$PLUGIN_BUILD_DIR" && yarn test < /dev/null)
  fi

  local zip
  zip="$(ls "$PLUGIN_BUILD_DIR"/build/*.zip 2>/dev/null | head -n1 || true)"
  [ -n "$zip" ] || die "yarn build produced no zip in $PLUGIN_BUILD_DIR/build"
  ARTIFACT="$WORK_DIR/wazuhAlertManager-$OSD_VERSION.zip"
  cp "$zip" "$ARTIFACT"
  (cd "$WORK_DIR" && sha256sum "$(basename "$ARTIFACT")" > "$(basename "$ARTIFACT").sha256")
  chmod 644 "$ARTIFACT" "$ARTIFACT.sha256"
  log "Built $ARTIFACT"
}

build_phase() {
  checkout_dashboard
  setup_node
  stage_plugin
  build_plugin
}

main() {
  parse_args "$@"

  if [ "$BUILD_PHASE" -eq 1 ]; then
    # Re-invoked as the unprivileged build user: build only.
    build_phase
    exit 0
  fi

  if [ "$BUILD_ONLY" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
    die "Installing needs root. Use: sudo bash scripts/build-and-install.sh (or --build-only)"
  fi
  if [ "$INSTALL_DEPS" -eq 1 ]; then install_deps; fi
  check_prereqs
  detect_osd_version
  check_resources
  snapshot_source

  if [ "$(id -u)" -eq 0 ]; then
    pick_build_user
    local phase_args=(--_build-phase --osd-version "$OSD_VERSION" --work-dir "$WORK_DIR")
    if [ "$WITH_TESTS" -eq 1 ]; then phase_args+=(--with-tests); fi
    runuser -u "$BUILD_USER" -- env -i \
      HOME="$BUILD_HOME" USER="$BUILD_USER" LOGNAME="$BUILD_USER" LANG="${LANG:-C.UTF-8}" TERM="${TERM:-dumb}" \
      PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
      bash "$WORK_DIR/plugin-src/scripts/build-and-install.sh" "${phase_args[@]}"
  else
    build_phase
  fi

  ARTIFACT="$WORK_DIR/wazuhAlertManager-$OSD_VERSION.zip"
  [ -f "$ARTIFACT" ] && [ -f "$ARTIFACT.sha256" ] || die "Build finished without producing $ARTIFACT"

  if [ "$BUILD_ONLY" -eq 1 ]; then
    cat >&2 <<EOF

==> Build complete (not installed)
    Install it with:
      sudo bash $REPO_ROOT/install.sh --artifact $ARTIFACT --checksum $ARTIFACT.sha256
EOF
    exit 0
  fi

  log "Installing with install.sh"
  bash "$REPO_ROOT/install.sh" --dashboard-root "$DASHBOARD_ROOT" --artifact "$ARTIFACT" --checksum "$ARTIFACT.sha256" ${INSTALL_ARGS[@]+"${INSTALL_ARGS[@]}"}
}

main "$@"
