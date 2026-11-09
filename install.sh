#!/usr/bin/env bash
#
# Wazuh Alert Manager — one-line installer / upgrader / rollback tool.
#
# Detects the installed Wazuh Dashboard / OpenSearch Dashboards version, selects
# the matching plugin artifact, verifies its integrity, backs up the current
# install, and swaps the plugin in. It never touches OpenSearch data directly
# (upgrades preserve every plugin-owned index; --remove-data is a separate,
# explicitly confirmed step).
#
# Usage:
#   curl -fsSL <base-url>/install.sh | sudo bash                    # latest
#   curl -fsSL <base-url>/install.sh | sudo bash -s -- --version 2.0.3
#   sudo ./install.sh --artifact ./wazuhAlertManager-2.19.6.zip \
#        --checksum ./wazuhAlertManager-2.19.6.zip.sha256
#
# Recommended, supply-chain-safe form (download + verify the installer first):
#   curl -fsSLO <base-url>/v2.0.3/install.sh
#   curl -fsSLO <base-url>/v2.0.3/install.sh.sha256
#   sha256sum -c install.sh.sha256
#   sudo bash install.sh --version 2.0.3

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Default release host. Override with --base-url or WAM_RELEASE_BASE_URL.
BASE_URL="${WAM_RELEASE_BASE_URL:-https://github.com/xrisbarney/Wazuh-alert-manager/releases}"

DASHBOARD_ROOT="/usr/share/wazuh-dashboard"
PLUGIN_ID="wazuhAlertManager"
PLUGIN_DIR="$DASHBOARD_ROOT/plugins/$PLUGIN_ID"
BACKUP_DIR="/var/lib/wazuh-alert-manager/backups"

# The plugin CLI must run as whoever owns the plugins directory. Wazuh 4.x
# packages hand the whole dashboard tree to the wazuh-dashboard user; Wazuh
# 5.0 packages keep the tree root-owned (0755) and the service only reads it.
# Running as the wrong user fails with EACCES on `plugins/.plugin.installing`.
plugins_owner() {
  stat -c '%U' "$DASHBOARD_ROOT/plugins" 2>/dev/null || echo wazuh-dashboard
}

plugin_cli() {
  local owner
  owner="$(plugins_owner)"
  if [ "$owner" = "root" ]; then
    "$DASHBOARD_ROOT/bin/opensearch-dashboards-plugin" "$@" --allow-root
  else
    sudo -u "$owner" "$DASHBOARD_ROOT/bin/opensearch-dashboards-plugin" "$@"
  fi
}

# Restore ownership to match the sibling plugins after any root-side write.
fix_plugin_owner() {
  local owner group
  owner="$(plugins_owner)"
  group="$(stat -c '%G' "$DASHBOARD_ROOT/plugins" 2>/dev/null || echo "$owner")"
  if [ -d "$PLUGIN_DIR" ]; then
    chown -R "$owner:$group" "$PLUGIN_DIR" || true
  fi
}

# OSD version -> Wazuh release this artifact targets. Anything not listed here
# is refused: the installer must never guess.
# 2.19.x = Wazuh 4.12-4.14 (reads wazuh-alerts-*). 3.6.0 = Wazuh 5.0 (reads the
# wazuh-findings-v5-* data streams); a development target until 5.0 is final.
SUPPORTED_OSD_VERSIONS="2.19.1 2.19.2 2.19.3 2.19.4 2.19.5 2.19.6 3.6.0"

# Optional signature verification (minisign). Not required, but used when both
# the tool and a trusted public key are present.
MINISIGN_PUBLIC_KEY="${WAM_MINISIGN_PUBLIC_KEY:-}"

VERSION=""          # pinned plugin version (empty = latest)
ARTIFACT=""         # local artifact path (offline mode)
CHECKSUM=""         # local checksum path
DRY_RUN=0
NO_RESTART=0
# Wazuh 5.0: the dashboard's indexer user only READS wazuh-* by default, so the
# installer grants it ownership of the plugin's own stores (exact prefixes)
# through a dedicated OpenSearch Security role. Needs the local admin
# credentials the Wazuh installer publishes on the indexer host.
DASHBOARD_USER="kibanaserver"
SKIP_STORE_ROLE=0
INDEXER_URL="https://127.0.0.1:9200"
INDEXER_CREDENTIALS_FILE="/etc/wazuh-indexer/export/credentials.env"
STORE_ROLE="wazuh_alert_manager_store"
ACTION="install"    # install | rollback | uninstall | remove-data
REMOVE_DATA_CONFIRM=""

CURL="curl -fsSL"
OSD_VERSION=""

# Localhost HTTPS probe. The dashboard serves a development/self-signed cert, so
# this verifies against the Wazuh root CA when present and only falls back to
# -k for the local availability check. Downloads below always use $CURL (no -k),
# so release integrity verification is never relaxed.
LOCAL_CURL_ARGS=()
if [ -r /etc/wazuh-indexer/certs/root-ca.pem ]; then
  LOCAL_CURL_ARGS=(--cacert /etc/wazuh-indexer/certs/root-ca.pem)
else
  LOCAL_CURL_ARGS=(-k)
fi

# Wazuh 5.0 signs the dashboard certificate with a per-component CA, so the
# indexer root CA does not verify https://127.0.0.1. The local probes only
# establish availability (never integrity), so fall back to -k when the CA
# does not verify the local dashboard. Called once the service is up.
settle_local_curl_args() {
  [ "${LOCAL_CURL_ARGS[0]:-}" = "-k" ] && return 0
  local code
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "${LOCAL_CURL_ARGS[@]}" "https://127.0.0.1/app/login" 2>/dev/null || true)"
  if [ "$code" = "000" ]; then
    if curl -sk -o /dev/null --max-time 5 "https://127.0.0.1/app/login" 2>/dev/null; then
      LOCAL_CURL_ARGS=(-k)
    fi
  fi
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log() { printf '%s\n' "==> $*" >&2; }
warn() { printf '%s\n' "!! $*" >&2; }

die() {
  printf '%s\n' "ERROR: $*" >&2
  exit 1
}

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    die "This installer must run as root. Use: curl -fsSL ... | sudo bash"
  fi
}

usage() {
  cat >&2 <<EOF
Wazuh Alert Manager installer

  install.sh [options]

Install / upgrade:
  --version V          Install a pinned plugin release (e.g. 2.0.3). Recommended.
  --artifact FILE      Install from a local ZIP (offline). Use with --checksum.
  --checksum FILE      SHA-256 checksum file for --artifact.
  --base-url URL       Override the release host (or WAM_RELEASE_BASE_URL).
  --dashboard-root DIR Override the dashboard install root (default $DASHBOARD_ROOT).
  --no-restart         Install but do not stop/restart the dashboard service.
  --dashboard-user U   Indexer user the dashboard runs as (default kibanaserver).
                       Wazuh 5.0 only: granted the plugin store role.
  --indexer-url URL    Indexer API for the Wazuh 5.0 store role (default https://127.0.0.1:9200).
  --skip-store-role    Wazuh 5.0 only: do not create/map the plugin store role.
  --dry-run            Resolve and print the plan without changing anything.

Other actions:
  --rollback           Restore the most recent backup of the plugin.
  --grant-store-role   Wazuh 5.0 only: (re)create the plugin store role and map
                       --dashboard-user to it, without installing anything.
  --uninstall-plugin   Remove the plugin while retaining all data.
  --remove-data        Permanently delete plugin-owned OpenSearch indices
                       (requires separate explicit confirmation).

Without --version the latest compatible release is selected.
EOF
  exit 1
}

# ---------------------------------------------------------------------------
# Version detection and artifact resolution
# ---------------------------------------------------------------------------

detect_osd_version() {
  local pkg="$DASHBOARD_ROOT/package.json"
  [ -f "$pkg" ] || die "Dashboard package.json not found at $pkg (is Wazuh Dashboard installed?)"
  OSD_VERSION="$("$DASHBOARD_ROOT/bin/use_node" -e \
    'try { process.stdout.write(require(process.argv[1]).version || "") } catch (e) {}' "$pkg" 2>/dev/null \
    || grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$pkg" | head -1 | sed 's/.*"\([^"]*\)"$/\1/')"
  [ -n "$OSD_VERSION" ] || die "Could not determine the OpenSearch Dashboards version from $pkg"

  local supported=0 v
  for v in $SUPPORTED_OSD_VERSIONS; do
    [ "$v" = "$OSD_VERSION" ] && supported=1
  done
  [ "$supported" -eq 1 ] || die \
    "Unsupported OpenSearch Dashboards version '$OSD_VERSION'. Supported: $SUPPORTED_OSD_VERSIONS."
  log "Detected OpenSearch Dashboards $OSD_VERSION"
}

artifact_name() {
  printf 'wazuhAlertManager-%s.zip' "$OSD_VERSION"
}

# Resolve the artifact URL (and checksum/signature URLs) for the chosen mode.
resolve_urls() {
  local name
  name="$(artifact_name)"
  if [ -n "$ARTIFACT" ]; then
    ARTIFACT_URL="$ARTIFACT"
  elif [ -n "$VERSION" ]; then
    ARTIFACT_URL="$BASE_URL/download/v$VERSION/$name"
  else
    ARTIFACT_URL="$BASE_URL/latest/download/$name"
  fi

  if [ -z "$ARTIFACT" ]; then
    CHECKSUM_URL="$ARTIFACT_URL.sha256"
    SIG_URL="$ARTIFACT_URL.minisig"
  fi
}

# ---------------------------------------------------------------------------
# Dashboard service management
# ---------------------------------------------------------------------------

service_action() {
  local action="$1"
  if [ "$DRY_RUN" -eq 1 ]; then
    log "[dry-run] systemctl $action wazuh-dashboard"
    return 0
  fi
  systemctl "$action" wazuh-dashboard
}

dashboard_ready() {
  # Wait until the dashboard answers HTTPS on localhost (login route). Wazuh
  # dashboard startup is slow after a cold indexer start, so allow generous
  # headroom (up to 5 minutes).
  # The first start after a plugin install can also rebuild the dashboard's
  # optimizer cache on OSD 3.x, so allow up to 10 minutes.
  local i
  for i in $(seq 1 300); do
    if curl -fsSL -o /dev/null --max-time 3 "${LOCAL_CURL_ARGS[@]}" "https://127.0.0.1/app/login" 2>/dev/null; then
      return 0
    fi
    # Up but not verifiable with the chosen CA: switch the local probes to -k.
    if [ "${LOCAL_CURL_ARGS[0]:-}" != "-k" ] && curl -fsk -o /dev/null --max-time 3 "https://127.0.0.1/app/login" 2>/dev/null; then
      LOCAL_CURL_ARGS=(-k)
      return 0
    fi
    sleep 2
  done
  return 1
}

indexer_curl_args() {
  # Prefer the CA the dashboard itself trusts for the indexer, then the indexer
  # root CA. Wazuh 5.0 uses per-component CAs, so verify that the chosen CA
  # actually validates $INDEXER_URL; for a localhost indexer fall back to -k
  # (availability only; the admin credentials never leave this host).
  local ca
  for ca in /etc/wazuh-dashboard/certs/indexer-ca.pem /etc/wazuh-indexer/certs/root-ca.pem; do
    if [ -r "$ca" ] && curl -sS -o /dev/null --max-time 5 --cacert "$ca" "$INDEXER_URL" >/dev/null 2>&1; then
      echo "--cacert $ca"
      return 0
    fi
  done
  case "$INDEXER_URL" in
    https://127.0.0.1*|https://localhost*) echo "-k" ;;
    *) echo "--cacert /nonexistent" ;;
  esac
}

store_role_instructions() {
  cat <<EOF
    The dashboard's indexer user ($DASHBOARD_USER) must own the plugin's stores.
    Create this OpenSearch Security role and map the user to it (Dashboard ->
    Security -> Roles, or the REST API as an administrator):

      PUT _plugins/_security/api/roles/$STORE_ROLE
      {
        "cluster_permissions": ["manage_point_in_time", "cluster_composite_ops"],
        "index_permissions": [{
          "index_patterns": ["wazuh-alert-status-v2-*", "wazuh-alert-manager-v2-*"],
          "allowed_actions": ["indices_all"]
        }]
      }
      PUT _plugins/_security/api/rolesmapping/$STORE_ROLE
      { "users": ["$DASHBOARD_USER"] }

    Native Wazuh storage is not part of this role. Re-run this installer or
    restart wazuh-dashboard afterwards; the plugin provisions its stores on start.
EOF
}

read_admin_password() {
  # Value may be quoted; strip one layer of quotes.
  grep '^WAZUH_INDEXER_ADMIN_PASSWORD=' "$INDEXER_CREDENTIALS_FILE" 2>/dev/null \
    | cut -d= -f2- | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"
}

ensure_store_role() {
  # Wazuh 4.x already maps the dashboard user to manage_wazuh_index (write on
  # wazuh-*). Wazuh 5.0 (OSD 3.x) grants read only, so add the plugin role.
  case "$OSD_VERSION" in
    2.*) return 0 ;;
  esac
  if [ "$SKIP_STORE_ROLE" -eq 1 ]; then
    log "Skipping store role (--skip-store-role)"
    return 0
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    log "[dry-run] ensure OpenSearch Security role $STORE_ROLE for $DASHBOARD_USER via $INDEXER_URL"
    return 0
  fi
  local admin_password
  admin_password="$(read_admin_password)"
  if [ -z "$admin_password" ]; then
    warn "No indexer admin credentials at $INDEXER_CREDENTIALS_FILE (distributed install?). The plugin store role was NOT created."
    store_role_instructions
    return 0
  fi
  local code
  local -a args
  # shellcheck disable=SC2207
  args=($(indexer_curl_args))
  local role_body='{"description":"Wazuh Alert Manager plugin-owned stores (exact prefixes only; native Wazuh storage excluded).","cluster_permissions":["manage_point_in_time","cluster_composite_ops"],"index_permissions":[{"index_patterns":["wazuh-alert-status-v2-*","wazuh-alert-manager-v2-*"],"allowed_actions":["indices_all"]}]}'
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 "${args[@]}" -u "admin:$admin_password" \
    -X PUT -H 'Content-Type: application/json' "$INDEXER_URL/_plugins/_security/api/roles/$STORE_ROLE" \
    -d "$role_body")" || code="000"
  case "$code" in
    200|201) ;;
    *) warn "Could not create role $STORE_ROLE (HTTP $code)"; store_role_instructions; return 0 ;;
  esac
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 "${args[@]}" -u "admin:$admin_password" \
    -X PUT -H 'Content-Type: application/json' "$INDEXER_URL/_plugins/_security/api/rolesmapping/$STORE_ROLE" \
    -d "{\"users\":[\"$DASHBOARD_USER\"]}")" || code="000"
  case "$code" in
    200|201) log "Granted $DASHBOARD_USER the plugin store role $STORE_ROLE (exact plugin prefixes only)" ;;
    *) warn "Could not map $DASHBOARD_USER to $STORE_ROLE (HTTP $code)"; store_role_instructions ;;
  esac
}

verify_plugin_runtime() {
  # Backend: the plugin's version route. Unauthenticated it returns 401 (route
  # registered) rather than 404/000 (plugin not loaded), so accept either.
  log "Verifying plugin runtime"
  local code
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "${LOCAL_CURL_ARGS[@]}" \
    "https://127.0.0.1/api/wazuh_alert_manager/system/version")"
  if [ "$code" != "200" ] && [ "$code" != "401" ]; then
    die "Plugin backend route did not respond (HTTP $code)"
  fi
  curl -fsSL -o /dev/null --max-time 10 "${LOCAL_CURL_ARGS[@]}" "https://127.0.0.1/app/login" \
    || die "Dashboard browser route did not respond"
}

# ---------------------------------------------------------------------------
# Install / upgrade
# ---------------------------------------------------------------------------

backup_current() {
  if [ ! -d "$PLUGIN_DIR" ]; then
    log "No existing plugin to back up (fresh install)"
    return 0
  fi
  mkdir -p "$BACKUP_DIR"
  local stamp
  stamp="$(date +%Y%m%d%H%M%S)"
  local backup="$BACKUP_DIR/${PLUGIN_ID}-${stamp}.tar.gz"
  if [ "$DRY_RUN" -eq 1 ]; then
    log "[dry-run] tar czf $backup -C $DASHBOARD_ROOT/plugins $PLUGIN_ID"
    return 0
  fi
  tar czf "$backup" -C "$DASHBOARD_ROOT/plugins" "$PLUGIN_ID"
  log "Backed up current plugin to $backup"
  printf '%s\n' "$backup" > "$BACKUP_DIR/latest"
}

install_artifact() {
  if [ "$DRY_RUN" -eq 1 ]; then
    if [ -n "$ARTIFACT" ]; then
      log "[dry-run] install file://$ARTIFACT"
    else
      log "[dry-run] download $ARTIFACT_URL"
      log "[dry-run] verify SHA-256 from $CHECKSUM_URL"
      if [ -n "$MINISIGN_PUBLIC_KEY" ]; then
        log "[dry-run] verify minisign from $SIG_URL"
      fi
    fi
    log "[dry-run] run $DASHBOARD_ROOT/bin/opensearch-dashboards-plugin install file://<artifact> as $(plugins_owner) (plugins directory owner)"
    return 0
  fi

  local work
  work="$(mktemp -d)"
  chmod 755 "$work"
  trap 'rm -rf "${work:-}"' EXIT

  # Stage the artifact into a location the wazuh-dashboard user can read.
  # The plugin installer runs as that user, so a root-only temp file or a
  # caller-owned local path would fail with EACCES.
  local name
  name="$work/$(artifact_name)"
  if [ -n "$ARTIFACT" ]; then
    [ -f "$ARTIFACT" ] || die "Artifact not found: $ARTIFACT"
    cp "$ARTIFACT" "$name"
  else
    log "Downloading $(artifact_name)"
    $CURL -o "$name" "$ARTIFACT_URL"

    # SHA-256 is mandatory.
    local expected actual
    expected="$($CURL "$CHECKSUM_URL" | awk '{print $1}')"
    actual="$(sha256sum "$name" | awk '{print $1}')"
    [ -n "$expected" ] || die "Empty checksum from $CHECKSUM_URL"
    [ "$expected" = "$actual" ] || die "Checksum mismatch for $(artifact_name)"
    log "SHA-256 verified"

    # Signature is preferred, not required. Verify only when a trusted public
    # key and minisign are both available.
    if [ -n "$MINISIGN_PUBLIC_KEY" ] && command -v minisign >/dev/null 2>&1; then
      if $CURL -o "$name.minisig" "$SIG_URL" 2>/dev/null; then
        minisign -Vm "$name" -x "$name.minisig" -P "$MINISIGN_PUBLIC_KEY" \
          || die "minisign signature verification failed for $(artifact_name)"
        log "minisign signature verified"
      else
        warn "No signature available at $SIG_URL (skipping; checksum still verified)"
      fi
    elif [ -n "$MINISIGN_PUBLIC_KEY" ]; then
      warn "minisign is not installed; signature verification skipped"
    fi
  fi

  if [ -n "$CHECKSUM" ] && [ -n "$ARTIFACT" ]; then
    [ -f "$CHECKSUM" ] || die "Checksum file not found: $CHECKSUM"
    local expected actual
    expected="$(awk '{print $1}' "$CHECKSUM")"
    actual="$(sha256sum "$name" | awk '{print $1}')"
    [ "$expected" = "$actual" ] || die "Checksum mismatch for $(artifact_name)"
    log "SHA-256 verified"
  fi
  chmod 644 "$name"

  backup_current
  service_action stop

  # Remove the previous plugin code (data lives in OpenSearch, not on disk).
  if [ -d "$PLUGIN_DIR" ]; then
    log "Removing previous plugin code"
    rm -rf "$PLUGIN_DIR"
  fi

  if ! plugin_cli install "file://$name"; then
    warn "Plugin install failed; attempting automatic rollback"
    rollback
    exit 1
  fi
  fix_plugin_owner

  if [ "$NO_RESTART" -eq 1 ]; then
    log "Installed (skipped restart per --no-restart)"
    return 0
  fi

  service_action start
  if dashboard_ready; then
    log "Dashboard is up"
    verify_plugin_runtime
  else
    warn "Dashboard did not become ready; attempting automatic rollback"
    rollback
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# Rollback / uninstall / remove-data
# ---------------------------------------------------------------------------

rollback() {
  local backup
  backup="$(cat "$BACKUP_DIR/latest" 2>/dev/null || true)"
  [ -n "$backup" ] || die "No backup available to roll back to"
  [ -f "$backup" ] || die "Backup file not found: $backup"

  if [ "$DRY_RUN" -eq 1 ]; then
    log "[dry-run] rollback from $backup"
    return 0
  fi

  service_action stop
  rm -rf "$PLUGIN_DIR"
  tar xzf "$backup" -C "$DASHBOARD_ROOT/plugins"
  fix_plugin_owner
  service_action start
  log "Rolled back to $backup"
}

uninstall_plugin() {
  if [ "$DRY_RUN" -eq 1 ]; then
    log "[dry-run] uninstall plugin (data retained)"
    return 0
  fi
  service_action stop
  rm -rf "$PLUGIN_DIR"
  service_action start
  log "Plugin removed. All plugin-owned OpenSearch data is retained."
}

remove_data() {
  # Permanently delete plugin-owned OpenSearch indices. This is the only path
  # that touches data, so it requires an explicit confirmation and targets only
  # the exact plugin prefixes (never wazuh-alerts-*).
  [ "$REMOVE_DATA_CONFIRM" = "yes-remove-wazuh-alert-manager-data" ] || die \
    "Refusing to remove data without --yes-i-really-want-to-remove-data. " \
    "This permanently deletes every wazuh-alert-status-* and wazuh-alert-manager-* index. " \
    "Native wazuh-alerts-* are never touched."

  die "OpenSearch access is not configured by the installer; use the Wazuh indexer admin " \
    "certificates and delete only these exact prefixes: wazuh-alert-status, wazuh-alert-status-v2-*, wazuh-alert-manager-*."
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --version) VERSION="${2:-}"; [ -n "$VERSION" ] || die "--version requires a value"; shift 2 ;;
      --artifact) ARTIFACT="${2:-}"; [ -n "$ARTIFACT" ] || die "--artifact requires a path"; shift 2 ;;
      --checksum) CHECKSUM="${2:-}"; [ -n "$CHECKSUM" ] || die "--checksum requires a path"; shift 2 ;;
      --base-url) BASE_URL="${2:-}"; [ -n "$BASE_URL" ] || die "--base-url requires a URL"; shift 2 ;;
      --dashboard-root) DASHBOARD_ROOT="${2:-}"; shift 2 ;;
      --dry-run) DRY_RUN=1; shift ;;
      --no-restart) NO_RESTART=1; shift ;;
      --dashboard-user) DASHBOARD_USER="${2:-}"; [ -n "$DASHBOARD_USER" ] || die "--dashboard-user requires a value"; shift 2 ;;
      --indexer-url) INDEXER_URL="${2:-}"; [ -n "$INDEXER_URL" ] || die "--indexer-url requires a URL"; shift 2 ;;
      --skip-store-role) SKIP_STORE_ROLE=1; shift ;;
      --rollback) ACTION="rollback"; shift ;;
      --grant-store-role) ACTION="grant-store-role"; shift ;;
      --uninstall-plugin) ACTION="uninstall"; shift ;;
      --remove-data) ACTION="remove-data"; shift ;;
      --yes-i-really-want-to-remove-data) REMOVE_DATA_CONFIRM="yes-remove-wazuh-alert-manager-data"; shift ;;
      -h|--help) usage ;;
      *) die "Unknown argument: $1" ;;
    esac
  done

  PLUGIN_DIR="$DASHBOARD_ROOT/plugins/$PLUGIN_ID"

  if [ "$ACTION" = "install" ] && [ -n "$ARTIFACT" ] && [ -z "$CHECKSUM" ]; then
    warn "Installing a local artifact without --checksum. Integrity verification is strongly recommended."
  fi
  if [ -n "$CHECKSUM" ] && [ -z "$ARTIFACT" ]; then
    die "--checksum is only valid with --artifact"
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  parse_args "$@"
  need_root

  case "$ACTION" in
    rollback)
      rollback
      exit 0
      ;;
    uninstall)
      uninstall_plugin
      exit 0
      ;;
    remove-data)
      remove_data
      exit 0
      ;;
    grant-store-role)
      detect_osd_version
      ensure_store_role
      exit 0
      ;;
  esac

  detect_osd_version
  resolve_urls

  log "Plan: $ACTION wazuhAlertManager for OpenSearch Dashboards $OSD_VERSION"
  log "Artifact: $ARTIFACT_URL"
  if [ "$DRY_RUN" -eq 1 ]; then
    ensure_store_role
    install_artifact
    log "Dry run complete."
    exit 0
  fi

  ensure_store_role
  install_artifact

  cat <<EOF

==> Success
    Wazuh Alert Manager has been installed for OpenSearch Dashboards $OSD_VERSION.
    Open it from the Wazuh dashboard side nav ("Wazuh alert manager").

    First startup provisions the plugin's own indices automatically; native
    Wazuh storage (4.x wazuh-alerts-*, 5.0 wazuh-events-v5-* / wazuh-findings-v5-*)
    is treated as read-only and is never modified. Existing plugin data is
    preserved across upgrades.

    Roll back by re-running this installer with --rollback.
    One-line form:
      curl -fsSL $BASE_URL/latest/download/install.sh | sudo bash -s -- --rollback
EOF
}

main "$@"
