#!/usr/bin/env bash
#
# Release helper: generate SHA-256 checksums and optional minisign signatures
# for a set of built plugin artifacts. Run from the repository root after
# `yarn build` (or with the path to the build/ directory).
#
# Usage:
#   scripts/make-release-artifacts.sh [build-dir]
#
# Produces, next to each wazuhAlertManager-*.zip:
#   <zip>.sha256   - one line "<hex>  <zip filename>"
#   <zip>.minisig  - only when WAM_MINISIGN_SECRET_KEY is set and minisign exists
#
# Also emits install.sh.sha256 so the one-line installer can be verified:
#   scripts/make-release-artifacts.sh --installer

set -euo pipefail

minisign_secret="${WAM_MINISIGN_SECRET_KEY:-}"
build_dir="${1:-build}"

if [ "${1:-}" = "--installer" ]; then
  [ -f install.sh ] || { echo "install.sh not found" >&2; exit 1; }
  sha256sum install.sh > install.sh.sha256
  if [ -n "$minisign_secret" ] && command -v minisign >/dev/null 2>&1; then
    minisign -Sm install.sh -s "$minisign_secret"
  fi
  echo "Wrote install.sh.sha256" >&2
  exit 0
fi

[ -d "$build_dir" ] || { echo "Build directory not found: $build_dir" >&2; exit 1; }

count=0
for zip in "$build_dir"/wazuhAlertManager-*.zip; do
  [ -f "$zip" ] || continue
  name="$(basename "$zip")"
  ( cd "$build_dir" && sha256sum "$name" ) > "$zip.sha256"
  echo "Wrote $name.sha256" >&2
  count=$((count + 1))
  if [ -n "$minisign_secret" ] && command -v minisign >/dev/null 2>&1; then
    minisign -Sm "$zip" -s "$minisign_secret"
    echo "Wrote $name.minisig" >&2
  fi
done

[ "$count" -gt 0 ] || { echo "No wazuhAlertManager-*.zip found in $build_dir" >&2; exit 1; }
echo "Done: $count artifact(s)." >&2
