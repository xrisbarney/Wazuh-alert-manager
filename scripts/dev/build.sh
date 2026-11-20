#!/usr/bin/env bash
# Build the plugin zip for one OSD version inside the dev image.
# Restores the version-stamped files afterwards so the working tree stays clean.
set -euo pipefail
. "$(dirname "$0")/common.sh"
cd "$REPO_DIR"
plugin_version="$(node -p "require('./package.json').version")"
cleanup() { git checkout -q -- opensearch_dashboards.json package.json common/build_info.ts 2>/dev/null || true; }
trap cleanup EXIT
in_dev "node scripts/set-target-version.js --osd-version ${OSD_VERSION} --plugin-version ${plugin_version} && yarn build"
ls -la build/*.zip
