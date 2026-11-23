#!/usr/bin/env bash
# Build the plugin zip for one OSD version inside the dev image.
# Restores the version-stamped files afterwards so the working tree stays clean.
# NOTE: `yarn build` (plugin-helpers) deletes the whole build/ directory first
# (verified: a marker file under build/archive/ does not survive a run), so only
# ONE zip exists in build/ at a time and nothing kept inside build/ survives the
# next line's build. Each zip is therefore copied aside into build-archive/ (a
# sibling of build/, gitignored) right after it is produced, so a multi-line run
# (4.x then 5.0) keeps both artifacts. e2e-deploy.sh still reads
# build/<name>.zip, so build each line immediately before its own deploy.
set -euo pipefail
. "$(dirname "$0")/common.sh"
cd "$REPO_DIR"
plugin_version="$(node -p "require('./package.json').version")"
# Snapshot the version-stamped files (including uncommitted edits such as
# optionalPlugins) and put them back afterwards; never git-checkout them, that
# would silently discard working-tree changes.
stamp_dir="$(mktemp -d)"
cp opensearch_dashboards.json package.json common/build_info.ts "$stamp_dir/"
cleanup() {
  cp "$stamp_dir/opensearch_dashboards.json" opensearch_dashboards.json
  cp "$stamp_dir/package.json" package.json
  cp "$stamp_dir/build_info.ts" common/build_info.ts
  rm -rf "$stamp_dir"
}
trap cleanup EXIT
in_dev "node scripts/set-target-version.js --osd-version ${OSD_VERSION} --plugin-version ${plugin_version} && yarn build"
# Keep this line's artifact out of the next `yarn build`'s way (it empties build/).
mkdir -p build-archive
cp build/wazuhAlertManager-${OSD_VERSION}.zip build-archive/
cp build/wazuhAlertManager-${OSD_VERSION}.zip.sha256 build-archive/ 2>/dev/null || true
ls -la build/*.zip build-archive/
