#!/usr/bin/env bash
# Type-check the plugin inside the dev image with a current TypeScript.
#
# The bootstrapped tree ships TypeScript 4.0.2, which stops at syntax errors
# in upstream generated sources (src/plugins/data antlr `override` members,
# ajv, vega-typings) and then skips semantic diagnostics for every file, so
# `tsc --noEmit` with the tree's own compiler reports nothing about plugin
# code. A newer compiler parses those files and reports real plugin errors;
# upstream diagnostics (paths starting with ../../, and their indented
# continuation lines) are filtered out.
#
#   scripts/dev/tsc.sh            # plugin diagnostics only; exit 1 when any
set -euo pipefail
. "$(dirname "$0")/common.sh"
TSC_VERSION="${WAM_TSC_VERSION:-5.4.5}"
raw="$(in_dev "npx -y -p typescript@${TSC_VERSION} tsc --noEmit --pretty false -p tsconfig.json 2>&1" || true)"
# Keep diagnostics whose file path is inside the plugin: "<path>(line,col): error TSxxxx: ...".
plugin="$(printf '%s\n' "$raw" | grep -E '^[^ ].*\): error TS' | grep -v '^\.\./\.\./' || true)"
if [ -n "$plugin" ]; then
  printf '%s\n' "$plugin"
  echo "tsc: plugin type errors found ($(printf '%s\n' "$plugin" | wc -l | tr -d ' '))" >&2
  exit 1
fi
echo "tsc: no plugin type errors (typescript@${TSC_VERSION})"
