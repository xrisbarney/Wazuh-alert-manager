#!/usr/bin/env bash
# Run the plugin's Jest suite inside the bootstrapped dev image.
#   scripts/dev/test.sh                      # whole suite
#   scripts/dev/test.sh server/lib/lease     # pattern passed to jest
set -euo pipefail
. "$(dirname "$0")/common.sh"
in_dev "yarn test $*"
