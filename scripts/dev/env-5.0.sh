# Point the dev loop at the Wazuh 5.0.0-rc2 single-node stack. Source it:
#
#   source scripts/dev/env-5.0.sh
#   scripts/dev/build-dev-image.sh   # once: wam-dev:5.0.0-rc2 (bootstraps OSD 3.6.0, slow)
#   scripts/dev/build.sh             # build/wazuhAlertManager-3.6.0.zip
#   scripts/dev/e2e-deploy.sh        # wam-e2e-dashboard:5.0 into the wam5 stack, https://localhost:8444
#
# `unset ${!WAM_@}` returns to the 4.14.10 defaults.
export WAM_DEV_IMAGE=wam-dev:5.0.0-rc2
export WAM_OSD_VERSION=3.6.0
export WAM_WAZUH_VERSION=5.0.0-rc2
export WAM_DASHBOARD_REF=v5.0.0-rc2
export WAM_NODE_VERSION=22.22.0
export WAM_STACK_DIR=/c/Users/Chris/projects/wazuh-docker-5/single-node
export WAM_E2E_IMAGE=wam-e2e-dashboard:5.0
export WAM_DASHBOARD_URL=https://localhost:8444
# 5.0 dashboard images start as root (the entrypoint drops to wazuh-dashboard itself).
export WAM_PLUGIN_UID=0
export WAM_PLUGIN_GID=0
# Playwright base URL, so `yarn test:e2e` follows the same stack.
export WAM_E2E_URL=https://localhost:8444
# Credentials the 5.0 stack was generated with (config/credentials/*.env);
# dotenv never overrides an exported variable, so these beat .env.e2e.local.
export WAM_E2E_USERNAME=admin
export WAM_E2E_PASSWORD="$(sed -n 's/^WAZUH_INDEXER_ADMIN_PASSWORD=//p' "${WAM_STACK_DIR}/config/credentials/indexer.env" | tr -d '
')"
export WAM_E2E_SEED=local
# Picks the 5.0 branches of the specs: `full_ui.spec.ts` seeds WCS findings
# through `seed_findings_v5.py` instead of 4.x alerts, and
# `trial_enrichment.spec.ts` expects the built-in `wazuh_cti_local` source.
export WAM_E2E_PROFILE=wazuh5
export WAM_SEED_URL=https://localhost:9201
export WAM_SEED_USERNAME=admin
export WAM_SEED_PASSWORD="$WAM_E2E_PASSWORD"
