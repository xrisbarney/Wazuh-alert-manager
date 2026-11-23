# Local Docker dev loop

Two kinds of image, driven by `scripts/dev/*.sh`:

| Image | Built from | Purpose |
|---|---|---|
| `wam-dev:<wazuh>` | `docker/dev/Dockerfile` | a bootstrapped `wazuh-dashboard` source tree; the plugin checkout is bind-mounted into it to build the zip, run Jest and `tsc` |
| `wam-e2e-dashboard:<tag>` | `docker/dev/Dockerfile.local` | the official `wazuh/wazuh-dashboard` image with the built zip installed; swapped into a local `wazuh-docker` single-node stack for Playwright / manual testing |

Every script reads its settings from `scripts/dev/common.sh`, where each value
is a `WAM_*` environment variable with a 4.14.10 default:

| Variable | 4.14.10 default | 5.0 (`scripts/dev/env-5.0.sh`) |
|---|---|---|
| `WAM_DEV_IMAGE` | `wam-dev:4.14.10` | `wam-dev:5.0.0-rc2` |
| `WAM_OSD_VERSION` | `2.19.6` | `3.6.0` |
| `WAM_WAZUH_VERSION` | `4.14.10` | `5.0.0-rc2` |
| `WAM_DASHBOARD_REF` | `v<WAM_WAZUH_VERSION>` | `v5.0.0-rc2` |
| `WAM_NODE_VERSION` | `18.19.0` | `22.22.0` (the ref's `.nvmrc`) |
| `WAM_STACK_DIR` | `/c/Users/Chris/projects/wazuh-docker/single-node` | `/c/Users/Chris/projects/wazuh-docker-5/single-node` |
| `WAM_E2E_IMAGE` | `wam-e2e-dashboard:dev` | `wam-e2e-dashboard:5.0` |
| `WAM_DASHBOARD_URL` | `https://localhost:8443` | `https://localhost:8444` |
| `WAM_PLUGIN_UID` / `WAM_PLUGIN_GID` | `1000` / `1000` | `0` / `0` |
| `WAM_EGRESS_ALLOWED_HOSTS` | `host.docker.internal,api.abuseipdb.com,misp.internal` (`misp.internal` = the lab MISP on the host, `lab/misp`; the override also adds it to `extra_hosts` as `host-gateway`) | same |

`source scripts/dev/env-5.0.sh` switches a shell to the 5.0 column (it also
sets `WAM_E2E_URL` so `yarn test:e2e` follows); `unset ${!WAM_@}` returns to
the defaults. Scripts run from Git Bash on Windows; `common.sh` sets
`MSYS_NO_PATHCONV=1` and converts the bind-mount path itself.

## Build the dev images (once per version, slow: `yarn osd bootstrap`)

```bash
scripts/dev/build-dev-image.sh                                   # wam-dev:4.14.10
source scripts/dev/env-5.0.sh && scripts/dev/build-dev-image.sh  # wam-dev:5.0.0-rc2
```

## Test, type-check, build

```bash
scripts/dev/test.sh [jest pattern]   # yarn test inside the dev image
scripts/dev/tsc.sh                   # plugin-only tsc diagnostics
scripts/dev/build.sh                 # build/wazuhAlertManager-<WAM_OSD_VERSION>.zip
```

`build.sh` stamps `opensearch_dashboards.json` / `common/build_info.ts` for
the selected OSD version through `scripts/set-target-version.js` and restores
them afterwards. With `env-5.0.sh` sourced it produces
`build/wazuhAlertManager-3.6.0.zip` (Wazuh line derived from
`supported-wazuh-versions.json`: 3.6.0 -> 5.0.0-rc2).

## Deploy into a stack

```bash
scripts/dev/e2e-deploy.sh                                    # 4.14.10 stack
source scripts/dev/env-5.0.sh && scripts/dev/e2e-deploy.sh   # 5.0.0-rc2 stack
```

`e2e-deploy.sh` builds `Dockerfile.local` with the zip, writes
`<WAM_STACK_DIR>/docker-compose.override.yml` (image name plus
`WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS`), recreates only `wazuh.dashboard`
and polls `<WAM_DASHBOARD_URL>/app/login` until it answers 200. The stack
itself must already exist and have been started once (certificates and
credentials in place).

The dev deploy also sets `WAZUH_ALERT_MANAGER_ENCRYPTION_KEY` on the
dashboard container (webhook secrets and AI keys are encrypted with it; without
it the notification dispatcher parks a signed webhook as `failed` for an hour
per attempt), and background delivery through a Notifications channel needs the
`wazuh_alert_manager_notify` role mapped to `kibanaserver` on the indexer
(`install.sh` does it on a real install). The 4.14.10 stack already has both.

`Dockerfile.local` installs the plugin with the image's own user: 4.x images
run as uid 1000, 5.0 images build as root (their entrypoint drops to
`wazuh-dashboard` itself), so the `RUN` step adds `--allow-root` when it is
root. The plugin CLI path is the same in both.

### 4.14.10 stack (`wazuh-docker/single-node`)

Project name `single-node`; containers `single-node-wazuh.*-1`.

| Service | Host port |
|---|---|
| dashboard | 8443 (https) |
| indexer | 9200 |
| manager | 1514, 1515, 514/udp, 55000 |

Login: `admin` with the indexer password set in that stack's
`docker-compose.yml`.

### 5.0.0-rc2 stack (`wazuh-docker-5/single-node`)

Checkout of `wazuh/wazuh-docker` branch `5.0.0`, with `docker-compose.yml`
edited: image tags `5.0.0-rc2` (the only published 5.0.0 tag), top-level
`name: wam5` (both stack directories are called `single-node`, which would
otherwise collide on project name, volumes and network), `container_name`
prefixed `wam5-`, host ports moved, and the EGRESS variable added to the
dashboard service.

| Service | Container | Host port -> container port |
|---|---|---|
| dashboard | `wam5-wazuh.dashboard` | 8444 -> 443 |
| indexer | `wam5-wazuh.indexer` | 9201 -> 9200 |
| manager | `wam5-wazuh.manager` | 1524 -> 1514, 1525 -> 1515, 1527 -> 1517, 55001 -> 55000 |

Login: `admin`. 5.0 ships no default passwords; they are created once by
`tools/utils/deployment/credentials-conf.sh` and live in
`<wazuh-docker-5>/single-node/config/credentials/{indexer,manager,dashboard}.env`
(never commit or paste them). Read the admin password with:

```bash
grep '^WAZUH_INDEXER_ADMIN_PASSWORD=' /c/Users/Chris/projects/wazuh-docker-5/single-node/config/credentials/indexer.env | cut -d= -f2-
```

The Server API user is `wazuh` with `WAZUH_MANAGER_API_PASSWORD` from
`manager.env` (`https://localhost:55001`). The 5.0 password rule allows only
`A-Z a-z 0-9 . , _ + : @ % ^ = ~ -` (12-64 chars, one of each class); `!` is
rejected.

Two one-off fixes the stock 5.0.0 compose file does not do, both needed before the
manager reports healthy and the plugin can provision:

1. The rc2 manager requires a client pair `indexer-connector.pem` /
   `indexer-connector-key.pem` issued by the indexer CA, owned `root:wazuh-manager`,
   mode 640. The certs tool generates it as `wazuh.manager.pem` / `wazuh.manager-key.pem`;
   a bind mount from Windows fails the ownership check, so copy it into the
   `wam5_wazuh_etc` volume once:

   ```bash
   cd /c/Users/Chris/projects/wazuh-docker-5/single-node
   SRC="$(cygpath -w "$PWD/wazuh-certificates")"
   MSYS_NO_PATHCONV=1 docker run --rm -v wam5_wazuh_etc:/etc/wazuh-manager -v "$SRC:/src:ro" \
     --entrypoint sh wazuh/wazuh-manager:5.0.0-rc2 -c '
       cp /src/wazuh.manager.pem /etc/wazuh-manager/certs/indexer-connector.pem &&
       cp /src/wazuh.manager-key.pem /etc/wazuh-manager/certs/indexer-connector-key.pem &&
       chown root:wazuh-manager /etc/wazuh-manager/certs/indexer-connector*.pem &&
       chmod 640 /etc/wazuh-manager/certs/indexer-connector*.pem'
   docker compose up -d --force-recreate wazuh.manager
   ```

2. On 5.0 the dashboard's indexer user (`kibanaserver`) only reads `wazuh-*`, so the
   plugin's store role and the native-read role from `install.sh` must be created by
   hand against `https://localhost:9201` (roles `wazuh_alert_manager_store` and
   `wazuh_alert_manager_native_read`, both mapped to `kibanaserver`; the JSON bodies
   are in `install.sh`), then restart `wazuh.dashboard`. Without the store role the
   plugin logs `failed to provision indices`.

Start / stop:

```bash
cd /c/Users/Chris/projects/wazuh-docker-5/single-node
docker compose up -d       # first start takes a few minutes; indexer needs vm.max_map_count=262144 (Docker Desktop sets it)
docker compose down        # add -v to drop the data volumes
```

#### How the 5.0 stack was prepared (no sudo on the host)

1. `wazuh-certs-tool.sh` and `config.yml` are not in the checkout. The
   production URLs in `docs/ref/getting-started/deployment/single-node.md`
   return 403 until 5.0.0 ships; the pre-release ones work:
   `https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/installation-assistant/wazuh-certs-tool-5.0.0-rc2.sh`
   and `config-5.0.0-rc2.yml`. `config.yml` was rewritten per the docs with
   nodes `wazuh.indexer`, `wazuh.manager` (ip `127.0.0.1`, dns
   `wazuh.manager`, `localhost`, `host.docker.internal`) and `wazuh.dashboard`.
2. `certificates-conf.sh --cert --copy --priv` and `credentials-conf.sh`
   need root and openssl, so they run inside `ubuntu:24.04` with the checkout
   bind-mounted. The Windows checkout has CRLF line endings, which bash
   rejects; the three scripts (`tools/utils/deployment/*.sh`,
   `build-docker-images/shared/password-policy.sh`) are copied into the
   container with `\r` stripped, keeping their relative layout, and run from
   `single-node/`:

   ```bash
   export MSYS_NO_PATHCONV=1
   W="$(cygpath -w /c/Users/Chris/projects/wazuh-docker-5)"
   docker run --rm -v "${W}:/w" -w /w/single-node -e WAZUH_INDEXER_ADMIN_PASSWORD='<password>' ubuntu:24.04 bash -lc '
     apt-get update -qq && apt-get install -y -qq openssl >/dev/null
     mkdir -p /opt/wd/tools/utils/deployment /opt/wd/build-docker-images/shared
     for f in tools/utils/deployment/certificates-conf.sh tools/utils/deployment/credentials-conf.sh build-docker-images/shared/password-policy.sh; do
       sed "s/\r$//" "/w/$f" > "/opt/wd/$f"; done
     bash /opt/wd/tools/utils/deployment/certificates-conf.sh --cert --copy --priv
     bash /opt/wd/tools/utils/deployment/credentials-conf.sh'
   ```

   Output: `config/{root-ca,wazuh_indexer,wazuh_manager,wazuh_dashboard}/certs`,
   `config/credentials/*.env`, plus `wazuh-certificates/` and the root CA key
   in `wazuh-ca/` (keep it; it is what issues certificates for new nodes).
   `chown`/`chmod` on the bind mount succeeded (Docker Desktop no-ops them).
3. `docker compose -f single-node/docker-compose.yml config` validates.
