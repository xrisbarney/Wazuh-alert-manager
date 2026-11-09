# Installation

Wazuh Alert Manager is an OpenSearch Dashboards plugin that installs into the
Wazuh Dashboard. It is a **single zip** per supported dashboard version, and a
**one-line installer** handles detection, integrity verification, backup, and
rollback.

## Where to install it

Install the plugin on the **Wazuh Dashboard node**. Do not install it on a
Wazuh manager, indexer-only node, or agent. The plugin runs inside the Dashboard
process and reaches the Wazuh Indexer/OpenSearch cluster through the
Dashboard's configured service identity.

For a distributed or highly available deployment:

1. Run the installer on **every Wazuh Dashboard replica** that can receive user
   traffic.
2. Use the artifact that exactly matches each replica's OpenSearch Dashboards
   version. A load balancer must not send users to a replica where the plugin is
   absent or has a different version.
3. Apply the same `wazuh_alert_manager.*` configuration and encryption-key
   environment variable to every replica, then restart them using the site's
   normal rolling-maintenance procedure.
4. Install nothing on manager, indexer-only, or agent nodes. Plugin data is
   stored centrally in the indexer under `wazuh-alert-status-v2-*` and
   `wazuh-alert-manager-v2-*`, so it remains available whichever Dashboard
   replica serves the request.

Multiple Dashboard replicas are supported. Distributed leases ensure that
only one healthy replica owns a given background sync, lifecycle, or automation
work lane at a time; another replica can take over after the lease expires.
Installing on every Dashboard replica is therefore required for consistent UI
availability and does not multiply alert processing.

## Supported versions

The plugin artifact must match the exact OpenSearch Dashboards version, or the
dashboard refuses to load it:

| Wazuh release(s) | OpenSearch Dashboards | Artifact |
|------------------|-----------------------|----------|
| 4.12.0 | 2.19.1 | `wazuhAlertManager-2.19.1.zip` |
| 4.13.0–4.13.1 | 2.19.2 | `wazuhAlertManager-2.19.2.zip` |
| 4.14.0–4.14.1 | 2.19.3 | `wazuhAlertManager-2.19.3.zip` |
| 4.14.2–4.14.4 | 2.19.4 | `wazuhAlertManager-2.19.4.zip` |
| 4.14.5–4.14.7 | 2.19.5 | `wazuhAlertManager-2.19.5.zip` |
| 4.14.8–4.14.10 | 2.19.6 | `wazuhAlertManager-2.19.6.zip` |
| 5.0.0 (rc2; development target) | 3.6.0 | `wazuhAlertManager-3.6.0.zip` |

The same plugin serves both Wazuh lines. A build for Wazuh 4.x reads
`wazuh-alerts-*`; a build for Wazuh 5.0 reads the `wazuh-findings-v5-*` data
streams. The installer picks the artifact from the running dashboard's exact
OpenSearch Dashboards version, so there is nothing to choose by hand. Wazuh
5.0 support is in development while 5.0 is prerelease; see
[[Architecture#one-plugin-for-wazuh-4x-and-50]].

### Wazuh 5.0 specifics

Two platform differences on Wazuh 5.0 are handled for you:

- **Store ownership.** The dashboard's indexer user (`kibanaserver`) is read-only on
  `wazuh-*` on 5.0. The installer creates the OpenSearch Security role
  `wazuh_alert_manager_store` (`indices_all` on `wazuh-alert-status-v2-*` and
  `wazuh-alert-manager-v2-*` only, plus point-in-time and bulk cluster
  permissions) and maps that user to it, using the admin credentials the Wazuh
  installer leaves in `/etc/wazuh-indexer/export/credentials.env`. On a
  distributed deployment without those credentials it prints the exact role to
  create. Native Wazuh storage is not part of the role. Use `--dashboard-user`,
  `--indexer-url` or `--skip-store-role` to adjust.
- **Blocked create-index API.** The 5.0 indexer sets
  `cluster.blocks.create_index: true`. The plugin provisions each of its stores
  through a temporary plugin-owned index template and a bootstrap write (which
  auto-creates the index with the right mappings and aliases), then removes
  both the bootstrap document and the template. Rollover generations are
  unaffected. You will see `Created ... through a bootstrap write` in the
  dashboard log on 5.0.


The installer reads the dashboard's own `package.json` (`version`) to select the
artifact and refuses any version not in this table — it never guesses. Wazuh
patch releases do not all use the same dashboard version, which is why 4.14 has
four rows. Check this table again after upgrading Wazuh.

## One-line installer

```bash
# Latest compatible release
curl -fsSL https://github.com/xrisbarney/Wazuh-alert-manager/releases/latest/download/install.sh | sudo bash

# Pinned release (recommended)
curl -fsSL https://github.com/xrisbarney/Wazuh-alert-manager/releases/latest/download/install.sh | sudo bash -s -- --version 2.0.3

# Local / offline artifact
sudo ./install.sh --artifact ./wazuhAlertManager-2.19.6.zip \
  --checksum ./wazuhAlertManager-2.19.6.zip.sha256
```

For stronger supply-chain safety, download and verify the installer before
running it:

```bash
curl -fsSLO https://github.com/xrisbarney/Wazuh-alert-manager/releases/download/v2.0.3/install.sh
curl -fsSLO https://github.com/xrisbarney/Wazuh-alert-manager/releases/download/v2.0.3/install.sh.sha256
sha256sum -c install.sh.sha256
sudo bash install.sh --version 2.0.3
```

The default release host is GitHub Releases (override with `--base-url` or the
`WAM_RELEASE_BASE_URL` environment variable for a private mirror). Versioned artifacts are published under
`<base-url>/download/v<version>/wazuhAlertManager-<osd>.zip` plus `.sha256` (required)
and `.minisig` (optional, verified when `minisign` and
`WAM_MINISIGN_PUBLIC_KEY` are present). `<base-url>/latest/download/` resolves the newest
release for the "latest" mode.

## What the installer does

1. Detects the installed OpenSearch Dashboards version.
2. Selects the matching artifact; fails closed on unsupported versions.
3. Downloads the ZIP (or uses the local `--artifact`).
4. Verifies the SHA-256 checksum and, when available, the minisign signature.
5. Backs up the currently installed plugin to `/var/lib/wazuh-alert-manager/backups`.
6. Stops `wazuh-dashboard`.
7. Removes the previous plugin code and installs the new artifact via the
   dashboard plugin installer (as the `wazuh-dashboard` user).
8. Restarts the dashboard and waits for readiness.
9. Verifies the plugin backend route and the browser login route.
10. Rolls back automatically if installation or startup fails.
11. Prints a concise success report.

No Wazuh credentials are required. On first startup the plugin provisions or
migrates its own indices using the dashboard service identity.

## What the installer never does

- Modifies `wazuh-alerts-*` (read-only evidence source).
- Deletes plugin data during an upgrade (data lives in OpenSearch, not on disk).
- Purges legacy `wazuh-alert-status` (retained read-only migration input).
- Installs custom Wazuh security roles.
- Disables certificate verification for downloaded releases.

## Modes

| Command | Effect |
|---------|--------|
| `install.sh --version 2.0.3` | Fresh install, v2 upgrade, or same-version reinstall |
| `install.sh --dry-run` | Resolve versions/artifacts and print the plan without changing anything |
| `install.sh --no-restart` | Install but leave the dashboard stopped |
| `install.sh --rollback` | Restore the most recent backup |
| `install.sh --uninstall-plugin` | Remove the plugin, retain all data |
| `install.sh --remove-data` | After a second confirmation, print exact manual indexer cleanup instructions. It never accepts indexer credentials or deletes data itself, and never targets `wazuh-alerts-*`. |

## Release-side tooling

Generate checksums and signatures after building:

```bash
scripts/make-release-artifacts.sh build          # *.zip.sha256 (+ .minisig)
scripts/make-release-artifacts.sh --installer    # install.sh.sha256 (+ .minisig)
```

Set `WAM_MINISIGN_SECRET_KEY` to also produce minisign signatures; consumers set
`WAM_MINISIGN_PUBLIC_KEY` to verify them.
