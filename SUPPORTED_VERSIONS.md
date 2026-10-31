# Supported versions

OpenSearch Dashboards enforces an exact match between a plugin's
`opensearch_dashboards.json` -> `opensearchDashboardsVersion` and the
running dashboard's own version before it will load the plugin at all.
That check lives in the platform, not in this plugin, so there is no way
to make a single build "just work" across every dashboard version - what
this repo does instead is keep the plugin code itself limited to stable,
documented OSD APIs, so that targeting a new version is normally a
one-command rebuild rather than a rewrite:

```bash
node scripts/set-target-version.js --osd-version <version> --plugin-version <plugin-version>
```

Run that from inside `<wazuh-dashboard checkout>/plugins/wazuhAlertManager`
before `yarn build` (see README.md for the full build steps).

The same match requirement applies when building a custom Docker image
for a containerized deployment (see **Deploying on Docker / Kubernetes**
in README.md) - the plugin zip `COPY`'d into the image must match the
`wazuh-dashboard` base image tag's version, same as any other install.

| Wazuh release(s) | wazuh-dashboard / OSD version | Release artifact | CI build source |
|---|---|---|---|
| 4.12.0 | 2.19.1 | `wazuhAlertManager-2.19.1.zip` | `v4.12.0` |
| 4.13.0–4.13.1 | 2.19.2 | `wazuhAlertManager-2.19.2.zip` | `v4.13.1` |
| 4.14.0–4.14.1 | 2.19.3 | `wazuhAlertManager-2.19.3.zip` | `v4.14.1` |
| 4.14.2–4.14.4 | 2.19.4 | `wazuhAlertManager-2.19.4.zip` | `v4.14.4` |
| 4.14.5–4.14.7 | 2.19.5 | `wazuhAlertManager-2.19.5.zip` | `v4.14.7` |
| 4.14.8–4.14.9 | 2.19.6 | `wazuhAlertManager-2.19.6.zip` | `v4.14.9`; browser-tested on 4.14.9 |

These mappings come from each official `wazuh/wazuh-dashboard` release tag.
The one-line installer reads the installed dashboard's `package.json` and
selects the artifact by its exact OSD version; it does not guess from the Wazuh
minor version. When Wazuh publishes another patch, its dashboard tag must be
checked before that patch is claimed as supported. If it introduces a new OSD
version, add a CI target and release ZIP first. If it retains an OSD version
already listed above, the existing exact-version ZIP remains compatible, but
the new Wazuh patch must still be smoke-tested and added to this table.

APIs this plugin relies on (all stable across the 2.19.x line, and
unlikely to move soon):

- `core.http.createRouter` / `IRouter` for server routes
- `core.opensearch.client.asCurrentUser` / `asInternalUser`
- `core.application.register` for the front-end app
- The `data` plugin as a required dependency
- `@elastic/eui` components

If a future OSD major version renames or removes one of these, the fix is
localized to `server/lib/opensearch.ts` (the OpenSearch client access
point) or the relevant route/component - not a rewrite of the whole
plugin.
