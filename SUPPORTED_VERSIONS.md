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

| Wazuh version | wazuh-dashboard / OSD version | Status |
|---|---|---|
| 4.12 | 2.19.1 | Previously built (v1.0.1 release) |
| 4.13 | 2.19.2 | Previously built (v1.0.1 release) |
| 4.14 | 2.19.5 | Current default target, built and tested against a real 4.14 all-in-one install |

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
