# Wazuh Alert Manager v3.0.0 (draft, not released)

One plugin for Wazuh 4.x and Wazuh 5.0. The same source tree, plugin id and
`*-v2-*` storage now serve both platform lines; each release artifact is
compiled for one exact OpenSearch Dashboards version and knows which Wazuh
line it targets.

## Highlights

- **Wazuh 5.0 support (OSD 3.6.0).** A 5.0 build reads the
  `wazuh-findings-v5-*` data streams instead of the 4.x `wazuh-alerts-*`
  indices, normalizes each finding into the existing bounded canonical record,
  and follows a finding's `event.index` / `event.doc_id` to its underlying
  `wazuh-events-v5-*` event only when an analyst opens it. Native storage on
  both lines stays read-only.
- **Automatic source detection.** Every sync tick resolves the native source
  from the build target and `sync.sourceMode` (`auto` by default), validates
  any `sync.sourceIndexPattern` override against the selected family, and
  probes that the pattern resolves to the expected indices or data streams.
  The result (`ready`, `waiting`, or `blocked` with a reason) is shown in
  Storage Health. The plugin never falls back to a different pattern.
- **Labelled severity, no fake numbers.** Wazuh 5.0 rule levels are labels
  (`informational`, `low`, `medium`, `high`, `critical`). They are stored
  verbatim in the new `severity_label` field; `rule.level` stays null for 5.0
  records. Rule minimum levels, level filters and SLA tiers apply to 5.0
  records through severity bands (0-3 low, 4-6 medium, 7-11 high, 12+
  critical), which are the bands the UI has always badged.
- **Platform wording.** On a Wazuh 5.0 build the workbench says *Findings*
  (Finding queue, Finding details, Linked findings, Operational findings)
  where a 4.x build says Alerts. Routes, fields and storage are unchanged.
- **Safer hydration.** Before any read of a stored `source_index`, the index
  is re-validated against its family's exact physical-index matcher; the
  5.0 second hop to the event requires a `.ds-wazuh-events-*` backing index.
- **Write guard by name.** Besides the exact plugin prefixes, every native
  Wazuh prefix (4.x alerts, 5.0 events/findings and their `.ds-` backing
  indices, states, native case management) is refused explicitly.

- **Wazuh 5.0 platform differences handled.** The 5.0 dashboard's indexer
  user is read-only on `wazuh-*`, so the installer grants it a least-privilege
  role scoped to the plugin's two exact prefixes (or prints the role for
  distributed installs). The 5.0 indexer also blocks the create-index API
  cluster-wide; the plugin provisions its stores through a temporary
  plugin-owned template and a bootstrap write instead.

## Upgrade notes

- Existing 4.x installs upgrade in place. Mapping version 13 adds
  `source_family`, `source_profile_version`, `severity_label`,
  `event_index`, `event_doc_id` and `space` to every alert generation.
  The 4.x sync cursor keeps its `sync_state` document; a 5.0 build uses
  `sync_state:wazuh5_findings`, so a 4.x cursor is never replayed against
  findings after a platform upgrade.
- New config key `wazuh_alert_manager.sync.sourceMode`
  (`auto` | `wazuh4_alerts` | `wazuh5_findings`). `sync.sourceIndexPattern`
  is now an optional override and must stay inside the selected family.
  `sync.minRuleLevel` is ignored for 5.0 labelled severity.
- `/api/wazuh_alert_manager/system/version` now reports
  `targetWazuhVersion` and `targetWazuhMajor`; `/system/health` gains a
  `source` block; `GET /alerts/{id}` gains `_raw_event`, `_event_available`
  and `_source_family`.
- Build tooling: `scripts/set-target-version.js --wazuh-version`,
  `TARGET_WAZUH_VERSION` / `TARGET_WAZUH_MAJOR` in `common/build_info.ts`,
  a prerelease 5.0 row in `supported-wazuh-versions.json`, and
  `install.sh` recognizing OSD 3.6.0 and running the plugin CLI as the owner
  of the dashboard's `plugins/` directory (Wazuh 5.0 packages keep that tree
  root-owned; 4.x hands it to the `wazuh-dashboard` user).
- Test tooling: `e2e/seed_findings_v5.py` and
  `WAM_BENCH_PROFILE=wazuh5` for `benchmark/bench.py` write only to
  plugin-owned `wazuh-*-v5-wam-*` test data streams;
  `benchmark/reset_v2.py --include-wam-test-streams` removes them.

## Verified so far (development evidence, not release gates)

- Wazuh 4.14.9 / OSD 2.19.6: unit suite (39 suites / 394 tests), in-place
  upgrade from v2.0.3 through `install.sh` (mapping v13, source detection,
  sync resumed), installer rollback and re-install, dashboard restart,
  headed browser bench (all mutating specs pass except one failure that is
  identical on v2.0.3).
- Wazuh 5.0.0-rc2 / OSD 3.6.0: live discovery of the findings data model,
  nanosecond-timestamp cursor behaviour, rollover during a point-in-time
  window, event hydration, admin and mapped non-admin identity shapes.

## Known limitations

- Wazuh 5.0 is prerelease; the 5.0 target is re-verified when 5.0 is final.
- `sync.minRuleLevel` applies only to 4.x; on 5.0 use the new
  `sync.minSeverityLabel` (label floor applied to `wazuh.rule.level` at the
  source).
- Native 5.0 single-finding cases (`wazuh.case.*`) and plugin cases remain
  separate; there is no import or two-way sync.
