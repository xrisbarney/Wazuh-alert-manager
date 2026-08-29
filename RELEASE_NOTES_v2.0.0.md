# Wazuh Alert Manager 2.0.0

Version 2.0 turns the plugin into a bounded, upgrade-safe SOC workbench for
Wazuh 4.12–4.14. Matching release ZIPs are compiled inside the official Wazuh
Dashboard source trees for OpenSearch Dashboards 2.19.1, 2.19.2, and 2.19.5.

## Highlights

- Plugin-owned rollover families for alerts, activity, cases, and evidence;
  native `wazuh-alerts-*` remains read-only.
- Reviewed retirement, guarded restore, archived-case reopen, evidence holds,
  and separately confirmed purge.
- Safe resumable migration from the legacy `wazuh-alert-status` single index.
- Exact, non-sampled operational reporting with write-time SLA fields and
  composite analyst pagination.
- Durable forward-only automation with immediate and correlated-burst triggers,
  constrained AND/OR entity expressions, case deduplication/routing, preview,
  revisions, safety caps, queue fencing, and dead-letter handling.
- Case evidence snapshots and trusted archive resolution prevent closed cases
  from pinning full operational alerts forever.
- Case and alert summaries, collapsible workbench cards, multi-select case
  severity/assignee filters, sticky navigation, corrected light-theme contrast,
  flyout-safe toasts, and expanded attack-path graph/timeline views.
- One-line version-detecting installer with mandatory SHA-256 verification,
  backup, runtime checks, and rollback.

## Validation

- 32 Jest suites / 323 tests.
- Headed Playwright release bench: 11 passed, one prerequisite probe skipped,
  zero failures on Wazuh 4.14.7.
- The release workflow independently builds and tests the 4.12, 4.13, and 4.14
  source targets before publishing any tag.

## Upgrade notes

Installation remains install-and-go. Provisioning and migration are idempotent
and run on plugin startup. Legacy indices are retained as read-only migration
inputs. Do not manually rename a ZIP for another dashboard version; install the
artifact whose OSD version exactly matches `/usr/share/wazuh-dashboard/package.json`.

See the wiki pages **Installation**, **Lifecycle, Retention and RBAC**,
**Case Evidence and Case Lifecycle**, **Automation Rules**, and **Reporting** for
full operational guidance.
