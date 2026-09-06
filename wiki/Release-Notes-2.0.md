# Wazuh Alert Manager 2.0.2

This page documents the **2.0.2** release. It contains the bounded storage model,
durable high-volume automation worker, exact evidence counters, and bounded case
previews. Existing plugin data is migrated during upgrade; new installations
should use the matching 2.0.2 archive.

Version 2.0.2 provides a bounded security-operations workbench while
keeping Wazuh's native `wazuh-alerts-*` indices read-only.

## Supported releases

| Wazuh | OpenSearch Dashboards | Release asset |
|-------|-----------------------|---------------|
| 4.12.x | 2.19.1 | `wazuhAlertManager-2.19.1.zip` |
| 4.13.x | 2.19.2 | `wazuhAlertManager-2.19.2.zip` |
| 4.14.x | 2.19.5 | `wazuhAlertManager-2.19.5.zip` |

Each ZIP is built inside the matching official Wazuh Dashboard source tree. The
installer detects the dashboard version and refuses to guess when it is not in
the supported matrix.

## Highlights

- Rollable, alias-backed plugin storage with administrator-controlled rollover,
  retention, retirement, restore, reopen, holds, and purge guards.
- Safe migration from the legacy single `wazuh-alert-status` index.
- Bounded case evidence: closed evidence can retire without forcing every
  case-linked alert to remain in a live index forever.
- Immediate and correlated-burst automations with boolean entity groups,
  deduplicated case routing, previews, safety limits, and audit history.
- Collapsible alert and case summaries, improved light/dark themes, persistent
  workbench navigation, visible toasts, case severity/assignee filters, and
  corrected case deep links.
- Interactive attack graph and chronological/MITRE views for linked evidence.
- Exact reporting metrics with no alert sampling. Archived operational data is
  deliberately outside live SLA reports until it is restored.

## Upgrade behavior

An upgrade preserves plugin-owned data. Provisioning creates the v2 alias
families, then resumable migration/backfill jobs safely project legacy data into
the new model. The original `wazuh-alert-status` index remains a read-only
migration source; it is not automatically deleted.

Use the [[Installation]] guide for the one-line installer, integrity checks,
automatic backup, rollback, and offline installation. Review
[[Lifecycle, Retention and RBAC|Lifecycle-Retention-and-RBAC]] before changing
retention, and [[Automation Rules]] before enabling production actions.

## Validation evidence

Version 2.0.2 was built for all three supported dashboard versions and exercised
through unit/integration tests, browser workflows, lifecycle retire/restore
tests, and a clean installer/runtime smoke test against the release assets.

The high-volume plugin-pipeline benchmark ran three exact 100,000-alert trials on
a single-node Wazuh 4.14 / OpenSearch Dashboards 2.19.5 VirtualBox development VM.
End-to-end times were 246.181, 219.596, and 238.081 seconds. Every trial produced
the same verified result:

| Result | Exact count per trial |
|---|---:|
| Operational alert projections | 100,000 |
| Deduplicated cases | 42 |
| Case evidence relationships | 5,300 |
| Alerts closed by automation | 5,000 |
| Alerts assigned and moved to In progress | 2,500 |
| Negative-control alerts | 87,200 |
| Actions on negative controls | 0 |
| Automation queue remaining at completion | 0 |

One trial included a dashboard restart to exercise durable admission and worker
recovery. The benchmark injected controlled data into the plugin pipeline; it
did not include Wazuh agent-to-manager transport and is therefore evidence of
plugin behavior under this workload, not a universal production-capacity claim.
The reproducible kit and exact results are stored in
[`benchmark/evidence/v2.0.2-100k`](https://github.com/xrisbarney/Wazuh-alert-manager/tree/main/benchmark/evidence/v2.0.2-100k).
