# Wazuh Alert Manager 2.0

The recommended patch level is **2.0.2**. It contains the complete v2.0 feature
set, the durable high-volume automation worker, exact evidence counters and
bounded case previews. Versions 2.0.0 and 2.0.1 remain upgrade sources, but new
installations should use the latest release.

Version 2.0 turns the plugin into a bounded security-operations workbench while
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

## Validation

The release gate includes unit/integration tests, production builds in the
three-version compatibility matrix, a 4.14 browser workflow bench, lifecycle
retire/restore tests, and a clean installer/runtime smoke test against the
published release assets. The release page records the final outcome and
checksums.
