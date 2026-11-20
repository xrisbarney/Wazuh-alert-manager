# Wazuh Alert Manager 2.0.3

This page documents the **2.0.3** release. It contains the bounded storage model,
durable high-volume automation worker, exact evidence counters, and bounded case
previews. Existing plugin data is migrated during upgrade; new installations
should use the matching 2.0.3 archive.

Version 2.0.3 provides a bounded security-operations workbench while
keeping Wazuh's native `wazuh-alerts-*` indices read-only.

## Supported releases

| Wazuh release(s) | OpenSearch Dashboards | Release asset |
|------------------|-----------------------|---------------|
| 4.12.0 | 2.19.1 | `wazuhAlertManager-2.19.1.zip` |
| 4.13.0–4.13.1 | 2.19.2 | `wazuhAlertManager-2.19.2.zip` |
| 4.14.0–4.14.1 | 2.19.3 | `wazuhAlertManager-2.19.3.zip` |
| 4.14.2–4.14.4 | 2.19.4 | `wazuhAlertManager-2.19.4.zip` |
| 4.14.5–4.14.7 | 2.19.5 | `wazuhAlertManager-2.19.5.zip` |
| 4.14.8–4.14.10 | 2.19.6 | `wazuhAlertManager-2.19.6.zip` |

Each ZIP is built inside the matching official Wazuh Dashboard source tree. The
installer detects the dashboard version and refuses to guess when it is not in
the supported matrix.

Prebuilt container images are published for every row of the table at
`ghcr.io/xrisbarney/wazuh-dashboard-alert-manager:<wazuh version>` (and
`<wazuh version>-wam2.0.3`); see
[[Installation#container-deployments-docker--kubernetes]].

## What changed in 2.0.3

- Exact-version compatibility was extended to every OpenSearch Dashboards
  release used by Wazuh 4.12.0 through 4.14.10 (six archives, table above). A
  scheduled compatibility guard in the repository detects new Wazuh patch tags,
  upstream OSD-version changes, and drift between the installer and the build
  matrix.
- Related-alert linking and bulk alert mutations are immediately searchable.
- The Workbench header and the redesigned case views follow the active
  dashboard theme and stay legible in dark mode.
- Linked alerts show the Wazuh rule ID.
- The case attack graph provides directed, count-labelled relationships,
  draggable saved layouts, graph-to-alert navigation, an alert timeline, MITRE
  technique summaries, and kill-chain context. Graph descriptions use
  evidence-neutral language rather than inferring attacker intent from entity
  co-occurrence, and graph data loads only when its tab is opened.
- Build metadata records the plugin source revision instead of inheriting the
  surrounding Wazuh Dashboard repository revision.

Post-release updates to this version's distribution:

- 2026-11-09: Wazuh 4.14.10 was added to the compatibility matrix. It ships
  the same OpenSearch Dashboards 2.19.6, so `wazuhAlertManager-2.19.6.zip`
  applies unchanged and no new plugin version was cut.
- 2026-11-19: prebuilt dashboard container images with the plugin preinstalled
  were published to GitHub Container Registry for all fourteen supported Wazuh
  releases.

## 2.0 line highlights

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

Version 2.0.3 was built for all six supported dashboard versions against the
official `wazuh/wazuh-dashboard` source tags and exercised through 34 Jest
suites (354 tests), browser workflows, lifecycle retire/restore tests, and a
clean installer/runtime smoke test against the published release assets. The
OSD 2.19.6 archive was installed and browser-tested on Wazuh 4.14.9, with
Playwright covering sign-in, theme behavior, manual case creation, evidence
hold/release, graph and timeline views, case status transitions, and closure.

The v2.0.2 high-volume benchmark below remains applicable because 2.0.3 does
not change the storage or automation pipeline.

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
