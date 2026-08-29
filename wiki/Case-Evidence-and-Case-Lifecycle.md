# Case evidence and case lifecycle

## Architecture decision

Keeping every case-linked alert in the live operational alias forever is only an
interim correctness measure. It protects case drill-down, but recreates
unbounded storage as closed cases accumulate.

The scalable design separates:

1. the mutable operational alert used by triage;
2. a compact, durable case-evidence relationship and snapshot; and
3. the immutable full alert in a retained physical archive generation.

Inspecting one archived case alert must not require restoring a complete
generation. The server resolves the live alert first, then reads the exact
document from a trusted plugin-owned archive locator. Full-generation restore is
reserved for rollback and disaster recovery.

Archived alerts and cases are outside live reporting aliases. Restoring missing
alerts can make them reappear in the Workbench and alter totals, timing, and SLA
results for historical periods; newer live records are not overwritten. Reports
are operational views rather than immutable compliance records.

## Rollable evidence relationships

The evidence family uses:

```text
wazuh-alert-manager-v2-evidence-read
wazuh-alert-manager-v2-evidence-write
wazuh-alert-manager-v2-evidence-000001
```

One document represents one case-alert relationship, using a stable ID derived
from `case_id` and `alert_id`. It stores the exact plugin archive location,
read-only native provenance, a lifecycle state, audit timestamps, an optional
hold, and a bounded snapshot containing the status, timestamp, rule, level,
agent, and entities required for case context and attack-path reconstruction.

The snapshot is not a second full alert copy. Large raw payloads, comments, AI
output, and mutable triage history remain in their appropriate stores.

Rollover alone does not leave every evidence generation searchable forever.
From Storage & lifecycle, an administrator can compact any non-write evidence
generation. The server copies every current relationship insert-only into the
writer, including holds and archive locators, verifies every bulk result, then
write-blocks and detaches the source. The retained source can be explicitly
purged later because the live relationship is already carried forward.

## Alert retirement

Before alias cutover, retirement validates all affected records in batches:

- always carry `open` and `in_progress` alerts;
- carry a closed alert only while it belongs to an active case or has an explicit
  evidence hold;
- verify or create evidence relationships and snapshots for every linked alert;
- make closed alerts belonging only to closed, non-held cases archive-only;
- atomically detach the old generation only after carry and evidence counts pass.

The case UI renders the snapshot immediately. “View full evidence” performs a
server-side live lookup followed by a direct read from the exact retained archive.
The browser cannot provide an arbitrary index name. If the archive is offline or
policy-purged, the stub remains and reports the precise state.

Archive purge is blocked while referenced evidence belongs to an active case or
has a hold. Once closed-case evidence retention expires, a privileged explicit
purge may remove full payloads; stubs remain auditable as `purged`.

## Rollable cases

The case store is alias-backed:

```text
wazuh-alert-manager-v2-cases-read
wazuh-alert-manager-v2-cases-write
wazuh-alert-manager-v2-cases-000001
```

Rollover alone is not sufficient if every generation remains in the live read
alias. When an old case generation is retired:

- open and in-progress cases are copied to the current generation;
- closed cases remain live-searchable for the configured case-retention period;
- expired closed cases move to an Archived Cases view and remain directly
  retrievable while their physical generation is retained;
- reopening an archived case copies it into the current generation;
- purge remains separate, RBAC-gated, explicitly confirmed, and hold-aware.

Case documents remain bounded metadata: title, status, severity, owner, counters,
timestamps, and summaries. The relationship family—not an indefinitely growing
`alert_ids` array—is the long-term source of truth for membership.

## Workbench policy

Expose distinct, clearly explained settings for operational alerts, closed cases,
full case evidence, activity/audit data, and evidence holds. Rollover,
eligibility, retirement, archive lookup, restore, and permanent purge are separate
operations. Retention thresholds only mark items due.

All mutations use the existing lifecycle-manager gate (`all_access` or
`index_management_full_access`).

## What an analyst sees after retirement

A retired closed alert does not need to remain a full operational alert merely
because it once belonged to a case. The case retains a relationship stub and a
bounded snapshot (time, rule, level, agent, entities, status, and availability).
When the retained physical alert generation still exists, **View full evidence**
resolves that exact trusted archive location server-side. If policy later purges
the payload, the stub remains and clearly reports `purged`; it never substitutes
an unrelated alert or accepts an arbitrary browser-supplied index.

Example lifecycle:

1. Alert `A` is linked to active case `C`; retirement carries `A` forward.
2. `C` is closed and its hold is released.
3. A later alert-generation retirement archives `A` instead of copying the full
   operational document forever.
4. `C` still shows the evidence snapshot and can resolve the full retained alert.
5. If `C` itself ages beyond case retention, case-generation retirement moves it
   to Archived Cases.
6. Reopen copies `C` to the current writer; restoring a whole alert generation is
   unnecessary unless an administrator intentionally wants those alerts live
   again.

## Non-destructive migration

1. Provision evidence and case alias families without changing legacy stores.
2. Backfill evidence relationships from case `alert_ids` and alert `case_id`,
   recording discrepancies instead of guessing.
3. Dual-write relationship changes during backfill.
4. Validate per-case counts, then use relationship-first reads with legacy-array
   fallback.
5. Enable direct archived-evidence lookup and the bounded retirement planner.
6. Convert cases to rollover generations and enable archived case workflows.
7. Remove fallback only in a later release after an explicit health check.

Every phase is resumable. Native `wazuh-alerts-*` indices remain read-only.
