# Architecture

## Overview

Wazuh Alert Manager is an OpenSearch Dashboards **New Platform** plugin (server + public halves). It reads Wazuh alerts, maintains a parallel workflow record for each, and layers cases, automation, and reporting on top — all without touching `wazuh-alerts-*`.

## Indices the plugin owns

All indices are **v2**, auto-created and aliased on first start. Wazuh's native
`wazuh-alerts-*` indices are read-only evidence sources and are never written to.

| Index | Purpose |
|-------|---------|
| `wazuh-alert-status-v2-*` | Operational projection of each alert + its workflow state (status, assignee, case link, related-alert links, AI analysis, history). Exposed through read/write aliases and numeric rollover generations. |
| `wazuh-alert-manager-v2-activity` | Comment threads and audit events on alerts and cases (read/write aliases + generations). |
| `wazuh-alert-manager-v2-cases` | Cases (title, severity, status, alert IDs, correlation key, history). |
| `wazuh-alert-manager-v2-rules` | Automation (correlation) rules. |
| `wazuh-alert-manager-v2-meta` | Internal metadata: the sync watermark, leader lock, lifecycle settings, AI settings, retirement records. |
| `wazuh-alert-manager-v2-migration` | Legacy v1 -> v2 migration progress and checkpoint. |
| `wazuh-alert-manager-v2-sync-dlq` | Dead-letter queue for alerts that fail to sync. |

Legacy v1 indices (`wazuh-alert-status`, `wazuh-alert-manager-cases`,
`wazuh-alert-manager-comments`, `wazuh-alert-manager-rules`,
`wazuh-alert-manager-meta`) are read-only migration inputs and remain retained
after migration.

Mappings are versioned; an idempotent migration applies additive changes on start
and fails safe on incompatible ones. Write validation is fail-closed to the exact
prefixes `wazuh-alert-status-v2-` and `wazuh-alert-manager-v2-`.

## Lifecycle, retirement, and restore

The lifecycle is plugin-managed (see [[Lifecycle-Retention-and-RBAC]]): the stock
dashboard service account can create plugin indices but may lack cluster-wide ISM
policy privileges, so rollover is driven by the plugin worker rather than ISM.

- **Rollover** creates a new writable generation when the current one reaches its
  age or size threshold.
- **Retention** marks older, non-current generations "due" for review — it never
  deletes data automatically.
- **Retirement** carries every `open`/`in_progress` alert plus closed alerts needed
  by active cases or evidence holds into a compact carry index. Closed alerts in
  closed, unheld cases become archive-only with a durable evidence stub.
- **Restore** copies only IDs missing from the live store into the current writer,
  never overwriting a newer live record; it is idempotent and reversible.
- **Purge** is the only permanent deletion and always requires a separate explicit
  confirmation.

## The sync job

A background job periodically projects **new** Wazuh alerts into the
`wazuh-alert-status-v2-write` alias:

- It searches **sorted ascending** by `@timestamp` and advances its **watermark** only to the last alert actually copied — so a window with more matches than the batch size never silently drops the remainder.
- The copy is **field-protective**: plugin-owned fields (status, assignee, case link, history) are never overwritten by an incoming same-named Wazuh field.
- The whole tick runs under a **leader lock** (a document in the meta index), so with multiple dashboard replicas there is exactly one writer.

## Automation evaluation

After a tick commits its watermark, the enabled [[Automation Rules]] are evaluated against **that tick's batch**:

- **Per-alert** rules act on each matching alert immediately.
- **Burst** rules group the batch's matches by entity, then check each candidate entity's full window (threshold + any-of/all-of coverage) with an aggregation; a firing entity's burst gets the rule's actions, and case creation de-duplicates against the still-open case for that rule + entity.

Because candidate work is scoped to the batch, evaluation cost is proportional to new-alert volume, not index size.

## Front-end

- Two registered apps under one nav category: **Workbench** (Alerts / Cases / Settings) and **Reporting**.
- Charts (trends, donuts, status-over-time) use `@elastic/charts`, bundled by the monorepo; the attack-path graph is dependency-free SVG for maximum portability across OSD versions.

## Compatibility

The plugin is built per target (OSD 2.19.1 / 2.19.2 / 2.19.5 for Wazuh 4.12 / 4.13 / 4.14). The **server code is identical** across builds; only the version stamp differs. Each ZIP is compiled inside the matching official Wazuh Dashboard source tree rather than relabelled after the fact.
