# Architecture

## Overview

Wazuh Alert Manager is an OpenSearch Dashboards **New Platform** plugin (server + public halves). It reads Wazuh alerts, maintains a parallel workflow record for each, and layers cases, automation, and reporting on top — all without touching `wazuh-alerts-*`.

## Indices the plugin owns

| Index | Purpose |
|-------|---------|
| `wazuh-alert-status` | The synced alert + its workflow state (status, assignee, case link, history, related-alert links, AI analysis). |
| `wazuh-alert-manager-cases` | Cases (title, severity, status, alert IDs, correlation key, history). |
| `wazuh-alert-manager-comments` | Comment threads on alerts and cases. |
| `wazuh-alert-manager-rules` | Automation rules. |
| `wazuh-alert-manager-meta` | Internal metadata: the sync watermark and the leader lock. |

Mappings are versioned; an idempotent migration applies additive changes on start and fails safe on incompatible ones.

## The sync job

A background job periodically copies **new** Wazuh alerts into `wazuh-alert-status`:

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

The plugin is built per target (OSD 2.19.1 / 2.19.2 / 2.19.5 for Wazuh 4.12 / 4.13 / 4.14). The **server code is identical** across builds; only the version stamp differs. It targets the OUI/EUI generation shipped with those dashboards.
