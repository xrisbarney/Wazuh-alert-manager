# Architecture

## Version 2.0.2 overview

Wazuh Alert Manager 2.0.2 is an OpenSearch Dashboards New Platform plugin with server and browser components. It reads native Wazuh alert indices, builds a bounded operational projection, and adds alert workflow, cases, evidence relationships, automation, lifecycle controls, reporting, and optional AI analysis.

The central safety boundary is strict: native Wazuh storage is read-only, whether it is a 4.x `wazuh-alerts-*` index or a 5.0 `wazuh-events-v5-*` / `wazuh-findings-v5-*` data stream (and its hidden `.ds-` backing indices). Every plugin write is restricted to the exact `wazuh-alert-status-v2-` and `wazuh-alert-manager-v2-` prefixes, and the write guard additionally refuses every native prefix by name.

## One plugin for Wazuh 4.x and 5.0

The same source tree is compiled once per exact OpenSearch Dashboards version. Each build records the Wazuh release it targets, and that decides the only native *source family* the build may read:

| Family | Wazuh | Native source (read-only) | Severity model | Underlying evidence |
|---|---|---|---|---|
| `wazuh4_alerts` | 4.12–4.14 | `wazuh-alerts-*` indices | numeric `rule.level` 0–16 | the alert itself (`full_log`) |
| `wazuh5_findings` | 5.0 | `wazuh-findings-v5-*` data streams | label in `wazuh.rule.level` (`informational`, `low`, `medium`, `high`, `critical`) | the finding's `event.index` / `event.doc_id` in a `wazuh-events-v5-*` stream, read on demand |

A *source adapter* per family builds the sync query and normalizes each hit into the same bounded canonical record (`agent.*`, `rule.*`, `data.*` entities, MITRE, provenance). Cases, evidence, automation, reporting, lifecycle and the UI consume only that canonical record and do not know which family produced it. 5.0 records keep their severity label verbatim in `severity_label` and leave `rule.level` null; nothing converts a label into a number. Numeric thresholds (rule `minLevel`, level filters, SLA tiers) apply to 5.0 records through severity bands (0–3 low, 4–6 medium, 7–11 high, 12+ critical), the same bands the UI has always badged.

Source detection runs every sync tick: `sync.sourceMode` (`auto`, the default, or an explicit family that must be eligible for the build) selects the family; an optional `sync.sourceIndexPattern` override must stay inside it; a read-only probe confirms the pattern resolves to the expected indices or data streams with a mapped `@timestamp`. The outcome (`ready`, `waiting` for a not-yet-created source, or `blocked` with the reason) is recorded in the meta index and shown in Storage Health. The plugin never falls back to another pattern. Sync cursors are kept per family, so a 4.x cursor is never replayed against 5.0 findings after a platform upgrade.

## Plugin-owned storage

Four data families use read/write aliases and numeric rollover generations:

| Family | Read alias | Write alias | Initial generation | Purpose |
|---|---|---|---|---|
| Alert projection | `wazuh-alert-status-v2-read` | `wazuh-alert-status-v2-write` | `wazuh-alert-status-v2-000001` | Selected operational alert fields plus status, assignment, case preview, and workflow metadata. |
| Activity | `wazuh-alert-manager-v2-activity-read` | `wazuh-alert-manager-v2-activity-write` | `wazuh-alert-manager-v2-activity-000001` | Comments and audit activity for alerts and cases. |
| Cases | `wazuh-alert-manager-v2-cases-read` | `wazuh-alert-manager-v2-cases-write` | `wazuh-alert-manager-v2-cases-000001` | Case records, state, ownership, correlation identity, and bounded alert previews. |
| Evidence | `wazuh-alert-manager-v2-evidence-read` | `wazuh-alert-manager-v2-evidence-write` | `wazuh-alert-manager-v2-evidence-000001` | Authoritative case-to-alert relationships and evidence snapshots. |

The following are fixed stores. "Fixed" means that each has one stable index name rather than a rollover alias; it does not mean the documents are immutable.

| Index | Purpose |
|---|---|
| `wazuh-alert-manager-v2-meta` | Sync cursor, leases, lifecycle settings, AI settings, and retirement metadata. |
| `wazuh-alert-manager-v2-rules` | Enabled and disabled automation rules. |
| `wazuh-alert-manager-v2-migration` | Resumable legacy migration checkpoints and validation state. |
| `wazuh-alert-manager-v2-sync-dlq` | Source alerts that could not be projected after retry handling. |
| `wazuh-alert-manager-v2-automation-queue` | Durable automation events and their processing state. |
| `wazuh-alert-manager-v2-automation-dlq` | Automation events that exhausted retry handling. |
| `wazuh-alert-manager-v2-automation-executions` | Idempotency records and content-addressed ruleset snapshots. |

Mappings are bounded and versioned. Provisioning is idempotent and applies compatible mapping additions across retained generations. Legacy v1 indices are read-only migration inputs and are retained after migration.

## Alert synchronization

One dashboard replica at a time acquires a renewable sync lease. The synchronizer resolves the native source for this build (see above), then reads new native alerts or findings with a point-in-time search, a composite `@timestamp` and document-ID cursor, and an overlap window. On 5.0, where `@timestamp` is nanosecond-precision, the sort key is cast to milliseconds so the persisted cursor stays exact; a backing-index rollover during a point-in-time window is harmless because the window keeps its frozen view and the next window (with overlap) picks up the new generation. Full batches trigger an immediate continuation rather than waiting for the next configured interval.

For each batch, the server:

1. reconciles incomplete automation admissions from an earlier interrupted run;
2. captures the applicable saved ruleset snapshot and durably stages automation events;
3. writes alert projections with scripted partial upserts and refreshes them;
4. activates the staged automation events;
5. renews the sync lease; and
6. commits the cursor and watermark.

The cursor is not advanced before durable automation admission. Re-reading an overlapping source alert is safe: partial upserts preserve status, assignment, comments, case links, and other analyst-owned state. Records that cannot be synchronized enter the sync dead-letter queue instead of silently disappearing.

Only a bounded operational field set is projected. Full raw alert details remain in Wazuh and are loaded lazily from the trusted `source_index` and `source_id` recorded on the projection. Before any such read the stored index is re-validated against its own family's exact physical-index matcher, so a stale or tampered projection can never point the server at an arbitrary index. On 5.0 the server first reads the finding and then, only if the finding's `event.index` names a `wazuh-events-v5-*` backing index, the underlying event.

## Automation execution

Automation does not execute inline as an unrecorded side effect of cursor advancement. Admitted events contain the identity of an immutable, content-addressed ruleset snapshot. Separately leased worker lanes claim queue items, evaluate that saved snapshot, and perform idempotent actions. Retries, execution records, and the automation dead-letter queue make interruption and recovery visible.

Rules are prospective: they apply as alerts are ingested after a rule is enabled and do not scan historical alerts retroactively. See [[Automation-Rules]] for trigger, Boolean entity-group, deduplication, cap, and action semantics.

## Cases and evidence

Evidence documents are the authoritative case-to-alert relationship. The `alert_ids` stored on a case is a compatibility preview bounded to 1,000 IDs; `evidence_count` is the exact relationship count. Case detail views paginate the evidence family, so large cases do not require an ever-growing array in one case document.

Creating, correlating, adding, or removing alert evidence updates the relationship store and the bounded case preview. Migration from legacy releases is resumable and validates relationship counts before relying on evidence-first reads.

## Lifecycle, retirement, restore, and purge

The plugin manages rollover without requiring cluster-wide ISM privileges. Approximately every five minutes it checks the current writers for the configured maximum generation age or primary-shard size.

- **Alert retirement:** the selected source generation is write-blocked and detached. Open and in-progress alerts are carried into a deterministic live carry generation. Closed alerts are also carried when an active case or explicit hold requires them; other closed alerts become archive-only. The retired source remains retained.
- **Activity retirement:** the generation is write-blocked and detached without copying old activity into the live family.
- **Case retirement:** active cases and closed cases still inside case retention are carried. Expired closed cases become archived and can be restored or reopened through the workbench.
- **Evidence retirement:** relationship documents are copied insert-only into the current evidence writer before the retired generation is detached, preserving authoritative case membership without overwriting newer relationships.

Restore is insert-only: an archived alert is copied into the current writer only if its ID is absent from the live read alias. An archive is never attached directly to a live alias, and a newer live record is never overwritten. Purge is a separate, privileged, explicit action with reference and retention guards; retirement by itself does not physically delete data.

See [[Lifecycle-Retention-and-RBAC]] and [[Case-Evidence-and-Case-Lifecycle]] for the operator workflow and safeguards.

## Reporting

Operational reports query the live, unarchived projection and case aliases. Resolution metrics use write-time lifecycle fields and composite pagination for exact results; v2.0.2 does not estimate them from a sample. Archived records do not contribute unless they are restored to the live families.

## Browser applications and API

The browser provides the **Workbench** for alerts, cases, automation, settings, lifecycle operations, and optional AI analysis, plus **Reporting** for operational metrics. Browser code uses schema-validated plugin routes under `/api/wazuh_alert_manager`; it does not write indices through Console proxy endpoints.

Administrative settings and destructive lifecycle actions use the current Wazuh/OpenSearch Dashboards security context. Read-only users can inspect permitted data, while changes require the documented administrative privileges. The dashboard service identity's access to native alert indices constrains background ingestion. If users must see different subsets of projected alerts, apply document-level security separately to the plugin-owned operational indices; native-index restrictions are not automatically inherited by the copy.

## Supported builds

Plugin archives are compiled separately because the OpenSearch Dashboards version pin is exact:

| Wazuh | OpenSearch Dashboards |
|---|---|
| 4.12.x | 2.19.1 |
| 4.13.x | 2.19.2 |
| 4.14.x | 2.19.5 |

The plugin is built for every exact OSD version used by the supported Wazuh patches: 2.19.1 through 2.19.6 for Wazuh 4.12.0 through 4.14.10, and 3.6.0 for Wazuh 5.0 (a development target while 5.0 is prerelease). The **source code is identical** across builds, but every ZIP is compiled inside a matching official Wazuh Dashboard source tree and receives that target's exact version stamp (and target Wazuh release) rather than being relabelled after the fact. See [[Installation#supported-versions]] for the patch-level mapping.

Install the matching archive on every OpenSearch Dashboards node that can serve users. Nothing is installed on Wazuh agents, and a manager-only or indexer-only node does not need the dashboard plugin. See [[Installation]].
