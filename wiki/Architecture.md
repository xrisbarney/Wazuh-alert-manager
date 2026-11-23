# Architecture

## Version 2.0.3 overview

Wazuh Alert Manager is an OpenSearch Dashboards New Platform plugin with server and browser components. It reads native Wazuh alert indices (4.x) or finding data streams (5.0), builds a bounded operational projection, and adds alert workflow, cases with tasks and evidence relationships, automation, SLA enforcement, threat-intelligence enrichment and asset context, notifications, lifecycle controls, reporting and exports, and optional AI analysis.

The central safety boundary is strict: native Wazuh storage is read-only, whether it is a 4.x `wazuh-alerts-*` index or a 5.0 `wazuh-events-v5-*` / `wazuh-findings-v5-*` data stream (and its hidden `.ds-` backing indices). Every plugin write is restricted to the exact `wazuh-alert-status-v2-` and `wazuh-alert-manager-v2-` prefixes, and the write guard additionally refuses every native prefix by name.

## One plugin for Wazuh 4.x and 5.0

The same source tree is compiled once per exact OpenSearch Dashboards version. Each build records the Wazuh release it targets, and that decides the only native *source family* the build may read:

| Family | Wazuh | Native source (read-only) | Severity model | Underlying evidence |
|---|---|---|---|---|
| `wazuh4_alerts` | 4.12–4.14 | `wazuh-alerts-*` indices | numeric `rule.level` 0–16 | the alert itself (`full_log`) |
| `wazuh5_findings` | 5.0 | `wazuh-findings-v5-*` data streams | label in `wazuh.rule.level` (`informational`, `low`, `medium`, `high`, `critical`) | the finding's `event.index` / `event.doc_id` in a `wazuh-events-v5-*` stream, read on demand |

A *source adapter* per family builds the sync query and normalizes each hit into the same bounded canonical record (`agent.*`, `rule.*`, `data.*` entities, MITRE, provenance). Cases, evidence, automation, reporting, lifecycle and the UI consume only that canonical record and do not know which family produced it. 5.0 records keep their severity label verbatim in `severity_label` and leave `rule.level` null; nothing converts a label into a number. Numeric thresholds (rule `minLevel`, level filters, SLA tiers) apply to 5.0 records through severity bands (0–3 low, 4–6 medium, 7–11 high, 12+ critical), the same bands the UI has always badged.

On Wazuh 5.0 a finding may carry the native Case Management fields (`wazuh.case.*`). The 5.0 adapter copies a bounded allowlist of them (`id` - reserved, rc2 writes none - `status`, `severity`, `priority`, `tlp`, `title`, up to 20 `tags`, `updated_at`; every value a bounded string, unknown keys dropped) onto the canonical record as `native_case`, and the flyout and queue show it as a read-only "Native case" chip with a link to the Wazuh Cases app (`/app/case-management`, cases list; the app has no per-case route). The projection is re-derived on every sync, and because an edit in the Wazuh Cases app is a partial update that leaves the finding's `@timestamp` (and so the sync window) untouched, every completed 5.0 tick also runs a bounded reconciliation pass (`server/lib/native_case_reconcile.ts`): it searches the findings family for `wazuh.case.updated_at`/`created_at` since its own watermark (meta doc `native_case_reconcile:wazuh5_findings`, 500 findings per tick with checkpoint-and-continue) and applies only `native_case` as a partial update to the already-synced alert record, so an edit made in Wazuh flows through within a tick or two. `native_case` is deliberately not a plugin-owned field. It is **never written back**: the plugin has no write path to findings, and a native case is never a plugin case (`case_id` stays the plugin's own link). 4.x records always carry `native_case: null` and a 4.x build renders no native-case element at all. (The projection was built against the 5.0.0-rc2 dashboard sources while the 5.0 stack was stopped; the end-of-phase 5.0 pass re-checks the live field set and the Cases route.)

Source detection runs every sync tick: `sync.sourceMode` (`auto`, the default, or an explicit family that must be eligible for the build) selects the family; an optional `sync.sourceIndexPattern` override must stay inside it; a read-only probe confirms the pattern resolves to the expected indices or data streams with a mapped `@timestamp`. The outcome (`ready`, `waiting` for a not-yet-created source, or `blocked` with the reason) is recorded in the meta index and shown in Storage Health. The plugin never falls back to another pattern. Sync cursors are kept per family, so a 4.x cursor is never replayed against 5.0 findings after a platform upgrade.

## What we reuse from Wazuh

A deliberate rule runs through the 3.0 feature set: **where Wazuh or the bundled OpenSearch plugins already ship a capability, use it rather than rebuilding it**; build only what genuinely has no native equivalent. The decisions below were taken against a live Wazuh 4.14.10 stack and the Wazuh 5.0.0-rc2 sources (`docs/trial-features/REUSE-STUDY.md` in the repository records the evidence per decision).

| Need | What Wazuh 4.14 ships | What Wazuh 5.0 ships | What this plugin does |
|---|---|---|---|
| Delivery channels (Slack, Teams, webhook, email, SNS) | The indexer's **Notifications** plugin has channels but no "send" REST API | The same (its OpenSearch fork predates the send API); four disabled placeholder channels; private hosts denied by default | **Reuse the channels.** The dispatcher delivers through an inline Alerting `_execute` whose action targets the channel. The plugin's own outbox, retries and dead letters stay, because Alerting monitors cannot provide them. A direct HMAC-signed webhook is kept for signed, private-LAN or sub-minute receivers. |
| Email | Notifications `smtp_account` + email channel | The same | **Reuse.** There is no SMTP client in the plugin. |
| Threat-intel lookups | Nothing native (the VirusTotal/Maltiverse integrators write *sibling* alerts; CDB IOC lists change the rule id) | Content Manager syncs the CTI catalog into `wazuh-threatintel-enrichments*`; the engine stamps `wazuh.threat.enrichments[]` on findings; CTI Explorer reads that index locally | **Ingest** every verdict that already exists (4.x sibling alerts and CDB rule ids, 5.0 engine enrichments) and add a built-in `wazuh_cti_local` source that queries the local index on 5.0. **Build** only the cached on-demand lookups (AbuseIPDB, MISP, generic HTTP) and the per-case indicator aggregation, which nothing native does. The Wazuh CTI API is never called. |
| GeoIP | The indexer pipeline's `GeoLocation.*` (2019 database, last IP wins) | Engine ECS `<entity>.geo.*` / `.as.*` | **Ingest as a hint**, labelled with the database caveat. No lookup is built. |
| Asset context | `agent.{id,name,ip}` on alerts; groups only through the server API; `wazuh-states-inventory-*` and `wazuh-states-vulnerabilities-*` | `wazuh.agent.groups` on every finding; `wazuh-states-*` including SCA | **Ingest** groups (natively on 5.0, through the optional `wazuhCore` API client on 4.x) and read the state indices for the asset chips, with deep links into IT Hygiene, Vulnerability Detection and (4.x) Configuration Assessment. **Build** only the criticality matcher. |
| CSV export / scheduled reports | OpenSearch Reporting: saved-search CSV works but needs `reports_full_access`, corrupts under concurrency, and its scheduler delivers nothing | The fork emails a link to an unrendered instance | **Build** the plugin's own CSV routes and a small scheduler that delivers Markdown summaries through the channels above. Optionally provision index patterns and saved searches so Discover and Reporting also work on the plugin's indices. |
| PDF | Module PDFs (a private pdfmake build); Reporting dashboard PDFs rendered browser-side | Module PDFs removed | **Build** printable HTML and Markdown. "PDF" is the browser's own print path; no PDF library is bundled. |
| Case management | None | `wazuh.case.*` on a single finding (title, description, tags, status, severity, priority, TLP, comments); no id, grouping, assignee, tasks, timeline, attachments or SLA, and no shipped write role | **Build** the plugin's cases (they are the product). The 5.0 fields are projected **read-only** onto the record and never written back. |
| SLA breach detection | Alerting query/bucket monitors can detect, but degrade silently above 50 matches, need analyst role mappings, and cannot reassign or raise severity | The same | **Build** the scanner. |
| Scheduling / leader election | job-scheduler is a Java SPI; its REST lock API is undocumented for the dashboard user | The same | **Build** a small lease on the plugin's meta index. |
| Active response | Integrator scripts | The Incident Response app and `wazuh-active-responses` | **Out of scope** — see [[Security Model]]. |

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
| `wazuh-alert-manager-v2-attachments` | Case attachments: links and small files (2 MiB decoded cap, allowlisted media types, base64 body stored but not indexed). |
| `wazuh-alert-manager-v2-task-lists` | Reusable case task sets ("task lists") applied to a case manually or by an automation rule. |
| `wazuh-alert-manager-v2-enrichment-cache` | Cached threat-intelligence verdicts, document id = `sha256(source:type:value)`, with an `expires_at`. |
| `wazuh-alert-manager-v2-notifications` | Delivery outbox: one document per (event, channel) with attempts, backoff, claim and dead-letter state. |

The meta index also holds the plugin's settings documents, each written through `plugin_settings.ts` with its secret fields encrypted and masked on read: `ai_settings`, `enrichment_settings`, `asset_settings`, `sla_policy`, `notification_settings`, `report_schedules` (plus `report_run:<id>` for each schedule's last run), `source_state`, `saved_objects_bridge`, the sync cursors and the leases.

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

Operational reports query the live, unarchived projection and case aliases. Resolution metrics use write-time lifecycle fields and composite pagination for exact results; nothing is estimated from a sample. Archived records do not contribute unless they are restored to the live families. The same collector feeds the Reporting page, the export routes (HTML, Markdown, CSV, JSON) and the scheduled Markdown summaries, so a page and a summary never disagree. See [[Reporting]].

## Background jobs

Besides the sync job and the automation worker lanes, four lease-based jobs run on exactly one dashboard replica at a time (each takes its lease from `wazuh-alert-manager-v2-meta` through the generic `lease.ts`, renews it as it works, and stops the pass when a renewal is refused):

| Job | Lease | Tick | What it does |
|---|---|---|---|
| SLA breach and escalation scanner | `sla_escalation` | `sla.escalation.tickSeconds`, default 60 | Stamps a breach once per overdue alert or case and applies the policy's escalation rules idempotently. |
| SLA due backfill | `sla-due-backfill` | on demand | Recomputes due timestamps as a throttled `update_by_query` task after a policy change. |
| Notification dispatcher | `notification_dispatcher` | `notifications.dispatcher.tickSeconds`, default 5 | Claims due outbox entries and delivers them through the bound channel, with backoff and dead-lettering. |
| Report scheduler | `report_scheduler` | `reports.scheduler.tickSeconds`, default 60 | Renders each schedule's UTC slot once and stores the Markdown as `report_run:<id>`. |

Every one of them is optional (`enabled: false` in the plugin config stops it) and none is required for the workbench to function.

## Browser applications and API

The browser provides the **Workbench** for alerts, cases, automation, settings, lifecycle operations, and optional AI analysis, plus **Reporting** for operational metrics. Browser code uses schema-validated plugin routes under `/api/wazuh_alert_manager`; it does not write indices through Console proxy endpoints.

Administrative settings and destructive lifecycle actions use the current Wazuh/OpenSearch Dashboards security context. Read-only users can inspect permitted data, while changes require the documented administrative privileges. The dashboard service identity's access to native alert indices constrains background ingestion. If users must see different subsets of projected alerts, apply document-level security separately to the plugin-owned operational indices; native-index restrictions are not automatically inherited by the copy.

## Supported builds

Plugin archives are compiled separately because the OpenSearch Dashboards version pin is exact:

| Wazuh | OpenSearch Dashboards |
|---|---|
| 4.12.0 | 2.19.1 |
| 4.13.0–4.13.1 | 2.19.2 |
| 4.14.0–4.14.1 | 2.19.3 |
| 4.14.2–4.14.4 | 2.19.4 |
| 4.14.5–4.14.7 | 2.19.5 |
| 4.14.8–4.14.10 | 2.19.6 |
| 5.0.0-rc2 (preview) | 3.6.0 |

The plugin is built for every exact OSD version used by the supported Wazuh patches: 2.19.1 through 2.19.6 for Wazuh 4.12.0 through 4.14.10, and 3.6.0 for Wazuh 5.0.0-rc2 (a preview target while 5.0 is prerelease). The **source code is identical** across builds, but every ZIP is compiled inside a matching official Wazuh Dashboard source tree and receives that target's exact version stamp (and target Wazuh release) rather than being relabelled after the fact. See [[Installation#supported-versions]] for the patch-level mapping.

Install the matching archive on every OpenSearch Dashboards node that can serve users. Nothing is installed on Wazuh agents, and a manager-only or indexer-only node does not need the dashboard plugin. See [[Installation]].
