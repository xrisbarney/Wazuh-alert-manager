# 🚨 wazuhAlertManager

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22093124.svg)](https://doi.org/10.5281/zenodo.22093124)

An OpenSearch Dashboards plugin that turns Wazuh alerts into a small SOC
work desk: status workflow, dispositions, comments, audit history,
cross-alert linking, case management with tasks and reusable task lists,
attachments, SLA targets and escalation, threat-intelligence enrichment and
asset context, ingestion-time automation rules, notifications through your
existing channels, CSV/HTML/Markdown/JSON exports and scheduled summaries,
and optional AI-assisted analysis via OpenAI, DeepSeek, Gemini or Claude.

Release artifacts are built against official Wazuh Dashboard source for
**Wazuh 4.12.0–4.14.10**; the full browser bench runs on **Wazuh 4.14.10 / OSD
2.19.6**. **Wazuh 5.0.0-rc2** (OSD 3.6.0) is a **preview** target: the same
plugin reads 5.0's `wazuh-findings-v5-*` data streams instead of 4.x
`wazuh-alerts-*`, detected automatically per build, and is re-verified when
5.0 is final. See [SUPPORTED_VERSIONS.md](./SUPPORTED_VERSIONS.md) for the
exact version-to-artifact matrix.

The 3.0 line ships first as the pre-release **v3.0.0-rc.1**; **v2.0.3 remains
the latest stable release**. See
[RELEASE_NOTES_v3.0.0.md](./RELEASE_NOTES_v3.0.0.md).

---

## What's new in v3.0

**One plugin for Wazuh 4.x and Wazuh 5.0.** The same source tree, plugin id and
`*-v2-*` storage serve both lines. Each artifact is compiled for one exact
OpenSearch Dashboards version and knows which Wazuh line it targets, so a 4.x
build reads `wazuh-alerts-*` and a 5.0 build reads the `wazuh-findings-v5-*`
data streams. Source detection runs every sync tick and its outcome
(`ready` / `waiting` / `blocked`, with the reason) is shown in Storage Health.
5.0 severity labels are kept verbatim in `severity_label`; nothing invents a
numeric level.

On top of that, 3.0 adds:

- **Threat-intelligence enrichment and asset context.** Indicators (IPs,
  domains, URLs, hashes, users, processes, hosts) are extracted from every
  record, aggregated per case, and can be looked up against AbuseIPDB, MISP, a
  generic HTTP source, or — on Wazuh 5.0 — the local CTI catalog
  (`wazuh_cti_local`, reading `wazuh-threatintel-enrichments*`). Verdicts are
  cached, badged in the queue and stored on the alert. Asset criticality rules
  (name / glob / group / 4.x label) stamp `asset.criticality` at sync time, and
  the flyouts show OS, addresses, open ports, vulnerability and SCA chips read
  from `wazuh-states-*` with deep links to IT Hygiene, Vulnerability Detection
  and (4.x) Configuration Assessment.
- **Case structure.** Tasks on a case, reusable **task lists** applied manually
  or by an automation rule, a merged **timeline** (alerts, comments, audit
  events, task due dates), **attachments** (links and small files, 2 MiB cap,
  allowlisted media types) and **dispositions** (true positive / false positive
  / benign / duplicate / undetermined) with a closure reason, propagated from a
  case close onto the alerts it closes. On Wazuh 5.0 a finding's native
  `wazuh.case.*` fields are projected read-only as a "Native case" chip; the
  plugin never writes them back.
- **SLA enforcement.** Per-band assign/resolve targets editable under
  **Settings > SLA**, due timestamps on every alert and case, Due columns with
  Breached / Due-soon badges and quick filters, a background scanner that
  stamps breaches and applies escalation rules (assign, raise severity,
  comment, notify), and "currently breached" / "escalations in period" figures
  in Reporting.
- **Output.** Streaming `GET /alerts/export.csv` and `/cases/export.csv`,
  a per-case report (Markdown or self-contained HTML with a print stylesheet —
  the Print / Save as PDF path), a Reporting export menu (HTML, Markdown, CSV,
  JSON, Print / Save as PDF), scheduled Markdown summaries delivered through
  the notification channels, and optional Discover / OpenSearch Reporting
  index patterns and saved searches.
- **Notifications.** Deliver through the indexer's existing **Notifications**
  channels (Slack, Teams, chime, email, SNS, webhook) via an inline Alerting
  `_execute`, or through a direct HMAC-signed webhook from the dashboard
  server. A durable outbox with backoff, dead letters and an administrator
  retry sits in front of both. Events: `case.created`, `case.assigned`,
  `case.severity_raised`, `case.closed`, `sla.breached`, `sla.escalated`,
  `rule.action`, `report.scheduled`. Automation rules gained a **notify**
  action.
- **UI.** Both flyouts and Settings sit on a collapsible section rail with
  grouped navigation; the case flyout has its own **Assets** section with one
  collapsible row per agent; the Overviews are grouped metadata grids; the
  queues fit a 1280px viewport without horizontal scrolling.

---

## What's new in v2.0

The original plugin (comment tracking, index rollover, audit trail,
dropdown filters, better Lucene handling) is now implemented, plus a fair
bit more:

- **No more manual Dev Tools / cron setup.** The plugin provisions its own
  indices and syncs alerts from `wazuh-alerts-*` on a background timer
  inside the dashboard server process - no ingest pipeline, no external
  cron job, no credentials in a shell script. (The old approach is still
  documented at the bottom as a legacy/optional alternative.)
- **Comments** on both alerts and cases.
- **Full audit history** per alert/case: who changed what, and when -
  status changes, assignment changes, case links, comments, AI analysis
  runs, all as one timeline.
- **Dropdown filtering** by status, rule level range, rule ID, agent,
  alert type (`rule.groups`), and assignee - the free-text Lucene box is
  now an optional "advanced" fallback, not the primary way to filter.
- **Multi-select bulk actions**: select alerts in the table to bulk-close,
  bulk-set status, bulk-assign, or create a case from the selection in
  one action.
- **Assignment**: assign an alert or a case to a person, singly or in
  bulk. The picker prefers real dashboard users (via the OpenSearch
  Security plugin's internal users API) but always allows free text, for
  clusters without that API or assignees who aren't dashboard logins.
- **Case management**: a case links any number of alerts together, has
  its own status/severity/assignee/comments/history, and alerts show a
  link back to the case they belong to. Alerts can be added to an
  existing case from either direction: from an alert (a case picker in
  its Overview tab, searchable by title or a pasted case ID) or from a
  case (a search-and-select picker in its "Linked Alerts" tab, by rule
  description, agent, rule ID, or a pasted alert ID) - not just at case
  creation time. Cases also have their own **AI analysis** (summarizes the
  whole case - title, all linked alerts, all comments - not just one
  alert) and a **time-window filter** ("created in the last 24h/7d/...")
  alongside status/assignee/search in the Cases tab.
- **Cross-alert linking**: relate alerts to each other directly (not just
  through a case) from the alert flyout's "Related alerts" section.
- **Full-screen flyouts**: the alert and case detail panels have an
  expand toggle in the header (top-right) to go full width when you need
  the room - e.g. reading the raw JSON or a long AI analysis.
- **Reporting**: a "Reports" tab computes mean time to assign, mean time
  to resolve, and SLA compliance (by a severity-based target) for a
  selected time period, with a per-severity breakdown table - plus a
  cases section (created/open/closed counts, severity breakdown, mean
  time to close) for the same period. See **Reporting & SLA metrics**
  below for the methodology.
- **AI-assisted analysis**: configure an API key for OpenAI, DeepSeek,
  Gemini, or Anthropic Claude under the "AI Settings" tab, then generate
  a summary/severity assessment/next-steps writeup from an alert's
  "AI Analysis" tab. The key is encrypted at rest (AES-256-GCM) with a
  key you supply via an environment variable, and is never sent to the
  browser - see **AI analysis integration** below before using this.
- **A nav icon**: the plugin has its own logo in the side navigation
  instead of the default generic icon (`public/assets/logo.svg`).
- **Attack Path (first pass)**: a case's "Attack Path" tab extracts the
  hosts/accounts/MITRE ATT&CK techniques involved across its linked
  alerts, groups them into kill-chain phases, and lays them out as a
  chronological timeline - turning a pile of individually-unremarkable
  alerts into a readable incident narrative. See **Attack path analysis**
  below for how it works and **Coming soon** for where this is headed
  (interactive graph view, cross-case path-finding).
- Real server-side routes with request validation, replacing the
  original's direct browser -> `/api/console/proxy` calls (see
  **Security note** below).

---

## Architecture

```
common/                 shared TypeScript types + constants (index names, statuses, API root)
server/
  config.ts             plugin config schema (sync + lifecycle + migration defaults)
  plugin.ts             provisions indices, runs legacy migration, starts sync + lifecycle jobs
  lib/
    constants.ts          (in common/) single source of truth for index/alias names
    mappings.ts           explicit v2 index mappings this plugin owns
    provision.ts          idempotent "create index + alias if missing"
    sync_job.ts           copies new native alerts/findings into the v2 alert store on a timer
    source_profile.ts     the two read-only native families: 4.x wazuh-alerts-*, 5.0 wazuh-findings-v5-*
    source_runtime.ts     per-tick source detection (build target + config) -> ready / waiting / blocked
    adapters/             wazuh4_alert_adapter (v2 behaviour), wazuh5_finding_adapter (WCS -> canonical)
    sync_lock.ts          leader-lock doc so N dashboard replicas sync safely
    lifecycle.ts          plugin-managed rollover + retention marking
    alert_retirement.ts   case-safe carry-forward retirement, guarded restore, purge
    activity_retirement.ts  append-only activity generation retire/purge
    legacy_migration.ts   v1 -> v2 migration (v1 stores are read-only inputs)
    index_namespace.ts    fail-closed write-target validation (v2 prefixes only)
    index_resolution.ts   resolve a doc's physical index behind a read alias
    operational_projection.ts  compact projection of a Wazuh alert
    authorization.ts      RBAC: all_access / index_management_full_access gates
    identity.ts           actor identity from the OpenSearch Security plugin only
    history.ts            shared painless snippet for audit-trail append
    opensearch.ts         best-effort "who is the logged in user" lookup
    ai_providers.ts       one function per AI provider's HTTP API
    egress/               boundedFetch + validateEgressUrl; AI egress allowlist projection
                          (raw _source cannot cross the AI boundary)
    native_read.ts        read-only search of native indices outside the alert family
    wazuh_api.ts          optional wazuhCore server-API client (4.x agent groups)
    lease.ts              generic leader lease for the background jobs
    plugin_settings.ts    typed settings docs in the meta index, secrets encrypted + masked
    http_download.ts      downloadResponse + CSV escaping/streaming helpers
    attack_graph.ts       entity/kill-chain/hop extraction from a case's alerts
    case_report.ts        per-case Markdown/HTML report; attack_graph_svg.ts renders it
    case_timeline.ts      merged case timeline (alerts, comments, audit, task dues)
    case_tasks.ts         pure task-list operations; task_lists.ts the reusable sets
    enrichment/           threat-intel sources, cache, providers
    assets/               asset criticality matcher; asset_context.ts the state chips
    sla/                  policy, due backfill, escalation scanner
    notifications/        settings, outbox, dispatcher, transports, emitters, rule action
    report_schedules/     metrics, Markdown/HTML/CSV/JSON render, scheduler
  routes/
    alerts.ts             search/count/bulk-update/get/related/suggested/precedent/export.csv
    comments.ts           comments + audit on an alert or a case
    cases.ts              case CRUD + linking alerts + timeline + report + export.csv
    case_tasks.ts         tasks on a case; task_lists.ts reusable task lists + apply
    attachments.ts        case attachments (links + small files)
    evidence.ts           case-alert relationships, holds
    attack_path.ts        attack graph / kill chain for a case
    indicators.ts         per-case indicator aggregation
    enrichment.ts         enrichment settings, lookup, per-source test
    assets.ts             asset context chips from native wazuh-states-*
    sla.ts                SLA policy, due backfill, escalation status
    notifications.ts      channel settings, outbox, retry, dispatcher status
    filters.ts            dropdown option aggregations
    ai.ts                 AI settings + on-demand analysis generation
    users.ts              real dashboard users, for the assignee picker
    reports.ts            SLA / MTTA / MTTR metrics, schedules, export
    rules.ts              automation (correlation) rules CRUD + preview
    system.ts             storage health, lifecycle settings, rollover, retirement, restore, purge
public/
  assets/logo.svg         side-nav icon
  services/api.ts         typed HTTP client for all of the above
  components/             one component per concern (filter bar, bulk actions,
                          alert/case flyouts, comments thread, AI panels,
                          assignee/case pickers, alert multi-picker, reports,
                          attack path view, storage/lifecycle workbench, ...)
```

### Data model

The plugin owns a set of **v2** indices, all auto-created (and aliased) on first
server start. It never writes to Wazuh's native storage — 4.x `wazuh-alerts-*`
indices and 5.0 `wazuh-events-v5-*` / `wazuh-findings-v5-*` data streams are
read-only evidence sources. A build compiled for Wazuh 4.x reads alerts; a
build compiled for Wazuh 5.0 reads findings and follows a finding's
`event.index` / `event.doc_id` to its underlying event only when an analyst
opens it. Both produce the same bounded canonical record (plus
`source_family`, and for 5.0 the verbatim `severity_label`, since 5.0 rule
levels are labels rather than the 4.x 0–16 integers).

**Alias-backed families** (read alias, write alias, numeric rollover generations
starting at `-000001`):

| Family | Purpose |
|---|---|
| `wazuh-alert-status-v2-{read,write}` | Aliases over numbered alert generations. Each document is a bounded operational projection plus workflow state (status, assignee, disposition, SLA due dates, enrichment, asset, native-case projection). |
| `wazuh-alert-manager-v2-activity-{read,write}` | Aliases over numbered comment/audit generations, keyed by `alert_id` or `case_id`. |
| `wazuh-alert-manager-v2-cases-{read,write}` | Aliases over numbered case generations. Cases keep an exact `evidence_count`, nested `tasks[]`, applied task lists and bounded alert-ID/history previews. |
| `wazuh-alert-manager-v2-evidence-{read,write}` | Aliases over the authoritative, paginated case-alert relationship family, including provenance, holds, lifecycle state, compact snapshots and trusted archive locations. |

**Fixed single indices** (one stable name, no rollover; the documents are still
mutable):

| Index | Purpose |
|---|---|
| `wazuh-alert-manager-v2-meta` | Internal state and settings documents: sync cursor(s), leases/leader lock, lifecycle settings, AI settings, enrichment sources, asset rules, SLA policy, notification channels, report schedules and their last runs, source state, retirement records. |
| `wazuh-alert-manager-v2-rules` | Automation rule definitions and revisions. |
| `wazuh-alert-manager-v2-task-lists` | Reusable case task sets ("task lists") applied to a case manually or by a rule. |
| `wazuh-alert-manager-v2-attachments` | Case attachments: links and small files (2 MiB decoded cap, allowlisted media types, base64 body stored but not indexed). |
| `wazuh-alert-manager-v2-enrichment-cache` | Cached threat-intel verdicts, keyed by `sha256(source:type:value)` with an `expires_at`. |
| `wazuh-alert-manager-v2-notifications` | Delivery outbox: one document per (event, channel) with attempts, backoff and dead-letter state. |
| `wazuh-alert-manager-v2-migration` | Legacy v1 -> v2 migration progress/checkpoint. |
| `wazuh-alert-manager-v2-sync-dlq` | Dead-letter queue for alerts that fail to sync. |
| `wazuh-alert-manager-v2-automation-{queue,executions,dlq}` | Durable ingestion-time work, idempotent execution records and recoverable failures. |

The authoritative list is `MANAGED_INDICES` in `server/lib/provision.ts`; the
names themselves live in `common/constants.ts`.

Legacy v1 indices (`wazuh-alert-status`, `wazuh-alert-manager-comments`,
`wazuh-alert-manager-cases`, `wazuh-alert-manager-meta`, `wazuh-alert-manager-rules`)
are read-only migration inputs and are retained after migration.

Write validation is fail-closed to the exact prefixes `wazuh-alert-status-v2-` and
`wazuh-alert-manager-v2-` — an over-privileged service account cannot turn a
programming mistake into a write against a native Wazuh index.

The background sync job (`server/lib/sync_job.ts`) copies new alerts using a
**scripted partial-update upsert**, not a full-document reindex — so a status
change, comment, or case link you've already recorded on an alert is never
clobbered if that alert's timestamp falls into a later sync window.

### Rollover, retention, retirement, and restore

`server/lib/lifecycle.ts` rolls over generations (plugin-managed, so a stock
Wazuh install needs no cluster-wide ISM policy privileges). Retention only marks
older generations "due" for review — it never deletes automatically. An
administrator then retires a generation, which carries forward every
`open`/`in_progress` alert. A closed alert is carried only while it belongs to an
active case or has an evidence hold; closed-case evidence otherwise remains
represented by its evidence record and archive location. Retirement atomically
swaps the read alias and retains the write-blocked source. A guarded, idempotent restore copies only IDs
missing from the live store back into the current writer — it never overwrites a
newer live record. Purge is the sole permanent deletion and always requires a
separate explicit confirmation.

### Security note on the original design

The original plugin called `/api/console/proxy` directly from the
browser with a client-controlled `path` and request body - any
authenticated dashboard user (or an XSS payload) could use that to run
arbitrary read/write queries against *any* index, not just
`wazuh-alert-status`. This version replaces every one of those calls with
a dedicated, schema-validated server route that hard-codes which index it
touches and what shape of request it accepts.

---

## Installation

### One-line installer (recommended)

`install.sh` detects the installed Wazuh Dashboard / OpenSearch Dashboards
version, picks the matching artifact, verifies its SHA-256 (and, when
configured, a minisign signature), backs up the current plugin, and swaps it
in with automatic rollback on failure. On Wazuh 5.0 it also grants the
dashboard's indexer user a least-privilege OpenSearch Security role
(`wazuh_alert_manager_store`, write access to the two exact plugin prefixes
only), because 5.0 ships that user read-only on `wazuh-*`; on a distributed
install without local admin credentials it prints the role to create instead.
It never modifies `wazuh-alerts-*` or 5.0 events/findings, never
deletes plugin data on upgrade, and fails closed on an unsupported dashboard
version.

```bash
# Latest compatible release
curl -fsSL https://github.com/xrisbarney/Wazuh-alert-manager/releases/latest/download/install.sh | sudo bash

# Pinned release (recommended)
curl -fsSL https://github.com/xrisbarney/Wazuh-alert-manager/releases/latest/download/install.sh | sudo bash -s -- --version 2.0.3

# Supply-chain-safe: download and verify the installer first
curl -fsSLO https://github.com/xrisbarney/Wazuh-alert-manager/releases/download/v2.0.3/install.sh
curl -fsSLO https://github.com/xrisbarney/Wazuh-alert-manager/releases/download/v2.0.3/install.sh.sha256
sha256sum -c install.sh.sha256
sudo bash install.sh --version 2.0.3

# Pre-release (v3.0.0-rc.1). `latest` stays on the stable 2.0.3 release, so the
# pre-release must be installed with its OWN installer, downloaded from the RC
# tag: the 2.0.3 installer does not know OSD 3.6.0 (the Wazuh 5.0 preview) and
# predates the RC's new role grants.
curl -fsSLO https://github.com/xrisbarney/Wazuh-alert-manager/releases/download/v3.0.0-rc.1/install.sh
curl -fsSLO https://github.com/xrisbarney/Wazuh-alert-manager/releases/download/v3.0.0-rc.1/install.sh.sha256
sha256sum -c install.sh.sha256
sudo bash install.sh --version 3.0.0-rc.1
```

It also handles `--dry-run`, `--no-restart`, `--rollback`,
`--uninstall-plugin` (retains all data), and a separately confirmed
`--remove-data`, which prints exact manual indexer cleanup instructions instead
of accepting indexer credentials or deleting data itself. Override
`WAM_RELEASE_BASE_URL` only for a private release mirror. See `wiki/Installation.md` for the full reference and the release-side
checksum/signature tooling (`scripts/make-release-artifacts.sh`).

### Manual install (alternative)

1. Install the plugin zip:

   ```bash
   sudo systemctl stop wazuh-dashboard
   sudo /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin remove wazuhAlertManager --allow-root   # if upgrading
   # Use the ZIP mapped to your exact dashboard version in SUPPORTED_VERSIONS.md.
   sudo /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin install file:///path/to/wazuhAlertManager-2.19.6.zip --allow-root
   sudo systemctl start wazuh-dashboard
   ```

2. Open **Wazuh Dashboard → Wazuh Alert Manager**. On first start the
   plugin creates its indices and starts copying alerts automatically -
   there is nothing else to configure. Give it a minute (default sync
   interval is 60s) and alerts will start appearing with `status: open`.

3. (Optional) Configure AI analysis - see **AI analysis integration** below.

### Configuration reference (`wazuh_alert_manager.*`)

Every key below is optional; the plugin runs with no configuration at all.
Overrides go in `opensearch_dashboards.yml` under the **snake_case**
`wazuh_alert_manager` path — see the config-loading note below before relying
on that on a Wazuh-packaged dashboard.

| Key | Default | What it does |
|---|---|---|
| `enabled` | `true` | Turns the whole plugin off. |
| `sync.enabled` | `true` | Runs the background sync job. |
| `sync.intervalSeconds` | `60` (min 15) | Seconds between sync ticks. |
| `sync.sourceMode` | `auto` | `auto` \| `wazuh4_alerts` \| `wazuh5_findings`. An explicit value must still be eligible for the build. |
| `sync.sourceIndexPattern` | the family default | Optional override; must stay inside the selected family, otherwise sync stops safely and says so in Storage Health. |
| `sync.initialLookbackMinutes` | `10` | How far back the first tick reads. |
| `sync.batchSize` | `10000` (100–10000) | Source hits per tick. |
| `sync.minRuleLevel` | unset | **Wazuh 4.x only**: numeric `rule.level` floor applied at the source. |
| `sync.minSeverityLabel` | unset | **Wazuh 5.0 only**: label floor (`informational` … `critical`) applied to `wazuh.rule.level` at the source. |
| `sync.overlapSeconds` | `120` (0–3600) | Replay window; partial upserts make the overlap safe. |
| `lifecycle.enabled` | `true` | Plugin-managed rollover and retention marking. |
| `lifecycle.rolloverAge` / `.rolloverPrimarySize` | `7d` / `20gb` | Rollover thresholds. |
| `lifecycle.operationalRetentionDays` | `90` (min 7) | Alert generations marked due for review. |
| `lifecycle.activityRetentionDays` | `365` (min 30) | Activity generations. |
| `lifecycle.caseRetentionDays` | `365` (min 30) | Case generations. |
| `lifecycle.evidenceRetentionDays` | `730` (min 30) | Evidence generations. |
| `migration.enabled` / `.batchSize` / `.shadowWriteDays` | `true` / `1000` / `14` | Legacy v1 → v2 migration. |
| `sla.escalation.enabled` | `true` | The SLA breach/escalation scanner. |
| `sla.escalation.tickSeconds` | `60` (15–3600) | Scanner tick. |
| `sla.escalation.breachNotifyGraceMinutes` | `1440` (0 = notify on every breach) | A record overdue longer than this is stamped but sends no `sla.breached` notification, so enabling SLA on a backlog does not flood channels. |
| `notifications.dashboardUrl` | unset | Public base URL (http/https, include `server.basePath`) used for deep links in notification payloads; unset means app-relative links. |
| `notifications.dispatcher.enabled` | `true` | The outbox dispatcher. |
| `notifications.dispatcher.tickSeconds` | `5` (1–300) | Dispatcher tick. |
| `reports.scheduler.enabled` | `true` | The scheduled-summary renderer. |
| `reports.scheduler.tickSeconds` | `60` (15–3600) | Scheduler tick. |

The SLA policy, enrichment sources, asset criticality rules, notification
channels and report schedules are **not** yml settings: they are edited under
**Settings** and stored as documents in the plugin's meta index.

Two environment variables on the dashboard service complete the picture:

- `WAZUH_ALERT_MANAGER_ENCRYPTION_KEY` — required before any secret (AI
  provider key, enrichment API key, webhook HMAC secret) can be saved. See
  **AI analysis integration** below.
- `WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS` — a comma-separated hostname
  allowlist. By default outbound requests (enrichment lookups, direct
  webhooks) must be https to a public name; a host named here may be a
  private or `.local`/`.internal` receiver. `localhost` and IP literals are
  never accepted. This is the supported way to reach an on-premises webhook
  receiver or a lab MISP.

### Configuring the sync job

Defaults live in `server/config.ts` (`sync.enabled`, `sync.intervalSeconds`,
`sync.sourceMode`, `sync.sourceIndexPattern`, `sync.initialLookbackMinutes`,
`sync.batchSize`, `sync.minRuleLevel`). `sync.sourceMode` is `auto` by
default: a Wazuh 4.x build reads `wazuh-alerts-*`, a Wazuh 5.0 build reads
`wazuh-findings-v5-*`; an explicit `wazuh4_alerts` / `wazuh5_findings` value
must still be eligible for the build. `sync.sourceIndexPattern` is an
optional override that must stay inside the selected family (anything else
stops sync safely and is explained in Storage Health). `sync.minRuleLevel`
is a 4.x numeric floor applied at the source; its 5.0 counterpart is
`sync.minSeverityLabel` (`informational` | `low` | `medium` | `high` |
`critical`), applied to `wazuh.rule.level` at the source. Each is ignored by
the other line. These are meant to be overridable via
`opensearch_dashboards.yml` (e.g. `wazuh_alert_manager.sync.intervalSeconds: 30`
— the path is the snake_cased plugin id)
the standard OSD way - **but see the config-loading caveat below** before
relying on that on a Wazuh-packaged dashboard. If you hit it, change the
default in `server/config.ts` and rebuild instead.

### Role grants

The core workbench needs nothing beyond what a stock Wazuh install already
gives the dashboard user on Wazuh 4.x. Three optional grants unlock the 3.0
features that touch storage or indexer plugins the base plugin never used.
`install.sh` applies them when it has indexer admin credentials (on Wazuh 5.0
it reads `/etc/wazuh-indexer/export/credentials.env`; on 4.x pass
`--indexer-admin-password` or set `WAZUH_INDEXER_ADMIN_PASSWORD`), prints a
banner listing which were applied, and can re-apply them later with
`--grant-roles`:

| Role | Who needs it | What it allows | Opt out |
|---|---|---|---|
| `wazuh_alert_manager_store` | the dashboard's indexer user, **Wazuh 5.0 only** | Write access to the two exact plugin prefixes (5.0 ships that user read-only on `wazuh-*`) plus point-in-time and bulk | `--skip-store-role` |
| `wazuh_alert_manager_native_read` | the dashboard's indexer user **and every analyst** who should see asset chips and local CTI verdicts | Read-only search of `wazuh-states-*` and (5.0) `wazuh-threatintel-enrichments*` | `--skip-native-read-role` |
| `wazuh_alert_manager_notify` | the dashboard's indexer user only | Execute an inline Alerting monitor whose action targets a Notifications channel, read a channel config, publish to it, and read the plugin's outbox index — nothing else | `--skip-notification-role` |

The installer maps `wazuh_alert_manager_native_read` to the dashboard user and
prints the exact `rolesmapping` call for your analyst groups; analysts who pick
delivery channels also need the reserved `notifications_read_access`, which the
installer deliberately does not grant. Without any of these the plugin
degrades rather than fails: asset and enrichment chips read "no access" and the
dispatcher records a 403 as `last_error` and leaves notifications queued.
Every grant is read-only or delivery-only; the plugin still never writes to
native Wazuh storage.

### AI analysis integration

This is security tooling, so provider API keys are never stored in
plaintext. Before you can save one, set an environment variable for the
wazuh-dashboard service (not `opensearch_dashboards.yml` - see the caveat
below for why):

```bash
sudo mkdir -p /etc/systemd/system/wazuh-dashboard.service.d
sudo tee /etc/systemd/system/wazuh-dashboard.service.d/override.conf <<'EOF'
[Service]
Environment=WAZUH_ALERT_MANAGER_ENCRYPTION_KEY=<32+ random characters, e.g. output of `openssl rand -base64 32`>
EOF
sudo systemctl daemon-reload
sudo systemctl restart wazuh-dashboard
```

Then go to **AI Settings**: pick a provider (OpenAI, DeepSeek, Gemini, or
Anthropic Claude), paste the API key, save. The key is encrypted
(AES-256-GCM, key derived from `WAZUH_ALERT_MANAGER_ENCRYPTION_KEY`)
before it's written to `wazuh-alert-manager-meta`, and is decrypted only
in-memory, server-side, for the duration of an analysis request -
`GET .../ai/settings` never returns it, not even in encrypted form.

If you rotate the encryption key, any previously saved provider key
becomes undecryptable and must be re-entered. Treat this environment
variable the same as any other credential (don't log it, don't commit the
systemd drop-in with a real value to source control) - it is the thing
actually protecting the provider key at rest.

#### Config-loading note: the yml key is snake_case, not the plugin id

This plugin declares a normal `server/config.ts` schema, the standard OSD
way to accept `opensearch_dashboards.yml` overrides. The gotcha: OSD
derives a plugin's config path by snake_casing its manifest `id` unless
`opensearch_dashboards.json` sets an explicit `configPath` - for
`"id": "wazuhAlertManager"` that's **`wazuh_alert_manager`**, not
`wazuhAlertManager`. Confirmed by inspecting the dashboard's injected
metadata at runtime
(`"id":"wazuhAlertManager","configPath":"wazuh_alert_manager"`). So any
override goes under the snake_case key:

```yaml
wazuh_alert_manager.sync.intervalSeconds: 30
```

The AI provider API key is deliberately **not** wired through this config
schema at all, snake_case or otherwise - it's delivered via the
`WAZUH_ALERT_MANAGER_ENCRYPTION_KEY` environment variable (see above),
since an env var is the more conventional place for a secret than a YAML
file that might end up copy-pasted or checked into version control by
mistake.

### Reporting & SLA metrics

The **Reports** tab (`server/routes/reports.ts`, `public/components/reports_view.tsx`)
computes, for a selected time period (last 24h/7d/30d/90d):

- **Mean time to assign (MTTA)**: average of (first assignment timestamp -
  alert timestamp), across alerts that were ever assigned in the period.
- **Mean time to resolve (MTTR)**: average of (last "closed" status-change
  timestamp - alert timestamp), across alerts closed in the period.
- **SLA compliance**: each closed alert is checked against a target
  resolution time based on its severity band. These are the **defaults**,
  editable under **Settings > SLA**:

  | Severity | Rule level (4.x) | Assign within | Resolve within |
  |---|---|---|---|
  | Critical | 12+ | 15 minutes | 1 hour |
  | High | 7-11 | 1 hour | 4 hours |
  | Medium | 4-6 | 6 hours | 24 hours |
  | Low | 0-3 | 18 hours | 3 days |

  Compliance % = alerts resolved within their tier's target / all resolved
  alerts with a tracked SLA in the period. The breakdown table shows this
  per severity tier so you can see e.g. "Critical: 8/10 within SLA" rather
  than just one blended number. On Wazuh 5.0 the severity label maps onto
  the same bands (`informational` counts as Low). Alerts and cases also
  carry due timestamps, and a background scanner stamps breaches and applies
  the policy's escalation rules — see `wiki/Reporting.md`.

Both MTTA and MTTR are derived from each alert's own `history` array (the
same audit trail the flyout shows you), not a separate metrics pipeline -
so what you see in Reports is always consistent with what you see on an
individual alert.

### Attack path analysis

A case's **Attack Path** tab (`server/lib/attack_graph.ts`,
`server/routes/attack_path.ts`, `public/components/attack_path_view.tsx`)
turns the case's linked alerts into an entity graph and a kill-chain
narrative, entirely from data already on each alert - no new data
collection, no extra index:

1. **Entity extraction**: each alert contributes a `host` node
   (`agent.name`), zero or more `user` nodes (`data.srcuser`/`data.dstuser`),
   and zero or more `technique` nodes (`rule.mitre.id`/`rule.mitre.technique`,
   when Wazuh's MITRE mapping populated them). Entities that appear in
   multiple alerts are deduplicated and counted.
2. **Edges**: within a single alert, every entity present is connected to
   every other entity present - e.g. an alert with a host, a user, and a
   technique produces three edges. The Attack Graph view renders those
   relationships as an interactive node-link graph and lets the analyst move,
   focus, and inspect nodes without changing the underlying evidence.
3. **Kill-chain phases**: alerts are grouped by MITRE tactic and sorted
   into the standard ATT&CK kill-chain order (Reconnaissance -> ... ->
   Impact), independent of raw timestamp order - so a Discovery-phase
   alert that happened to log after an Impact-phase one still shows up in
   the right conceptual phase.
4. **Chronological hop list**: the same alerts, this time sorted by
   `@timestamp`, one "hop" per alert with its host/users/techniques/tactics
   - this is the actual sequence of what the system saw happen, as
   opposed to the phase grouping's conceptual ordering.

This first pass deliberately does *not* attempt path-finding (see below)
- it's descriptive, not predictive: it shows you what's in the case, not
what path an attacker most likely took between two points you didn't
already link together.

### Building from source

This plugin follows the standard OpenSearch Dashboards plugin layout and
must be built from inside a `wazuh-dashboard` checkout:

```bash
git clone --branch v4.14.10 https://github.com/wazuh/wazuh-dashboard.git
cd wazuh-dashboard
git clone <this repo> plugins/wazuhAlertManager
yarn osd bootstrap
cd plugins/wazuhAlertManager
node scripts/set-target-version.js --osd-version 2.19.6
yarn build
```

Each production build generates a unique artifact ID that is embedded in both
the server plugin and browser bundle. Workbench checks the server's no-store
`/api/wazuh_alert_manager/system/version` response and displays an update banner
if a cached browser bundle does not match the installed server build. The IDs
are also visible under **Settings > About**.

OpenSearch Dashboards may cache a plugin bundle under an unchanged URL for up to
one year. After upgrading the plugin, use the update banner's reload action. If
the old interface remains, perform a hard refresh or open Workbench in a fresh
private/incognito window before validating the deployed UI.

The zip is written to `plugins/wazuhAlertManager/build/`.

To target a different Wazuh/dashboard release, see
[SUPPORTED_VERSIONS.md](./SUPPORTED_VERSIONS.md).

Lifecycle administration, retention safeguards, and the way internal users,
SSO groups, and LDAP/AD groups inherit access are documented in the
[Lifecycle, retention, and Wazuh RBAC wiki page](./wiki/Lifecycle-Retention-and-RBAC.md).

---

## Deploying on Docker / Kubernetes

The instructions above assume a VM/bare-metal `wazuh-dashboard` install
managed by systemd. If your Wazuh dashboard already runs as a container
(docker-compose, a Helm chart, or a raw Deployment manifest), the easiest
path by far is to **not restructure that deployment at all** - just layer
this plugin's zip onto the same base image you already use, push the
result to your registry, and swap the image reference. Everything else
(volumes, networking, the rest of the Wazuh stack) stays exactly as it is.

**Prebuilt images.** Every supported Wazuh release has a ready-made image on
GitHub Container Registry: the official `wazuh/wazuh-dashboard:<version>` with
the matching plugin zip preinstalled and nothing else changed (same entrypoint,
user, volumes and environment variables). Tags are the Wazuh version, plus a
`-wam<plugin version>` tag pinned to the plugin release:

```bash
docker pull ghcr.io/xrisbarney/wazuh-dashboard-alert-manager:4.14.10
docker pull ghcr.io/xrisbarney/wazuh-dashboard-alert-manager:4.14.10-wam2.0.3
```

Swap it in for `wazuh/wazuh-dashboard:4.14.10` in your compose file or
manifest. The images are built by `.github/workflows/publish-images.yml`
from `docker/Dockerfile`, which downloads the zip and its checksum from the
GitHub release and verifies the checksum before installing. The same
Dockerfile builds any supported pair locally:

```bash
docker build -f docker/Dockerfile \
  --build-arg WAZUH_VERSION=4.14.10 --build-arg OSD_VERSION=2.19.6 \
  --build-arg PLUGIN_VERSION=2.0.3 -t wazuh-dashboard-alert-manager:4.14.10 .
```

Or build a custom image yourself:

```dockerfile
FROM wazuh/wazuh-dashboard:4.14.10

COPY wazuhAlertManager-2.19.6.zip /tmp/wazuhAlertManager.zip

RUN /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin install \
      file:///tmp/wazuhAlertManager.zip --allow-root
```

Push it to your registry, then change **only** the image reference in
whatever you already use to run the dashboard - the `image:` line of the
`wazuh-dashboard` service in `docker-compose.yml`, the `image` field in
your Helm `values.yaml`, or the container image in a raw `Deployment`
manifest. Do not otherwise restructure your existing Wazuh
docker-compose/K8s deployment.

- **Encryption key as an env var, not a systemd drop-in - only if you use
  AI analysis.** As on a VM install, this plugin needs no configuration
  to copy alerts and manage cases; the encryption key is only required
  if you plan to use the optional AI analysis feature. If you do, set
  `WAZUH_ALERT_MANAGER_ENCRYPTION_KEY` as a container env var (Docker) or
  via a Kubernetes `Secret` + `envFrom` (K8s), instead of the systemd
  drop-in used in the VM instructions above. **All replicas/pods must be
  given the exact same value.** AI-analysis provider keys are encrypted
  by whichever replica saved them, and must be decryptable by whichever
  replica later serves a request - if the value differs across pods,
  decryption fails as soon as a request is routed to a different pod
  than the one that saved it.
- **Stateless/ephemeral pods are fine.** This plugin keeps no meaningful
  state on local disk - everything it reads and writes lives in
  plugin-owned v2 OpenSearch indices (`wazuh-alert-status-v2-*` and
  `wazuh-alert-manager-v2-*`). No PVC is needed for this plugin specifically, and dashboard
  pods can be scaled, replaced, or rescheduled freely.
- **Multi-replica sync is automatic.** The background sync job uses a
  leader-lock document in the plugin's meta index, so it's safe to scale
  the dashboard to N replicas - only one replica runs the periodic
  `wazuh-alerts-*` sync tick at a time; the others detect the held lock
  and skip it automatically. No configuration is needed for this.
- **Version matching still applies.** The plugin zip you `COPY` into the
  image must still match the Wazuh/OSD version of the base image, per
  [SUPPORTED_VERSIONS.md](./SUPPORTED_VERSIONS.md) - same rule as the VM
  install, it just also determines which zip you reference in the
  Dockerfile.
- **Rolling upgrades**: rebuild the custom image with the matching
  plugin zip before or alongside bumping the base `wazuh-dashboard` image
  tag, then roll it out the way you already roll out image updates.
- **Health/readiness probes** work unchanged - this plugin adds no
  probe requirements and no plugin-specific health endpoint; whatever
  probe you already point at the dashboard's own endpoint is sufficient.

---

## Legacy: external cron sync (optional)

The original manual setup (ingest pipeline + external cron script with
hardcoded credentials) still works if you'd rather sync outside the
dashboard process, and disable the built-in job with
`wazuh_alert_manager.sync.enabled: false` (see the snake_case config note
above). See `wazuh-indexer-config/copy_wazuh_alerts.sh`.
This is no longer the recommended path - it re-copies with a full
`_reindex`, which means any status/comment/case work in progress on an
alert whose timestamp falls into a later run's window gets overwritten.

---

## CI: automated builds and releases

`.github/workflows/build-and-release.yml` builds this plugin against the
*real* wazuh-dashboard source tree for all six OSD versions used by supported
Wazuh patches (2.19.1 through 2.19.6) plus the prerelease Wazuh 5.0.0-rc2 /
OSD 3.6.0 entry - the same process documented
under **Building from source**, not just a relabeled manifest. Building
this way is the point: it catches real API incompatibilities between OSD
releases, not just a version-string mismatch.

- **Manual run**: use the "Run workflow" button on the Actions tab for a
  one-off build of every matrix entry (e.g. to sanity-check a branch)
  without cutting a release. Zips land as downloadable workflow artifacts.
- **Release**: push a tag matching `v*` to build every matrix entry and
  attach the zips to a GitHub Release automatically.

The workflow bakes in every gotcha this session hit doing the same build
by hand: the exact Node version pinned by wazuh-dashboard's own
`.nvmrc`, skipping the cypress/chromedriver/puppeteer postinstall
binary downloads that were observed to hang rather than fail cleanly,
and generous timeout/memory headroom for what is a genuinely heavy
monorepo bootstrap + TypeScript project-reference build on a standard
GitHub-hosted runner.

---

## Coming soon

Roughly in priority order:

- **Cross-case path-finding.** Right now the attack graph is scoped to
  one case's already-linked alerts. The natural next step is Dijkstra/A*
  search (the same well-understood graph-search family used in general
  pathfinding software, e.g. terrain/motion-planning tools like
  [MeshNav3D](https://openresearchsoftware.metajnl.com/articles/10.5334/jors.573))
  over the *entire* alert corpus in a time window, weighted by
  time-proximity and rule severity, to surface a probable lateral-movement
  chain between two entities that were never manually linked into the
  same case. The diffusion/geodesic techniques those tools use (Fast
  Marching, Heat Method) are specific to continuous mesh surfaces and
  don't transfer to a discrete alert graph - only the classical
  graph-search family does.
- **Identity context.** An enrichment source kind asked only for `user`
  indicators, answering an allowlisted projection (display name, title,
  department, manager, account enabled, last sign-in, groups, risk level)
  through the existing cache, secrets and egress policy; Microsoft Entra ID
  and Okta over https, anything else through the generic HTTP source.
- **Disposition-driven detection tuning.** Feeding the false-positive rate per
  rule back into a silencing or tuning workflow. Today the plugin reports the
  rate but never silences a detection itself.

"Suggest related alerts" and scheduled/exported reports, which this section
used to list, are shipped: see the alert flyout's **Related alerts** section and
**Settings > Reports** / the Reporting **Export** menu.

None of the items above are started - this section exists so the project's
direction is visible in the repo itself.

---

## Known limitations

- The sync job's per-cycle batch is capped (`sync.batchSize`, default
  10000). If a single window has more new alerts than that, the excess is
  picked up on the *next* cycle rather than dropped, but a warning is
  logged - lower `intervalSeconds` if you're consistently near the cap.
- User attribution (comments, history, "updated by") is best-effort: it
  reads the OpenSearch Security plugin's `/account` API for the logged in
  user, and falls back to a generic identity on clusters without it.
- The AI provider API key is encrypted at rest with a key you supply via
  the `WAZUH_ALERT_MANAGER_ENCRYPTION_KEY` environment variable (see
  **AI analysis integration**), but it still lives in the plugin's own
  OpenSearch index rather than a dedicated secrets manager (e.g. Vault,
  AWS Secrets Manager) - reasonable for a self-hosted/lab deployment,
  worth revisiting for a hardened multi-tenant one.
- The assignee picker's user list comes from the OpenSearch Security
  plugin's internal users API, which lists *authentication* accounts, not
  necessarily "people who use this dashboard" - on clusters using SSO/LDAP
  instead of internal users, that list will be empty and assignment falls
  back to free text (still fully functional, just not autocompleted).
- Reporting computes MTTA, MTTR, SLA, per-analyst resolution, and leaderboard
  figures exactly for the live, unarchived cohort. Timing and SLA are read from
  bounded write-time fields (materialized when an alert is assigned or closed)
  rather than a sampled document walk, and per-analyst buckets are paginated with
  composite aggregations instead of a top-N. Alerts that predate the write-time
  fields are materialized by a resumable background backfill; until that finishes
  the report shows an explicit "backfill pending" notice instead of a silent
  sample. See `wiki/Reporting.md`.
- The SLA policy (per-band assign and resolve targets, plus escalation rules)
  is edited under **Settings > SLA** and stored in the plugin's meta index;
  `server/lib/sla/policy.ts` only holds the defaults. A changed target applies
  to records closed from then on; existing due dates are recomputed by a
  throttled background backfill that the save schedules, and each dashboard
  replica picks a change up within 60 seconds.
- Scheduled summaries render in **UTC only** (no DST handling) and a missed
  slot is rendered once at the next tick rather than back-filled.
- An automation rule that matched but acted on nothing still shows
  "Last fired: Never": the per-rule execution companion is written only for
  the rules that applied an action in the batch.
- Entity-group edits to an automation rule still need the rule disabled (the
  server answers 409); other edits save as a new revision while it is enabled.
- On Wazuh 5.0, findings carry a severity label, not a number. The 4.x
  source floor `sync.minRuleLevel` is ignored there; use
  `sync.minSeverityLabel` instead. Numeric thresholds elsewhere (rule
  minimum level, level filters, SLA tiers) apply to 5.0 records through
  severity bands (0-3 low, 4-6 medium, 7-11 high, 12+ critical). Wazuh 5.0
  itself is prerelease; the 5.0 target is re-verified when 5.0 is final.

## Disclaimer

This plugin is not officially supported by Wazuh.
