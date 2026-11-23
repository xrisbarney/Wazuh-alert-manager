# Wazuh Alert Manager v3.0.0-rc.1

**Pre-release.** v2.0.3 remains the latest stable release and is untouched by
this tag. v3.0.0-rc.1 is published as a GitHub pre-release so the 3.0 line can
be exercised on real stacks; the final 3.0.0 waits for Wazuh 5.0 GA.

One plugin for Wazuh 4.x and Wazuh 5.0. The same source tree, plugin id and
`*-v2-*` storage serve both platform lines; each release artifact is compiled
for one exact OpenSearch Dashboards version and knows which Wazuh line it
targets.

---

## Support matrix

| Wazuh release(s) | OpenSearch Dashboards | Artifact | Status |
|---|---|---|---|
| 4.12.0 | 2.19.1 | `wazuhAlertManager-2.19.1.zip` | supported |
| 4.13.0–4.13.1 | 2.19.2 | `wazuhAlertManager-2.19.2.zip` | supported |
| 4.14.0–4.14.1 | 2.19.3 | `wazuhAlertManager-2.19.3.zip` | supported |
| 4.14.2–4.14.4 | 2.19.4 | `wazuhAlertManager-2.19.4.zip` | supported |
| 4.14.5–4.14.7 | 2.19.5 | `wazuhAlertManager-2.19.5.zip` | supported |
| 4.14.8–4.14.10 | 2.19.6 | `wazuhAlertManager-2.19.6.zip` | supported, browser bench target |
| 5.0.0-rc2 | 3.6.0 | `wazuhAlertManager-3.6.0.zip` | **PREVIEW** (see below) |

The installer selects the artifact from the running dashboard's exact OSD
version; there is nothing to choose by hand.

### Wazuh 5.0.0-rc2 is a preview

The 5.0 build is complete and exercised on a live 5.0.0-rc2 stack, but 5.0
itself is prerelease and its data model can still change. Treat it as a
preview, not a supported production target:

- Rule levels on 5.0 are **labels**, not numbers. They are stored verbatim in
  `severity_label` and `rule.level` stays `null`. Numeric thresholds (rule
  `minLevel`, level filters, SLA tiers) reach 5.0 records through the shared
  severity bands (0–3 low, 4–6 medium, 7–11 high, 12+ critical).
  `sync.minRuleLevel` is ignored on 5.0; use `sync.minSeverityLabel`.
- Rule ids are UUIDs and rule groups are ATT&CK-style tags
  (`attack.t1110`, `attack.t1548`, `wazuh-generic-1`, `wazuh-fim`, …), so an
  automation rule written for 4.x identifiers does not port across lines
  unchanged.
- The 5.0 dashboard's indexer user is read-only on `wazuh-*`, so the installer
  grants it the least-privilege `wazuh_alert_manager_store` role. The 5.0
  indexer also blocks the create-index API cluster-wide; the plugin provisions
  its stores through a temporary plugin-owned template and a bootstrap write.
- Native 5.0 single-finding cases (`wazuh.case.*`) are projected **read-only**
  as a "Native case" chip. There is no import, no write-back and no two-way
  sync with plugin cases.
- `wazuh_cti_local` (the built-in enrichment source that reads
  `wazuh-threatintel-enrichments*`) exists only on 5.0 builds. The CTI
  Explorer deep link is app-level: rc2 documents no record-level parameter.
- `wazuh-states-sca` exists only on 5.0, so the SCA chip carries counts there.
  On 4.x it reads *not indexed on 4.x* and links to Configuration Assessment,
  because 4.x keeps SCA results in the manager database rather than the
  indexer.
- The 5.0 target is re-verified against 5.0 GA before 3.0.0 final.

---

## What is new since v2.0.3

### One plugin, two Wazuh lines

- A 5.0 build reads the `wazuh-findings-v5-*` data streams instead of the 4.x
  `wazuh-alerts-*` indices, normalises each finding into the existing bounded
  canonical record, and follows a finding's `event.index` / `event.doc_id` to
  its underlying `wazuh-events-v5-*` event only when an analyst opens it.
- **Automatic source detection.** Every sync tick resolves the native source
  from the build target and `sync.sourceMode` (`auto` by default), validates
  any `sync.sourceIndexPattern` override against the selected family, and
  probes that the pattern resolves. The result (`ready`, `waiting`, or
  `blocked` with a reason) is persisted as the meta document `source_state`
  and shown in Storage Health. The plugin never falls back to another pattern.
- **Platform wording.** On a 5.0 build the workbench says *Findings* (Finding
  queue, Finding details, Linked findings) where a 4.x build says Alerts.
  Routes, fields and storage are unchanged.
- **Safer hydration.** Before any read of a stored `source_index`, the index is
  re-validated against its family's exact physical-index matcher; the 5.0
  second hop requires a `.ds-wazuh-events-*` backing index.
- **Write guard by name.** Besides the exact plugin prefixes, every native
  Wazuh prefix is refused explicitly: `wazuh-alerts-`, `wazuh-archives-`,
  `wazuh-events-`, `wazuh-findings-`, `.ds-wazuh-`, `wazuh-states-`,
  `wazuh-monitoring-`, `wazuh-statistics-`, `wazuh-case-management-`,
  `wazuh-threatintel-`, `.wazuh-cti-`, `wazuh-active-responses`.
- Sync cursors are per family (4.x `sync_state`, 5.0
  `sync_state:wazuh5_findings`), so a 4.x cursor is never replayed against
  findings after a platform upgrade.

### Trial features

The 3.0 feature work was built in phases. Each heading names the phase so the
implementation plan (`docs/trial-features/PLAN.md`) and this note line up.

**Phase 0 — shared foundations.** `boundedFetch` with no redirects, a response
size cap, an abort timeout covering DNS and a resolved-address check;
`validateEgressUrl` (https only, no localhost / `.local` / IP literals /
private ranges, with the `WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS` escape
hatch); a generic leader `lease`; typed settings documents with encrypted,
masked secrets; CSV/download route helpers with a formula-leader guard; a
read-only `native_read` helper for native indices outside the alert family;
`install.sh` role grants; and an optional `wazuhCore` dependency used only by
the sync job.

**Phase 6 — enrichment and context.**

- Indicator extraction from every record (IP, domain, URL, hash, user,
  process, host) including 4.x `syscheck.*_after` hashes, `data.audit.exe`,
  sibling VirusTotal/Maltiverse verdicts, CDB IOC rule ids, and 5.0
  `wazuh.threat.enrichments[]`; aggregated per case with counts and
  first/last seen.
- Enrichment sources: AbuseIPDB, MISP, generic HTTP, and on 5.0 the built-in
  `wazuh_cti_local`. Results are normalised to
  `{verdict, score, tags, link, summary}`, cached in
  `wazuh-alert-manager-v2-enrichment-cache`, stored on the alert and badged in
  the queue. API keys are encrypted at rest; every remote call goes through
  the egress policy.
- Asset criticality rules (agent name, glob, group, or 4.x label → criticality
  + tags) stamped at projection time, available as a queue badge, a filter and
  the automation `minAssetCriticality` scope.
- Asset context chips read from `wazuh-states-*` (OS, addresses, open ports,
  critical/high CVEs, SCA) with deep links, degrading gracefully to
  "no access" or "not available".
- **Boundary:** automation never performs a live enrichment lookup. Rules read
  only what is already stored, so a slow source can never stall the queue.

**Phase 5 — evidence and reporting output.**

- Streaming `GET /alerts/export.csv` and `GET /cases/export.csv` (the list
  filters, `search_after` paging, 10,000-row cap, formula-guarded cells).
- `GET /cases/{id}/report?format=markdown|html`: summary, disposition and
  closure reason, tasks, timeline, every linked alert, indicators, enrichment
  verdicts, attachments, comments, a server-rendered inline-SVG attack graph
  and a MITRE table. The HTML carries a print stylesheet; "Print / Save as
  PDF" is the browser's own PDF path.
- Case attachments: links and small files in
  `wazuh-alert-manager-v2-attachments` (2 MiB decoded cap, 20 per case,
  allowlisted media types, `Content-Disposition: attachment` + `nosniff` on
  every download).
- Scheduled Markdown summaries (daily/weekly UTC slots) rendered by a
  lease-based scheduler and downloadable from **Settings > Reports**.
- An optional Discover / OpenSearch Reporting bridge: two index patterns and
  two saved searches over the plugin's read aliases.

**Phase 3 — SLA enforcement.**

- Per-band assign and resolve targets under **Settings > SLA**, stored as the
  `sla_policy` meta document.
- `reporting.sla_due_at` / `reporting.assign_due_at` on alerts and `sla_due_at`
  on cases, with a throttled background backfill when the policy changes.
- Due columns with countdown, Breached and Due-soon badges, Breached and
  "Due within 1h" quick filters on both queues.
- A background scanner that stamps breaches once and applies up to 20
  escalation rules (assign to, raise case severity, comment, notify),
  idempotently, under the actor `system:sla`.
- Reporting gained "currently breached" and "escalations in period".

**Phase 2 — response structure inside a case.**

- Tasks on a case (nested, capped at 100) with an open/done chip in the queue.
- **Task lists**: reusable task sets in `wazuh-alert-manager-v2-task-lists`,
  applied from the create-case modal, the case Tasks section, or an automation
  rule's `applyTaskListId` (once per case, only on a case the rule created).
- A merged case **timeline**: alerts, comments, every audit event, task due
  dates, cursor-paginated.
- **Dispositions** (`true_positive`, `false_positive`, `benign`, `duplicate`,
  `undetermined`) with an optional closure reason, recorded on close,
  propagated from a case close to the alerts it closes, filterable on both
  queues, carried in both CSV exports, settable by an automation rule that
  closes, and reported as a donut plus a false-positive-rate-by-rule table.
- Read-only projection of 5.0 `wazuh.case.*` as a "Native case" chip, kept
  current by a per-tick reconciliation pass.

**Phase 1 — notifications.**

- Channel bindings under **Settings > Notifications**: an `indexer_channel`
  references a channel of the indexer's Notifications plugin and is driven
  through an inline Alerting `_execute`; a `webhook` is a direct,
  HMAC-SHA256-signed POST (`x-wam-signature`) from the dashboard server
  through the egress policy.
- Events: `case.created`, `case.assigned`, `case.severity_raised`,
  `case.closed`, `sla.breached`, `sla.escalated`, `rule.action`,
  `report.scheduled`.
- A durable outbox (`wazuh-alert-manager-v2-notifications`) with exponential
  backoff, dead-lettering after 5 attempts, deterministic ids so a replay
  cannot send twice, an administrator retry, and a delivery panel.
- A **notify** action on automation rules, combinable with the other actions;
  a notify-only rule is valid.

**Phases 8, 10 and 11 — interface.** Both flyouts and Settings moved from tab
strips to grouped, collapsible section rails (48px icon rail with tooltips and
count dots; the choice is remembered per browser). The case flyout gained an
**Assets** section with one collapsible row per agent of the linked alerts.
The Overviews became grouped metadata grids without duplicate read-only rows.
The queues fit 1280px and 1920px viewports without horizontal scrolling, the
Created-by column is gone from the Cases queue, and the Reporting header
gained an **Export** menu (HTML, Markdown, CSV, JSON, Print / Save as PDF).

**Phase 9 — live lab.** `lab/agent` (a Vagrant Ubuntu VM enrolled as a Wazuh
agent, with a generator producing real auditd / sshd / sudo / FIM events) and
`lab/misp` (a trimmed MISP deployment) so enrichment and indicators are
exercised against real services rather than fixtures. Documented in
`lab/README.md`, including which generated artifact lands in which indicator
field and which does not.

**Phase 12 — automation on live device data.** `e2e/automation_live.spec.ts`
drives eight rule scenarios (per-alert triage, burst case, co-occurrence,
severity band floor, asset criticality, auto-close, notify-only, and the
draft → preview → enable → edit → rollback → delete lifecycle) entirely
through the UI against real agent events on both Wazuh lines.

Three defects that run found are fixed in this pre-release:

- The rules list shows a **real "Last fired"** and match count. The executor
  writes a per-rule `rule_execution` companion (`matchCount`, `lastFired`,
  `counters`) after each execution batch, and `GET /rules` / `GET /rules/{id}`
  join it onto every rule. A rule that matched but acted on nothing still
  reads "Never".
- An **enabled rule can be edited and saved** from the editor. The preview
  gate now guards the disabled → enabled transition only, matching the server;
  an enabled rule's edit saves as a new revision and the rule stays enabled.
  (Entity-group edits still need the rule disabled.)
- The **Cases queue search box** is a `multi_match` phrase-prefix over the
  case title and description instead of a Lucene `query_string`, so pasting a
  rule-created title (`<rule>: automated incident`) finds the case as typed.

---

## Upgrade notes

- **Existing 4.x installs upgrade in place.** No reindex and no data migration
  is required; the plugin applies additive mapping changes to every retained
  generation on start. The mapping version reaches **25** in this release
  (`source_family`, `severity_label`, SLA due fields, dispositions, tasks and
  applied task lists, `native_case`, `sla.breached_at` / `sla.escalated`,
  `data.audit.exe`, and the enrichment/asset objects are among the additions).
- **New stores are created automatically** on first start:
  `wazuh-alert-manager-v2-` + `task-lists`, `attachments`, `enrichment-cache`,
  `notifications`. `install.sh` needed no new index patterns because the
  existing `wazuh-alert-manager-v2-*` role pattern already covers them.
- **Run the SLA due backfill once after upgrading.** Records projected before
  the due-date fields existed get them only from the backfill. Saving an SLA
  policy whose targets changed schedules it automatically; an administrator
  can also start it with `POST /api/wazuh_alert_manager/sla/backfill` and watch
  `GET /sla/backfill`.
- **New config keys** (all optional, all under the snake_case
  `wazuh_alert_manager` path): `sync.sourceMode`, `sync.minSeverityLabel`,
  `sla.escalation.{enabled,tickSeconds,breachNotifyGraceMinutes}`,
  `notifications.{dashboardUrl,dispatcher.{enabled,tickSeconds}}`,
  `reports.scheduler.{enabled,tickSeconds}`. `sync.sourceIndexPattern` is now
  an optional override that must stay inside the selected family.
- **New environment variable:** `WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS`, a
  comma-separated hostname allowlist, is the only way to reach a private or
  `.local` / `.internal` enrichment source or webhook receiver.
  `WAZUH_ALERT_MANAGER_ENCRYPTION_KEY` is unchanged but now protects the
  enrichment API keys and webhook HMAC secrets as well as the AI provider key.
- **New role grants.** `install.sh` creates and maps
  `wazuh_alert_manager_native_read` (read on `wazuh-states-*` and, on 5.0,
  `wazuh-threatintel-enrichments*`) and `wazuh_alert_manager_notify` (inline
  Alerting execute, Notifications config read and publish, read on the outbox
  index). Both have opt-out flags (`--skip-native-read-role`,
  `--skip-notification-role`) and can be re-applied later with
  `--grant-roles`. Map `wazuh_alert_manager_native_read` to your analyst groups
  yourself — the installer prints the exact call. Analysts who pick delivery
  channels also need the reserved `notifications_read_access`. Without the
  grants the plugin degrades (chips read "no access", deliveries stay queued
  with a 403 in `last_error`) rather than failing.
- **API additions** worth knowing about: `/system/version` reports
  `targetWazuhVersion`, `targetWazuhMajor` and `savedObjectsBridge`;
  `/system/health` gains a `source` block; `GET /alerts/{id}` gains
  `_raw_event`, `_event_available` and `_source_family`.
- **Build tooling:** `scripts/set-target-version.js --wazuh-version`,
  `TARGET_WAZUH_VERSION` / `TARGET_WAZUH_MAJOR` in `common/build_info.ts`, a
  prerelease 5.0 row in `supported-wazuh-versions.json`, and `install.sh`
  recognising OSD 3.6.0.
- **Test tooling:** `e2e/seed_findings_v5.py` and `WAM_BENCH_PROFILE=wazuh5`
  for `benchmark/bench.py` write only to plugin-owned `wazuh-*-v5-wam-*` test
  data streams; `benchmark/reset_v2.py --include-wam-test-streams` and
  `e2e/cleanup_synthetic.py --apply` remove synthetic test data.

---

## Known issues

Open at the time of this pre-release. Each is tracked in
`docs/trial-features/PLAN.md`.

**Automation**

- Duplicate rule **names** are accepted; two drafts can carry the same name.
- An asset criticality rule only affects records projected **after** the rule
  is saved. Nothing already in the queue is re-stamped, so a rule with an
  asset floor sees nothing until the next sync tick.
- On 5.0 the **Assign to** control lists only the security plugin's internal
  users, so a rule cannot assign to an arbitrary name from that control.

**SLA and scheduling**

- Scheduled summaries render in **UTC only** (no DST handling) and a missed
  slot is rendered once at the next tick rather than back-filled.
- An SLA escalation threshold is evaluated against the **current** policy per
  band, not the stored due date, so changing a band target re-evaluates
  existing records immediately.
- Each dashboard replica caches the SLA policy for up to 60 seconds.
- Breach and escalation figures in Reporting read the **live** activity
  generations only; a period reaching past `lifecycle.activityRetentionDays`
  or into retired activity undercounts.

**Reporting and exports**

- Dispositions are counted by close time (`reporting.closed_at`), so alerts
  closed before this release are invisible to the Dispositions report.
- The false-positive table is bounded to the 25 rules with the most closes.
- The Reporting page's previous-window comparison repeats the three SLA
  enforcement queries without reading their result (six searches per load
  instead of three).
- CSV exports cap at 10,000 rows (`x-wam-truncated: true` beyond that); the
  case report caps at 5,000 linked alerts and 500 timeline entries.
- Tasks are not included in the CSV exports.

**Interface and accessibility**

- In the case Indicators table a 64-character sha256 can wrap onto a second
  line at full width.

**Platform**

- Wazuh 5.0.0-rc2 is a preview; see the caveats above.
- On a stock Wazuh 4.14 ruleset the lab generator's outbound destinations and
  URLs never reach `data.dstip` / `data.url` (the auditd decoder leaves the
  encoded `saddr` in `full_log`), so IP enrichment is exercised against the
  agent address and a benign probe only. A manager-side decoder would be
  needed; this is a Wazuh ruleset limitation, not a plugin one.
- Active Response (pushing commands back to agents) is still deliberately not
  shipped.
