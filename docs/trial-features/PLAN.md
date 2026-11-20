# trial-features implementation plan

Branch `trial-features`, cut from `3.0` on 2026-11-20 (so the Wazuh 5.0
adapter is included). Nothing here is released; the branch may be reconciled
into 3.0.0 later. Features are built in the order the owner chose: **6, 5, 3,
2, 1** (see [RECOMMENDATIONS.md](RECOMMENDATIONS.md)). Multi-tenancy (4) is
dropped.

Check a box only when the step is implemented, unit-tested in the dev image,
and (where it has UI) exercised by a Playwright spec against the Docker stack.

## Wazuh 5.0 overlap check (done 2026-11-20)

Checked `wazuh/wazuh`, `wazuh-dashboard-plugins` and `wazuh-indexer-plugins`
5.0.0 changelogs, the indexer-plugins technical docs and the running 4.14.10
indexer plugin list. What 5.0 ships natively and how this plan avoids it:

| Wazuh 5.0 native | Overlap with this plan | Decision |
|---|---|---|
| Case management app on findings (`wazuh.case.*`: title, description, severity, priority, TLP, status, comments) | Our cases (already shipped in 2.x) | Keep ours: evidence lifecycle, automation, timeline, tasks and export are not in 5.0. Native case fields stay read-only (`NATIVE_WAZUH_PREFIXES`). No TLP/priority duplication. |
| Incident Response app = active response triggers in the dashboard; `wazuh-active-responses` stream | Not in scope (item 7, not selected) | Nothing built. Do not add active response. |
| CTI Explorer: look up domain, URL, IP, hash against Wazuh CTI (subscription) | Feature 6 enrichment lookups | Keep pluggable sources (AbuseIPDB, MISP, generic HTTP) with caching and attachment to the alert/case, which CTI Explorer does not do. On 5.0 builds add an "Open in CTI Explorer" link per indicator instead of a Wazuh CTI connector. |
| Engine ingest-time IOC and GeoIP enrichment on findings | Feature 6 indicator extraction | Surface any `threat.*` / `geo.*` fields already on a 5.0 finding in the indicator list; never re-look-up what the engine already matched. |
| Indexer Reporting plugin (fork of OpenSearch Reporting): scheduled dashboard/saved-search reports, email delivery | Feature 5 scheduled reports | Our metrics are plugin API data, not visualizations, so the Reporting plugin cannot render them. Keep a small scheduler that posts a summary through our own delivery channels. No PDF rendering engine; "PDF" is the printable HTML report. |
| Indexer Notifications plugin (Slack, Teams, email, webhook, SNS channels), present on 4.14 too (`opensearch-notifications`) | Feature 1 | It has no public REST "send" API (only a test endpoint), so it cannot be driven from a dashboard plugin. Build direct webhook + SMTP delivery behind the egress policy. |
| Indexer Alerting plugin: scheduled monitors over indexer data | Feature 3 escalation | Alerting can only notify; it cannot reassign, raise severity or comment. Keep our escalation scanner. |
| AI assistant plugin | Our optional AI analysis | Untouched by this plan. |

## Environment

- [x] `docker/dev/Dockerfile`: bootstrapped `wazuh-dashboard` v4.14.10 tree (Node 18.19.0) for `yarn test` / `yarn build`. Image `wam-dev:4.14.10`.
- [x] Wazuh 4.14.10 single-node Docker stack from `wazuh-docker` (checkout at `C:\Users\Chris\projects\wazuh-docker\single-node`, dashboard on https://localhost:8443, admin / SecretPassword).
- [ ] `scripts/dev/test.sh`, `build.sh`, `e2e-deploy.sh` (build zip in the dev image, bake it into a dashboard image with `docker/Dockerfile`, swap it into the stack).
- [ ] `e2e/seed_alerts.py` runnable from the host against the Docker indexer (`WAM_SEED_URL`), and `full_ui.spec.ts` seeding without Vagrant when `WAM_E2E_SEED=local`.
- [ ] `.env.e2e.local` pointing at the Docker stack.

## Phase 0: shared foundations

Needed by 6 and 1 (HTTP egress), 3 and 5 (periodic jobs), every feature (settings docs).

- [ ] 0.1 `server/lib/egress/http.ts`: `boundedFetch(url, {method, headers, body, timeoutMs, maxResponseBytes})` with no redirects, response-size cap, abort timeout, error typing. `server/lib/egress/url_policy.ts`: `validateEgressUrl(url, {purpose, allowedHosts})` generalising `ai_url_policy.ts` (https only, no localhost / `.local` / IP literals / private ranges, optional allowlist from `WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS`). `ai_url_policy.ts` keeps its behaviour and delegates. Unit tests.
- [ ] 0.2 `server/lib/lease.ts`: generic leader lease on `META_INDEX` (`acquireOrRenewLease(client, leaseId, holder, ttlMs)`, `releaseLease`), same semantics as `sync_lock.ts` but parameterised. Unit tests. Existing sync lock untouched.
- [ ] 0.3 `server/lib/plugin_settings.ts`: typed read/write of settings docs in `META_INDEX` with `assertManagedWriteTarget`, `refresh: 'wait_for'`, secret fields encrypted via `crypto.ts` and masked on read (`hasSecret: true`). Unit tests.
- [ ] 0.4 Route-level helpers: `requirePluginAdmin` reuse; a `downloadResponse(response, {filename, contentType, body})` helper for CSV/Markdown/HTML routes.
- [ ] 0.5 Playwright helpers: `e2e/helpers.ts` (sign-in, `api()` call with `osd-xsrf`, seed via API where possible). Smoke spec passes against the Docker stack.

## Phase 6: enrichment and context

- [ ] 6.1 Indicator extraction. `common/indicators.ts`: `extractIndicators(source)` returns `{type: ip|domain|url|hash|user|process|host, value, field}` from the projected alert (entities, `data.*`, 5.0 `threat.*`/`geo.*` when present). `GET /cases/{id}/indicators` pages all case evidence and aggregates indicators with counts and first/last seen. Alert flyout Overview gets an Indicators block; case flyout gets an Indicators tab with copy-all. Unit tests for extraction; route test.
- [ ] 6.2 Enrichment sources. Settings doc `enrichment_settings` (`sources[]`: id, name, kind `abuseipdb|misp|generic_http`, baseUrl, apiKey (encrypted), enabled, supports, cacheTtlSeconds, timeoutMs). Routes `GET/PUT /enrichment/settings` (admin), `POST /enrichment/lookup {type, value}` (any user) and `POST /enrichment/test/{sourceId}`. Providers normalise to `{source, verdict: malicious|suspicious|clean|unknown, score, tags[], link, raw summary}`. New fixed index `wazuh-alert-manager-v2-enrichment-cache` (doc id = sha256 of source:type:value, `expires_at`). Lookups go through `boundedFetch` + `validateEgressUrl`. Generic HTTP: URL template with `{value}`, header template, JSON pointer paths for verdict/score/tags. Mapping + `MANAGED_INDICES` + install.sh role patterns + `MAPPING_VERSION` bump. Unit tests per provider (mocked fetch) and cache. Settings tab "Enrichment".
- [ ] 6.3 Lookups in the UI. Alert flyout "Enrichment" tab and case Indicators tab: per-indicator Lookup button, cached verdict badges, link out; on 5.0 builds an "Open in CTI Explorer" link. Results stored on the alert record under `enrichment` (plugin-owned field; add to `PLUGIN_OWNED_FIELDS`, mapping) so they survive re-sync and show in the queue as a badge.
- [ ] 6.4 Asset context. Settings doc `asset_settings` (`assets[]`: match by agent name or glob, criticality `low|medium|high|critical`, tags[]). Sync projection stamps `asset.criticality` and `asset.tags` on new alerts (both adapters). Alert queue and flyout show the badge; filter by criticality. Automation Match scope gets `minAssetCriticality`. Settings tab "Assets". Unit tests for matching and the predicate.
- [ ] 6.5 Not built (documented boundary): live enrichment lookups inside automation evaluation. Enrichment results are only usable as a predicate when already cached (`enrichmentVerdict` match condition over the stored `enrichment` field), never fetched by the worker.
- [ ] 6.6 Playwright `e2e/trial_enrichment.spec.ts`: configure a generic HTTP source pointing at a local stub (served by the test), look up an IP from an alert, assert badge; asset criticality badge after seeding.

## Phase 5: evidence and reporting output

- [ ] 5.1 CSV export. `GET /alerts/export.csv` and `GET /cases/export.csv` accept the same filter query as the list routes, stream up to 10,000 rows with `search_after`, `content-disposition: attachment`. Export `buildBoolQuery`/`filterQuerySchema` from `alerts.ts`. "Export CSV" button on both queues (fetch + blob with `osd-xsrf`). Route tests.
- [ ] 5.2 Case report. `GET /cases/{id}/report?format=markdown|html`: summary, disposition and closure reason (phase 2 adds them; render when present), tasks, merged timeline (phase 2 route; until then alerts + comments), all linked alerts (paged evidence, cap 5,000), indicators, comments, attack graph as server-rendered inline SVG from `AttackGraph` data, MITRE table. HTML has a print stylesheet; "Download PDF" opens the HTML and calls `window.print()`. Buttons in the case flyout. Route test with a fixture case.
- [ ] 5.3 Attachments. New fixed index `wazuh-alert-manager-v2-attachments` (`case_id`, `kind: link|file`, `name`, `url`, `content_type`, `size`, `sha256`, `data` base64 with `enabled: false`, `created_by`, `created_at`). Caps: 2 MiB per file, 20 per case, allowlisted content types. Routes list/create/delete/download; audit events `attachment_added/removed`. Attachments tab in the case flyout. Mapping, provisioning, install.sh patterns, tests.
- [ ] 5.4 Scheduled summaries. Settings doc `report_schedules` (`schedules[]`: id, name, cadence `daily|weekly`, dayOfWeek, hourUtc, rangeDays, deliveries[] placeholder until phase 1). Scheduler job on `lease.ts` (1-min tick) renders the reporting metrics to Markdown and stores the last run under `META_INDEX` doc `report_run:{scheduleId}` (downloadable from Settings). Phase 1 adds webhook/email delivery. Settings tab "Reports".
- [ ] 5.5 Playwright `e2e/trial_export.spec.ts`: CSV download has header + rows; case report HTML contains case title and linked alert; attachment link add/remove.

## Phase 3: SLA enforcement

- [ ] 3.1 Configurable targets. Settings doc `sla_policy` (`targets` per severity band in minutes for resolve and assign; defaults = current `REPORTING_SLA_POLICY`). `reporting_fields.ts` reads a cached policy (`getSlaPolicy(client)` with 60-s TTL, invalidated on PUT); all four call sites (reporting, automation close, case close, backfill) use it. `GET/PUT /sla/policy` (admin). Settings tab "SLA". Reports Overview SLA text reads the policy.
- [ ] 3.2 Due timestamps. Alerts: `reporting.sla_due_at` (+ `reporting.assign_due_at`) written on first projection (sync upsert insert branch, both adapters) and on severity-affecting updates; cases: `sla_due_at` from severity at create/update. Mapping + `MAPPING_VERSION` bump + `PLUGIN_OWNED_FIELDS`. Queue columns "Due" with countdown and breach badge (uses `effectiveLevel`), sort by due; "Breached" and "Due within 1h" quick filters. Backfill for existing open alerts in the reporting backfill job.
- [ ] 3.3 Escalation scanner. `server/lib/sla_escalation.ts` job (lease, 60-s tick) over open/in_progress alerts and cases: policies from `sla_policy.escalations[]` (`target alert|case`, `thresholdPercent`, `condition unassigned|untouched|any`, actions: `assignTo`, `raiseSeverity` (cases), `comment`, `notify` (webhook id, wired in phase 1)). Idempotent via `sla.escalated[]` markers on the record and `appendActivityOnce`. Activity actions `sla_escalated`, `sla_breached` (breach recorded once when due passes). Unit tests for selection, thresholds, idempotency.
- [ ] 3.4 Reporting: SLA section gains "currently breached" and "escalations in period" counts.
- [ ] 3.5 Playwright `e2e/trial_sla.spec.ts`: set a 1-minute target, seed an alert, see the breach badge and an `sla_breached` history entry after the scanner tick; escalation auto-assigns.

## Phase 2: response structure inside a case

- [ ] 2.1 Tasks. Case doc gains `tasks[]` (nested: id, title, owner, due_at, done, done_by, done_at, created_by, created_at, order; cap 100) and `task_counts {open, done}`. Routes `POST /cases/{id}/tasks`, `PUT /cases/{id}/tasks/{taskId}`, `DELETE`. Audit `task_added|task_completed|task_reopened|task_removed`. Tasks tab in the case flyout; "3/7 tasks" chip in the case queue. Mapping bump, tests.
- [ ] 2.2 Playbooks. New fixed index `wazuh-alert-manager-v2-playbooks` (name, description, tasks[] with title/owner/dueOffsetMinutes, created/updated audit). CRUD routes (write = admin). `POST /cases/{id}/playbooks/{playbookId}/apply` appends tasks (idempotent per playbook per case). Create-case modal gets a playbook picker; automation `openCase` action gets `applyPlaybookId` (types, validation, planner, evaluator, preview, UI). Settings tab "Playbooks". Tests.
- [ ] 2.3 Timeline. `GET /cases/{id}/timeline?cursor=` merges alert `@timestamp`s (evidence, cap 1,000), comments, audit events for the case (new activity query without the comment filter), task events and SLA events, sorted by time with a scoped cursor. Timeline tab in the case flyout. Also used by the case report (5.2).
- [ ] 2.4 Disposition. `POST /cases/{id}/close` body gains `disposition` (`true_positive|false_positive|benign|duplicate|undetermined`) and `closureReason`; stored on the case and propagated to the alerts it closes (`disposition` on the alert, in `PLUGIN_OWNED_FIELDS`). Alert status change to closed (single and bulk) accepts an optional disposition. Close dialog with the select; disposition badge on closed cases/alerts; filter by disposition. Reporting: "Dispositions" section (donut) and "False-positive rate by rule" table (terms on `rule.id` × `disposition`). Tests.
- [ ] 2.5 Playwright `e2e/trial_case_structure.spec.ts`: create case with playbook, complete a task, view timeline entries, close with false_positive, see it in reporting.

## Phase 1: notifications

- [ ] 1.1 Settings. Doc `notification_settings`: `webhooks[]` (id, name, url, secret (encrypted; HMAC-SHA256 `x-wam-signature`), extra headers, enabled, events[]), `email` (smtp host/port/secure/user/password (encrypted)/from/to defaults, enabled). Events: `case.created`, `case.assigned`, `case.severity_raised`, `case.closed`, `sla.breached`, `sla.escalated`, `rule.action`, `report.scheduled`. Routes `GET/PUT /notifications/settings`, `POST /notifications/test/{channelId}` (admin). Settings tab "Notifications".
- [ ] 1.2 Outbox and dispatcher. New fixed index `wazuh-alert-manager-v2-notifications` (event, channel, payload, attempts, status `pending|sent|failed|dead`, next_attempt_at, last_error). `server/lib/notifications/dispatcher.ts` worker on `lease.ts` (5-s tick), delivery via `boundedFetch` (webhook) and a minimal SMTP client (STARTTLS/implicit TLS, AUTH PLAIN/LOGIN) unless `nodemailer` is already available in the dashboard tree; exponential backoff, dead after 5 attempts. Payloads are allowlisted projections only (`projectCaseEvent`, `projectAlertForNotification` with entities and severity, never raw `_source`). Route `GET /notifications/outbox` + retry. Outbox panel in the Notifications tab. Tests.
- [ ] 1.3 Emitters. Hook in `activity.ts` for `targetType: 'case'` actions → outbox; SLA scanner breach/escalation → outbox; scheduled summaries (5.4) → outbox with the rendered Markdown.
- [ ] 1.4 Rule action `notify: {channelIds[]}` end to end: types, `actionsSchema`, `normalizeRule`, planner, evaluator stage with idempotent delivery ids, preview counters, execution counters mapping, rules UI Actions stage (remove the "no webhook actions" text).
- [ ] 1.5 Playwright `e2e/trial_notifications.spec.ts`: local webhook receiver started by the test; create a case → receiver gets a signed payload; rule with notify action fires on a seeded alert.

## Phase 7: documentation and hand-off

- [ ] README (features, new indices, settings, "no export/webhook" statements removed), `AGENTS.md` index inventory, wiki Architecture/User-Guide/Automation-Rules/Reporting/Security-Model pages, `RELEASE_NOTES_v3.0.0.md` draft section "Trial features".
- [ ] Full `yarn test` green in the dev image; `yarn build` zip for OSD 2.19.6 installed in the Docker stack; all `e2e/trial_*.spec.ts` green; smoke + existing mutating specs still green.

## Log

- 2026-11-20: branch created from 3.0; recommendations and plan written; dev image build and Docker stack started; subsystem maps in `runtime-evidence/trial-features/map/` (git-excluded).
