# Reuse study: trial features vs what Wazuh 4.14 / 5.0 already ship

Written 2026-11-20 against branch `trial-features`. Companion to
[PLAN.md](PLAN.md) and [RECOMMENDATIONS.md](RECOMMENDATIONS.md). Owner's rule:
do not rebuild what Wazuh 4.14.x / 5.0 or the OpenSearch plugins bundled in the
Wazuh indexer and dashboard already provide robustly; prefer reading their
indices, calling their APIs or driving their channels. The premise that the
5.0 native case model is insufficient is **confirmed** (section 1.6).

Evidence legend used throughout:

- **[STACK]** verified on the local Wazuh 4.14.10 single-node Docker stack
  (indexer `https://localhost:9200`, dashboard `https://localhost:8443`,
  server API `https://localhost:55000`; OpenSearch / OSD 2.19.6, all
  bundled plugins 2.19.6.0).
- **[SRC]** from official docs or the named GitHub branch/file (5.0 =
  `wazuh/*` repos at `5.0.0`; no running 5.0 instance exists).
- **[UNVERIFIED]** inference not checked on a live system.

Every claim below was taken through an adversarial verification pass. Where
a verifier refuted the original research claim, this document says so
explicitly (section 6 collects them) and only the corrected statement is used.

---

## 0. Cross-cutting facts that shape every decision

These were established repeatedly by independent verifiers and are the reason
several "reuse" ideas collapse into "build":

1. **Our routes run as the logged-in user; only the sync job runs as the
   dashboard internal user.** `server/routes/*.ts` use
   `context.core.opensearch.client.asCurrentUser` (e.g. `alerts.ts:115`,
   `cases.ts:355`); `server/plugin.ts:48` uses `asInternalUser`
   (= `kibanaserver`, roles `kibana_server`, `own_index`,
   `manage_wazuh_index` [STACK]). Consequences: any reuse of Alerting,
   Notifications, Reporting, Observability or ISM from a route needs the
   *analyst* to hold the matching reserved role (none are mapped to non-admin
   users on a stock install [STACK]); any reuse from the background job needs
   `kibanaserver` to be granted the role (it cannot even list monitors today:
   `POST /_plugins/_alerting/monitors` as kibanaserver -> 403
   `cluster:admin/opendistro/alerting/monitor/write` [STACK]).
2. **The plugin has no Wazuh server API client.** `grep -rn "55000|wazuh-wui|/api/request" server common public` -> nothing. The only
   supported path to `:55000` is the `wazuhCore` plugin's route-handler
   context `context.wazuh_core.api.client.{asInternalUser,asCurrentUser}`
   (4.14.10 `plugins/wazuhCore/server/plugin.js:77-95`; 5.0.0
   `plugins/wazuh-core/server/plugin.ts:95-116`). `asCurrentUser` there needs
   the browser's `wz-token` cookie and a Wazuh RBAC mapping for the OSD user
   (an unmapped analyst gets HTTP 200 with empty `affected_items` for
   `/agents` and `/groups`, or 403 on `/mitre/*` [STACK]); `asInternalUser`
   uses the stored `wazuh-wui` credential with `run_as`. Anything that reads
   agent groups, MITRE detail or SCA on 4.x therefore adds an **optional
   `wazuhCore` plugin dependency** and must run in the sync job, not per
   request. (Open question Q3.)
3. **Status-index mapping is `dynamic: false`** (`server/lib/mappings.ts:9`)
   and the projection is an allowlist (`operational_projection.ts:42-100`,
   `wazuh5_finding_adapter.ts:109-184`). Every native field we want to filter
   or aggregate on needs a mapping entry + `MAPPING_VERSION` bump; raw fields
   are only visible per alert through `_raw_source` / `_raw_event`
   hydration (`routes/alerts.ts:325-372`, flyout `alert_flyout.tsx:56-112`,
   which collapses arrays to the last element).
4. **`PLUGIN_OWNED_FIELDS` protects top-level keys only** (`sync_job.ts:25-36`;
   Painless `params.protected.contains(entry.getKey())` at `:429`). Dotted
   paths such as `agent.groups` or `asset.criticality` never match; the whole
   top-level `agent` object is overwritten on resync. Settings-derived
   fields (asset criticality, SLA due) must be re-stamped at projection time
   rather than protected.
5. **`NATIVE_WAZUH_PREFIXES`** (`index_namespace.ts:10-20`) refuses writes to
   `wazuh-alerts-`, `wazuh-archives-`, `wazuh-events-`, `wazuh-findings-`,
   `.ds-wazuh-`, `wazuh-states-`, `wazuh-monitoring-`, `wazuh-statistics-`,
   `wazuh-case-management-`. It does not yet list `wazuh-threatintel-`,
   `.wazuh-cti-`, `wazuh-active-responses` (5.0 indices this study proposes to
   *read*). `assertManagedWriteTarget` guards only document writes to our
   indices; a `transport.request` to a plugin REST endpoint never passes
   through it, so "write back to native cases" is a policy decision, not a
   code gate (`index_namespace.ts:32-38`).
6. **No public "send" REST API exists in the Notifications plugin on either
   target line.** 2.19.6 registers only config/features/channels/test REST
   handlers (`NotificationPlugin.kt` `getRestHandlers()` L164-179 [SRC],
   `POST /_plugins/_notifications/{send,feature/send,...}` -> "no handler
   found" [STACK]); the send API arrived in OpenSearch 3.10 (notifications
   PR #1280) and Wazuh 5.0's indexer is OpenSearch 3.6.0
   (`wazuh-indexer/5.0.0/buildSrc/version.properties`) [SRC]. **However**,
   PLAN.md:25's conclusion "it cannot be driven from a dashboard plugin" was
   **refuted**: `POST /_plugins/_alerting/monitors/_execute?dryrun=false` with
   an *inline* monitor body (not persisted, `enabled:false`) whose action
   targets a Notifications `config_id` delivers an arbitrary Mustache-rendered
   body in 0.4-1.4 s, leaves zero alert documents, and works for a user holding
   only `alerting_full_access` + read on a tiny index [STACK]. That is the
   mechanism this study reuses for delivery (section 2, phase 1).

---

## 1. Capability inventory (4.14.10 vs 5.0)

Verdict column: **REUSE** (drive it), **INGEST** (read its data), **BUILD**
(nothing adequate), **DROP** (do not pursue). Evidence class in brackets.

### 1.1 Notifications / outbound integrations

| Capability | Wazuh 4.14.10 | Wazuh 5.0 | Verdict |
|---|---|---|---|
| Manager `integratord` (slack, pagerduty, shuffle, virustotal, maltiverse, `custom-*`) | Present but idle (no `<integration>` block; `wazuh-control status` -> not running) [STACK]. Can be fed plugin events end to end via `POST /events` (30 req/min, 100 events/req) + custom rule (`PUT /rules/files`, hot reload) + `shuffle` generic webhook: 2.1 s end to end [STACK]. Needs whole-`ossec.conf` `PUT /manager/configuration` + `PUT /manager/restart` once, server-API credentials, no email. | Removed: no `src/os_integrator`, no `integrations/`, daemon list has no integratord; leftover `<integration>` block stops the manager (`docs/guide/migration/integratord-notifications.md`) [SRC]. | DROP as design (4.x-only, config rewrite + restart, coarse auth). |
| Indexer Notifications plugin: channel types slack, chime, microsoft_teams, webhook, email (smtp_account/ses), sns, email_group | `opensearch-notifications 2.19.6.0`; `GET _plugins/_notifications/features` lists all types [STACK]. Webhook: static `header_params` sent verbatim; `Content-Type` defaults to `application/json` only when `header_params` is empty, otherwise `text/plain` unless set explicitly [STACK]; no HMAC/templated headers [SRC `DestinationHttpClient.kt:145-198`]. Secrets in `header_params` are returned in plaintext to `notifications_read_access` [STACK]. SMTP: host/port/method/from via REST; username/password only in the indexer keystore (`opensearch.notifications.core.email.<account>.{username,password}`) [SRC+STACK]. `host_deny_list` ships empty; indexer reached `host.docker.internal` and loopback [STACK]. JVM truststore does not contain the Wazuh CA, so HTTPS to the dashboard fails `certificate_unknown` [STACK]. | `wazuh-indexer-notifications` fork: same four REST handlers [SRC]; adds `active_response` config type; **creates four disabled placeholder channels** `default_slack_channel`, `default_jira_channel`, `default_pagerduty_channel`, `default_shuffle_channel` (placeholder URLs; sending to a disabled channel returns LOCKED "The channel is muted") [SRC]; **blocks loopback/RFC1918/CGNAT/link-local/ULA by default** (`DEFAULT_HOST_DENY_LIST`, operator override *replaces* the list; HTTP only, not SMTP) [SRC]. | REUSE as channel registry + delivery transport (via Alerting `_execute`, below). |
| Notifications REST send | None (only `feature/test/{id}` with fixed body) [STACK]. | None (OpenSearch 3.6 < 3.10) [SRC]. | n/a |
| Alerting plugin: monitors (query, bucket, document, composite), actions to Notifications channels, `_execute` | `opensearch-alerting 2.19.6.0` [STACK]. Schedule floor 1 minute (SECONDS/MILLIS rejected; 5-field cron only) [STACK]. Inline `_execute?dryrun=false` = on-demand send with custom body [STACK]. Doc-level monitor over an outbox: works for small volumes but `max_actionable_alert_count=50` silently degrades `per_alert` to per-execution batches, failed deliveries are never retried (watermark advances), backlog before monitor creation is never delivered, one ACTIVE alert + finding per delivery [STACK]. Query-level digest: cron + per-action throttle (<= 24h) work; `ctx.results.0.hits.hits` capped at input `size` (default 10) [STACK]. Email through Alerting = `text/plain` only, no attachments (`ChannelMessage(compiledMessage, null, null)`) [STACK+SRC]. Monitors run with the *role names snapshotted from whoever last saved them*, evaluated live; `kibanaserver` cannot create monitors [STACK]. | `wazuh-indexer-alerting` fork of OpenSearch 3.6 alerting; alert/finding history and comments disabled by default; several doc-level monitor fixes in the 5.0 cycle; adds `ACTIVE_RESPONSE` monitor type [SRC]. Behaviour on a live 5.0 node [UNVERIFIED]. | REUSE only the inline `_execute` send path; DROP doc-level/query-level monitors as the outbox mechanism. |
| Dashboard channel/monitor admin UI | `notificationsDashboards`, `alertingDashboards` 2.19.6.0 green; apps under "Explore"; server routes act as the logged-in user; a `kibana_user`-only analyst gets 403 and the Notifications UI silently shows "Channels (0)" [STACK]. | Same plugins packaged (`base-builder.sh packages_list` includes alerting, notifications) [SRC]. | REUSE for channel CRUD (link out); our Settings tab is a channel picker needing `notifications_read_access`. |
| Email SMTP client | Notifications `smtp_account` + `email` config; test message delivered (multipart text+html) in 0.15 s; Alerting-driven mail is text-only [STACK]. | Same fork [SRC]. | REUSE (text-only); own SMTP client becomes optional (Q1). |

### 1.2 Threat intelligence / IOC enrichment

| Capability | 4.14.10 | 5.0 | Verdict |
|---|---|---|---|
| GeoIP on alerts | Indexer `ingest-geoip` processors in `filebeat-7.10.2-wazuh-alerts-pipeline` write `GeoLocation.{country_name,city_name,region_name,location}` for 10 `data.*` IP fields (no `ip` attribute, no ASN); **last processor wins** when several IPs are present; GeoLite2 DB dated 2019-11-12; only public IPs; 0 of 187 stack alerts carry it; docs written directly to `wazuh-alerts-*` (e.g. `e2e/seed_alerts.py`) bypass it; `_simulate` is admin-only [STACK]. | Engine `geo` enrichment writes ECS `<entity>.geo.*` for client/destination/server/source (+ `.as.{number,organization.name}`) and `.geo` only for host/observer/wazuh.agent.host; optional policy stage; needs GeoLite2 download from `analysisd.geo_manifest_url` (defaults to a pre-production host) [SRC]. | INGEST as best-effort hints with caveats; never build a GeoIP lookup. |
| VirusTotal | `virustotal.py` (FIM md5 only, VT API v2, syscheck group only); emits a *separate* alert with `data.virustotal.*` (all `keyword`, pre-mapped in the `wazuh` template), rules 87100-87106 (87105 level 12); error alerts carry no `source.alert_id`; unconfigured on the stack [STACK]. | Removed with integratord; "no direct equivalent for live third-party lookups" (`virustotal-migration.md`) [SRC]. | INGEST when present (4.x only). |
| Maltiverse | `maltiverse.py` reproduced end to end against a mock: separate alert with ECS-style `data.threat.indicator.*`, `data.threat.software.*`, raw `data.maltiverse.source`, `data.alert_id` link; numbers stringified; all fields dynamic `keyword`; inspects only `data.srcip` (public), `data.hostname`, `data.url`, `syscheck.md5/sha1_after` [STACK]. | Removed [SRC]. | INGEST when present (4.x only). |
| Community AbuseIPDB / MISP / OTX / GTI / ThreatLens scripts | `wazuh/integrations` repo, `custom-*` scripts; not shipped; vendor-specific `data.*`; must be copied to the manager filesystem as root:wazuh 750 (no API) [SRC+STACK]. No OpenCTI integration exists [SRC]. | Mechanism removed [SRC]. | DROP as a dependency; normalise `data.integration`-tagged sibling alerts if present. |
| CDB lists (`malicious-ioc`) | `etc/lists/malicious-ioc/{malicious-ip 199, malicious-domains 200, malware-hashes 200 (164 with family)}`; rules **99901-99920** on `srcip, sha256, ClientIP, ip_address, src_ip, dest_ip, http.hostname, dns.rrname, win.eventdata.ipAddress`; a hit changes rule id/level and *drops* the base rule's MITRE tags; no enrichment field. Readable via `GET /lists?...`; shipped subdir lists **not** writable through `PUT /lists/files` (root `etc/lists` only; manager restart to load) [STACK]. | No `/lists`, `/rules`, `/decoders` in the 5.0 server API; engine has `iockvdb`/`iocsync` fed by CTI [SRC]. | INGEST by `rule.id` on 4.x. |
| MITRE | `rule.mitre.{id,technique,tactic}` already projected; 7 `/mitre/*` endpoints; techniques return STIX tactic ids; cold call 3 s, whole table (750) 157 KB in 0.24 s; `GET /rules?mitre=` is 4.x only [STACK]. | Same 7 `/mitre/*` endpoints; `wazuh.rule.mitre.{technique,subtechnique,tactic}.{id,name}` nested, flattened by our adapter [SRC]. | INGEST (already done); optional cached table via wazuhCore (Q3). |
| Wazuh CTI IoC catalog | None (CTI = CVE pages only) [STACK]. | Content Manager syncs `cti:catalog:consumer:iocs` hourly into alias `wazuh-threatintel-enrichments` (blue/green `-a/-b`); docs `document.{id,name,type,confidence,provider,reference,tags,feed.name,software.*,first_seen,last_seen}`; types `url_domain,url_full,connection(ip:port),hash_sha256,hash_md5,hash_sha1` (dashboard-side enum only); no bare-IP type; checksum doc `__ioc_type_hashes__` must be excluded; Open plan consumer `public-iocs-5` served **without auth** (live `GET .../changes?from_offset=0&to_offset=3` -> 200; first record provider `threat-fox`, feed `abuse_ch`); CTI API has no lookup endpoint and returns 429 under load; shipped roles grant read only to `dashboard_server` and `wazuh_manager` [SRC + live CTI API]. | INGEST on 5.0 (local index read); never call the CTI API. |
| Engine IOC enrichment on findings | n/a | `wazuh.threat.enrichments[] = {indicator:<CTI doc>, matched:{field}}`; connection requires ip **and** sibling port (lone IPs never match); domains = any field containing domain/registered_domain/subdomain + host.name/host.hostname/dns.question.name; md5/sha1/sha256; `confidence` stringified; object (not nested) mapping; depends on the iocs consumer being populated [SRC]. | INGEST (bounded projection). |
| CTI Explorer app | n/a | Local reader of `wazuh-threatintel-enrichments*` / `.wazuh-threatintel-vulnerabilities*` as the signed-in user; lookup = case-insensitive `term document.name` (+ `prefix "<ip>:"`); <= 50 records; no attachment to findings/cases; URL keeps tab/record; the Overview tab also calls the server Ruleset APIs for counts [SRC]. | REUSE deep link + reuse its query shape. |

### 1.3 Assets / inventory

| Capability | 4.14.10 | 5.0 | Verdict |
|---|---|---|---|
| Agent identity on alerts | `agent.{id,name,ip}` only; no groups; `agent.labels.*` only when `<labels>` configured (verified end to end: label appears in ~45 s as dynamic `keyword`; hidden labels suppressed) [STACK]. | `wazuh.agent.{id,name,groups,version,host.*}` on every finding/state doc (`wcs_wazuh_agent_groups` template; rc2 fixture `groups:["default"]`); **labels removed** ("Agent labels were removed in 5.0.0") [SRC]. | INGEST groups on 5.0; 4.x labels optional override. |
| Agent groups / metadata | Server API `GET /agents?select=id,name,group`, `GET /groups/{g}/agents`, 70 ms; agent 000 has no `group`; an unmapped run_as user gets empty results silently [STACK]. | Same endpoints; agent 000 removed; enrollment rejects unknown groups [SRC]. | INGEST via sync-time cached lookup (4.x needs wazuhCore, Q3). |
| Inventory states | 13 `wazuh-states-inventory-<type>-<cluster>` + `wazuh-states-vulnerabilities-<cluster>` plain indices, WCS-shaped (`host.os.*`, `destination.port`, `vulnerability.{id,severity,score.base,under_evaluation,detected_at}`, `package.*`), root `agent.id`; **all 0 docs** on the stack because the manager never indexes its own inventory (`disable_scan_manager=1`) and no agent is enrolled; non-admin users need an explicit read grant (403 otherwise) [STACK]. Server API `/syscollector/{id}/*` works for 000 (API shape differs from index shape) [STACK]. | Same families as bare indices `wazuh-states-inventory-<type>`, `wazuh-states-vulnerabilities`, plus `wazuh-states-sca`, `wazuh-states-fim-*`; identity `wazuh.agent.id`; no `/syscollector`, no `/sca` API [SRC]. | INGEST (wildcard patterns, per-family field map, graceful 403). |
| SCA | API `GET /sca/{id}` and `/checks/{policy}` (`result` = passed/failed/**not applicable**, 47% n/a on the stack); no state index; alerts 19003/19007-19009 carry `data.sca.*` as a changefeed [STACK]. | `wazuh-states-sca` (`check.name`, `check.result`, `check.compliance.*`, `check.mitre.*`, `policy.*`); no API [SRC]. | INGEST on 5.0; defer on 4.x. |
| Vulnerability read API | None (`/vulnerability` 404) [STACK]. | Only `PUT /agents/scan/vulnerability` (trigger) [SRC]. | INGEST from states index. |
| IT Hygiene / Vulnerability Detection apps | Present (4.13+), deep links `/app/it-hygiene#/overview/?tab=it-hygiene&tabView=dashboard&agentId=<id>`, `/app/vulnerability-detection#/overview/?tab=vuls&tabView=dashboard&agentId=<id>` [STACK+SRC]. | Same ids and redirects [SRC]. | REUSE (deep link, summary chips only). |

### 1.4 Reporting / export

| Capability | 4.14.10 | 5.0 | Verdict |
|---|---|---|---|
| Wazuh module reports (pdfmake) | `plugins/wazuh` private `ReportPrinter` (pdfmake 0.2.7 in the plugin's own `node_modules`), 21 fixed module layouts, needs `wz-token` cookie, writes PDFs to `data/wazuh/downloads/reports/<md5(user)>/`; no contract export [STACK]. | Removed (#7813); replaced by `reportsDashboards.generateInContextPDFReport(url)` plugin contract, which renders **saved dashboards/visualizations** client-side [SRC]. | DROP. |
| OpenSearch Reporting (reportsDashboards + reports-scheduler) | Saved-search -> CSV/XLSX server-side (buffered, JSON-wrapped, `limit` default 10000, scroll above `max_result_window`, dots escaped `agent\.name`, empty cells `" "`); index pattern must carry a `fields` attribute (else 500); needs `reports_full_access` + `indices:monitor/settings/get` + `kibana_user`; module-level mutable state makes concurrent generation return garbage (11/12 bodies blank) [STACK]. Dashboard/visualization PDF/PNG = browser html2canvas+jsPDF, never stored. **Scheduler is a no-op**: cron ticks create instances with `Status.Success` and deliver nothing (two ticks, zero webhook hits) [STACK]. | Fork `wazuh-indexer-reporting` **does** add `NotificationApiUtils.onReportInstanceCreated` (PR #67): sends a "New Report Available" *link* through Notifications channels when an instance is created; file still rendered only when a user opens the link; saved-object sources only [SRC]. Discover gains native "Download CSV" (upstream OSD 3.x PR #9530; Wazuh #1442 makes the cap `reports.csv.maxRows`, bounded by `max_result_window`) [SRC]. | BUILD own CSV; optional index-pattern provisioning (Q8). |
| Observability Notebooks | Indexer `_plugins/_observability/object` CRUD works (admin, ~1 s); no `observabilityDashboards` plugin, no UI, Reporting's notebook source 404s; needs `observability_*` roles [STACK]. | No observability plugin on indexer or dashboard [SRC]. | DROP. |
| File/attachment storage | None against alerts/cases (Reporting stores metadata only; Wazuh plugin PDFs are per-user local disk) [STACK]. | None (`wazuh.case` has no attachment field) [SRC]. | BUILD. |

### 1.5 Alerting / SLA / scheduling primitives

| Capability | 4.14.10 | 5.0 | Verdict |
|---|---|---|---|
| Native alert status / assignment | None: `wazuh` template has no status/assignee/case fields; server API has no `/alerts`, `/cases`; dashboard has no case code [STACK]. | Native case fields (1.6); no assignment/SLA [SRC]. | BUILD (already ours). |
| Alerting as SLA breach detector | Query-level monitor with `range sla_due_at lt now` works (1 alert per trigger regardless of record count); bucket-level composite on `_id`/`alert_uid` gives one alert per record with ACTIVE -> ACKNOWLEDGED -> COMPLETED, **but** above `max_actionable_alert_count=50` per-alert NEW actions silently become per-execution batches on every tick (59-record test) [STACK]. Doc-level alerts never COMPLETE [STACK]. 1-minute floor; ack does not flow back; analysts need `alerting_read_access` + `alerting_ack_alerts` mapped [STACK]. | Fork; same model expected [UNVERIFIED]. | DROP from plan (optional later mirror). |
| Alerting action calling our API | Technically possible (custom body + headers to httpbin) but: JVM truststore lacks Wazuh CA (`certificate_unknown` to the dashboard and to the indexer itself), plaintext service credential in channel config, `Content-Type` pitfall, Mustache trailing-comma invalid JSON, no retry/audit [STACK]. | 5.0 deny list adds private-host blocking [SRC]. | DROP. |
| ISM | Index-level conditions only (`min_index_age, min_doc_count, min_size, min_rollover_age, cron`; a `query` condition -> 400); `notification` action does fire webhooks (verified) but with index-metadata context only; `job_interval` 5 min [STACK]. | Same plugin line [UNVERIFIED]. | DROP. |
| job-scheduler | Java SPI; the `PUT _job_details` REST registration exists but targets the Extensions SDK (`ExtensionProxyAction` missing -> job parse fails); REST lock API (`GET _lock`, `PUT _release_lock/{id}`) works [STACK]. | Same [SRC]. | DROP as scheduler; lock API noted (Q10). |

### 1.6 Cases

| Capability | 4.14.10 | 5.0 | Verdict |
|---|---|---|---|
| Native case object | None (`/_plugins/_security_analytics/*` -> no handler; security-analytics deliberately excluded from the 4.x bundle, commented out in `packaging_scripts/assemble.sh`) [STACK+SRC]. | `wazuh.case.*` fields on **one finding** (`title, description, tags[], user.name (last updater, server-set), status active|acknowledged|completed|error|deleted|audit, severity, priority, tlp, created_at, updated_at, comments[]`); no id, no grouping, no assignee, no tasks, timeline, attachments, SLA, field-change audit; 20-comment cap is dashboard-side only; written via `PUT /_plugins/_security_analytics/findings/_update` against the **backing `.ds-` index**, bulk cap 10, arrays replaced wholesale, caller needs write on findings backing indices (no shipped role has it; `dashboard_server` is read-only) [SRC]. | BUILD (ours); optional read-only projection (Q6). |
| Per-case URL / embedding | n/a | Only app/tab deep links (`/overview/?tab=caseManagement&tabView=dashboard|cases`); no plugin-contract exports (`setup()/start()` return `{}`); HTTP routes `GET/POST/DELETE /indexer/findings/case/{index}/{docId}` exist [SRC]. | DROP embedding; deep link only. |
| Disposition -> detection feedback | No automatic trigger. Effector exists: `PUT /rules/files/<f>.xml` with `overwrite="yes" level="0"` verified via `/logtest` (live pickup needs `PUT /manager/restart`, not executed) [STACK]. | No trigger; `status: error` is inert. Effector: toggle Standard detector `enabled` (`cluster:admin/opensearch/securityanalytics/detector/write`, admin-only; disabling drops all findings of that integration) or Custom detector/rule `enabled` [SRC]. | BUILD trigger (2.4); effector = future opt-in (Q7). |
| Ticketing / task lists | Only outbound integrator scripts; TheHive/IRIS/Jira are blog `custom-*` scripts; no round trip [STACK+SRC]. | Jira/PagerDuty/Shuffle = plain webhook channels with placeholder auth; Alerting stores only `action_execution_results{action_id,last_execution_time,throttled_count}` (response body discarded, so no ticket id) [SRC+STACK]. Active Response monitors write `wazuh-active-responses` (host response, out of scope) [SRC]. | BUILD tasks/task-lists; REUSE channels as transport only. |

---

## 2. Decision per PLAN.md step

Format: **Decision** - component / mechanism - what we still provision -
limits - evidence. "Refuted" lines name research claims the verification pass
rejected, so the plan does not inherit them.

### Phase 0: shared foundations

**0.1 `boundedFetch` + `validateEgressUrl` - BUILD (unchanged, narrower use).**
Still required for enrichment sources (6.2) and the direct (HMAC) webhook
channel (1.2). Not needed for the Notifications-channel delivery path, where
the indexer owns egress. Note the policy conflict with on-prem receivers: PLAN
0.1 blocks private ranges and so does 5.0's Notifications deny list by default
[SRC]; an operator with Shuffle/n8n on 10.x needs an explicit allowlist on
*both* paths (Q9).

**0.2 `lease.ts` - BUILD.** job-scheduler's REST lock API
(`GET /_plugins/_job_scheduler/_lock`, `PUT .../_release_lock/{id}`) works
[STACK] but its permission requirements for `kibanaserver` are unverified and
it adds nothing over `sync_lock.ts` semantics. Keep ours (Q10).

**0.3 `plugin_settings.ts` - BUILD.** Secrets we keep: enrichment API keys,
direct-webhook HMAC secrets. Secrets we no longer need to hold: SMTP
credentials and channel auth headers when the Notifications path is used
(they live in the indexer keystore / channel config).

**0.4 route helpers - BUILD.** Unchanged.

**0.5 Playwright helpers - BUILD.** Unchanged.

**New 0.6 `server/lib/native_read.ts` - BUILD (small).** Read-only search
helper for native indices outside the alert/finding family
(`wazuh-states-*`, `wazuh-threatintel-enrichments*`), bypassing
`assertSafeSourcePattern` (which admits only the selected source family,
`index_namespace.ts:45-62`) while still refusing any write. Add
`wazuh-threatintel-`, `.wazuh-cti-` and `wazuh-active-responses` to
`NATIVE_WAZUH_PREFIXES`. Every call tolerates 403/404 and returns "no access"
/ "not available" (the Wazuh dashboard does the same: its cti-feed route
swallows 403 into null [SRC]).

**New 0.7 Roles and install.sh - BUILD (docs + script).** Three new grants
surface repeatedly [STACK]: (a) analysts need `read` on `wazuh-states-*`
(6.4) and, on 5.0, on `wazuh-threatintel-enrichments*` (6.2); (b) the
channel picker needs `notifications_read_access` (1.1); (c) the delivery
service identity needs `alerting_full_access` + read on the outbox index (1.2).
Document that on a stock install only `all_access` has any of these.

**New 0.8 (decision pending, Q3) optional `wazuhCore` dependency.** If
accepted: `optionalPlugins: ["wazuhCore"]` in `opensearch_dashboards.json` and
a thin wrapper around `context.wazuh_core.api.client.asInternalUser.request()`
with the configured `apiHostID`, used only by the sync job (agent groups on
4.x, optional MITRE table cache).

### Phase 6: enrichment and context

**6.1 Indicator extraction - BUILD + INGEST.** Extraction itself exists in
neither line (BUILD, as planned). What changes is the input set:

- INGEST on 4.x (from `_raw_source`, projection extension needed because
  `operational_projection.ts:84-92` keeps only `data.srcip/dstip/...`):
  `syscheck.{md5,sha1,sha256}_after`, `data.url`, `data.hostname`,
  `data.win.eventdata.ipAddress`, `GeoLocation.*` (hint only: stale 2019 DB,
  last-IP-wins, no `ip` attribute, absent for private IPs and for docs written
  without the Filebeat pipeline [STACK]).
- INGEST on 4.x sibling alerts: `data.integration` in {`virustotal`,
  `maltiverse`, `custom-*`} linked by `data.virustotal.source.alert_id` /
  `data.alert_id`; normalise into a `threat.matches[]` verdict. CDB hits:
  tag indicators when `rule.id` in 99901-99920 [STACK].
- INGEST on 5.0 (from the finding): `file.hash.*`, `url.*`,
  `dns.question.name`, `related.{ip,hosts,hash,user}`,
  `<entity>.geo.*` / `.as.*`, and a **bounded** copy of
  `wazuh.threat.enrichments[]` (`indicator.{id,name,type,provider,feed.name,
  confidence,tags,software.name}`, `matched.field`, cap N entries) into the
  same `threat.matches[]` [SRC]. Remember lone IPs are never engine-matched
  (connection = ip + port) [SRC], so our own lookups still cover bare IPs.
- Add `hash|domain|url` entity kinds to `entity_expression.ts` (today only
  `srcip|dstip|srcuser|dstuser|agent|rule|process`).
- Mapping: new `threat` and `geo` sub-objects, `MAPPING_VERSION` bump.
- **Correct PLAN.md:23**: the 5.0 paths are `wazuh.threat.enrichments[]` (not
  `threat.*`) and `<entity>.geo.*` / `<entity>.as.*` (not `geo.*`).

Refuted: "surface GeoLocation, never look it up again" (GeoLocation is
stale, unattributable and usually absent; it is a hint, not a substitute for
a lookup).

**6.2 Enrichment sources - BUILD + INGEST (5.0 local CTI source).** No
analyst-initiated, cached, attached lookup exists on either line
(VT/Maltiverse are ingest-time, FIM-only or unconfigured; 5.0 engine matching
is offline and cannot be extended to third-party feeds [SRC]). Build the
pluggable sources as planned (AbuseIPDB, MISP, generic HTTP; VirusTotal v3
optional with the public-API commercial-use caveat). Add one zero-config
built-in source on 5.0 builds, **`wazuh_cti_local`**: a read of
`wazuh-threatintel-enrichments*` with the CTI Explorer's own query (exact
case-insensitive `term document.name`; for IPs also
`term document.type=connection` + `prefix document.name "<ip>:"`; md5/sha1/
sha256 exact; `exists document.type` to skip `__ioc_type_hashes__`) returning
provider/feed/confidence/software/tags as a verdict [SRC; DSL shape ran on
2.19.6 in 0.16 s with a synthetic index [STACK]]. It returns "absent from
catalog", not "clean". Do **not** build a Wazuh CTI HTTP connector: the API
is a bulk catalog-sync surface with no lookup endpoint, rate-limited with
429s, and the token belongs to the indexer [SRC]. **Correct PLAN.md:22**: CTI
Explorer is a local index reader, not a subscription lookup; the local read is
legitimate reuse in addition to the deep link.

Refuted: "CTI API has no documented rate limits / third-party terms / needs
device-code auth for IoCs" (Open feed is unauthenticated, 429 is documented,
feed data carries third-party licences such as abuse.ch).

**6.3 Lookups in the UI - BUILD.** As planned; CTI Explorer deep link on 5.0
(`/app/cti-explorer` with the record in the query string [SRC]). The flyout
Fields tab must stop collapsing arrays (`alert_flyout.tsx:56-60,105-106`) or
`threat.matches[]` will show only the last entry.

**6.4 Asset context - BUILD matcher + INGEST groups + INGEST states.**

- Criticality source: keep the settings-doc matcher (agent name / glob) as
  the primary key and **add `agent.groups` as a match key**. On 5.0 stamp
  `agent.groups` from `wazuh.agent.groups` in the adapter (currently dropped,
  `wazuh5_finding_adapter.ts:130-153`). On 4.x groups are not on the alert
  and require a sync-time, TTL-cached `GET /agents?select=id,name,group`
  through wazuhCore `asInternalUser` (Q3); agent 000 has no group and is 100%
  of this stack's alerts [STACK]. 4.x `agent.labels.criticality` = optional
  extra matcher, documented as gone in 5.0 [STACK+SRC].
- Stamping: `asset.{criticality,tags}` and `agent.groups` are written at
  projection time on every sync and **not** added to `PLUGIN_OWNED_FIELDS`
  (top-level-only protection would freeze them; see section 0.4). Mapping
  entries + `MAPPING_VERSION` bump.
- Asset context chips (new sub-step 6.4b): read `wazuh-states-inventory-system*`
  (OS/hostname), `wazuh-states-inventory-networks*` (IPs),
  `wazuh-states-inventory-ports*` (`interface.state: listening`),
  `wazuh-states-vulnerabilities*` (agg `vulnerability.severity`, top CVEs by
  `vulnerability.score.base`), and on 5.0 `wazuh-states-sca*`
  (`check.result: failed`). Per-family field map: 4.14 root `agent.id`, 5.0
  `wazuh.agent.id`. Always wildcard patterns (4.14 names carry
  `-<cluster.name>`). Degrade to "no access" on 403, "no inventory" on empty.
  Deep-link to IT Hygiene / Vulnerability Detection with `agentId`. Do not
  build inventory tables, CVE lookup or SCA evaluation. 4.14 SCA via the
  server API is deferred (needs wazuhCore + `sca:read`; `result` has a third
  value "not applicable").
- Automation predicate `minAssetCriticality` as planned.

Refuted: "use agent groups as the primary key instead of a registry" (not on
4.x alerts, agent 000 has no group, membership is operational config, no
API client); "stamp into PLUGIN_OWNED_FIELDS" (dotted paths never match);
"states indices verified" (0 docs on 4.14; shapes from mappings only).

**6.5 - unchanged (documented boundary).** Cached verdicts only; the
`wazuh_cti_local` source is cheap but still runs through the cache, never
inside the worker.

**6.6 Playwright - BUILD.** Add a 5.0-shaped fixture with
`wazuh.threat.enrichments[]` and `wazuh.agent.groups` in `seed_findings_v5.py`
(plugin-owned `wazuh-*-v5-wam-*` streams only); states/threatintel indices
cannot be seeded natively (never write to `wazuh-states-*` /
`wazuh-threatintel-*`), so chip tests use a synthetic read-only index name
behind a test-only pattern override or assert the "no inventory" state.

### Phase 5: evidence and reporting output

**5.1 CSV export - BUILD (as planned); optional REUSE for Discover users.**
The Reporting path was reproduced (admin, 0.4 s, 191 rows) but is unfit as our
export: it needs a saved search + index pattern with a populated `fields`
attribute per filter set, `reports_full_access` + `indices:monitor/settings/get`
+ `kibana_user`, is tenant-blind (hard-coded `.kibana`), buffers everything into
a JSON-wrapped string, escapes dots, and corrupts concurrent requests (11 of 12
parallel bodies blank) [STACK]. 5.0 Discover's native CSV is browser-only with
no API [SRC]. Keep `GET /alerts/export.csv` / `GET /cases/export.csv` with
`search_after`, our own authz and streaming. Optional 5.1b (Q8): provision
index patterns `wam-alerts` (`wazuh-alert-status-v2-read`, `@timestamp`) and
`wam-cases` (`wazuh-alert-manager-v2-cases-read`, time field `created_at`,
there is no `@timestamp`) with `fields` (empty `"[]"` is sufficient; full list
only changes date formatting) through `core.savedObjects.createInternalRepository()`
at `start()`, **not** `IndexPatternsService.createAndSave` (server-side
`getFieldsForWildcard` throws) [STACK]; refresh on `MAPPING_VERSION` change;
never set as default. Analysts still need `kibana_user` to see them.

Refuted: the original "avoid createAndSave because of setDefault" reason
(setDefault is a no-op when a default exists; the real blocker is the server
API client), and "Discover CSV is a Wazuh 5.0 addition" (upstream OSD 3.x).

**5.2 Case report - BUILD (as planned).** Nothing renders plugin API data to
PDF: the 4.14 pdfmake printer is private, fixed-layout, cookie-gated and
deleted in 5.0; 5.0's `generateInContextPDFReport` is a plugin contract but
renders only a saved dashboard/visualization URL in the browser [SRC+STACK].
Server-rendered HTML + inline SVG + print stylesheet stands. Do not vendor
pdfmake/jspdf.

**5.3 Attachments - BUILD (as planned).** No file store against a record in
either line; Notebooks have no UI on either line; Wazuh's own PDF directory is
per-user local disk with no upload route [STACK+SRC].

**5.4 Scheduled summaries - BUILD scheduler + rendering; delivery via phase 1.**
Reporting cannot render our metrics and its 4.14 scheduler delivers nothing
(verified: two cron ticks, two Success instances, zero webhook hits) [STACK];
the 5.0 fork emails only a link to a saved-object report [SRC]. Keep the
lease-based scheduler and Markdown rendering. Delivery now has two paths from
phase 1: Notifications channel (text body with a dashboard link; no
attachments) or direct webhook. Optional operator recipe (docs only): a
scheduled saved-search CSV definition over the 5.1b index pattern, downloaded
from Reporting > Reports (no email on 4.14).

Refuted: "5.0 fork has no sender" (it has `NotificationApiUtils`, but it only
links to an unrendered instance).

**5.5 Playwright - BUILD.** Unchanged.

### Phase 3: SLA enforcement

**3.1 Configurable targets - BUILD.** No native SLA concept on either line.

**3.2 Due timestamps - BUILD.** As planned (`reporting.sla_due_at`, cases
`sla_due_at`). This field is also the only thing that would ever make an
Alerting mirror possible.

**3.3 Escalation scanner - BUILD (as planned).** Every alternative was
examined and rejected [STACK]: Alerting actions can only notify (no assign /
raise / comment / index write); an Alerting webhook to our own API fails on
TLS trust (`certificate_unknown`), needs a plaintext service credential in the
channel, suffers the `Content-Type` and Mustache-trailing-comma pitfalls, has
no retry or audit, and runs under snapshotted role names; ISM has no
per-document conditions; job-scheduler is Java SPI / Extensions-SDK only.
Cadence floor of Alerting (1 min) equals our 60-s tick, so it buys no latency.
Breach/escalation notifications go through the phase-1 outbox (which can
target Notifications channels). **Drop** the "provision Alerting monitors"
opt-in from the plan: the bucket-level mirror degrades silently above 50
breached records (`max_actionable_alert_count`), needs `alerting_read_access`
+ `alerting_ack_alerts` mapped to every analyst, cannot be created by
`kibanaserver`, and its ack never flows back [STACK]. Keep it as a documented
possibility (Q5), not a step.

**3.4 Reporting counts - BUILD.** Unchanged.

**3.5 Playwright - BUILD.** Unchanged.

### Phase 2: response structure inside a case

**2.1 Tasks, 2.2 Task lists, 2.3 Timeline - BUILD.** No task, task list or
timeline primitive exists on either line (1.6). Jira/PagerDuty/Shuffle on 5.0
are webhook channels; a task list step "create ticket" can reuse them as
transport (phase 1) but the ticket id/status round trip must be ours
(Alerting discards the receiver's response) [STACK+SRC].

**2.4 Disposition - BUILD.** Keep our taxonomy
(`true_positive|false_positive|benign|duplicate|undetermined`). 5.0's
`status: error` is a loose "false positive" with no effect anywhere [SRC].
Do **not** mirror to the native case (Q6): it is 5.0-only, one finding per
update, bulk cap 10, read-modify-write of the full `comments` array racing
with the native UI, needs write on `.ds-wazuh-findings-v5-*` that no shipped
role grants, and the correct target is `source_index` + `source_id`, **not**
`event_index` (which is the events stream) [SRC + `wazuh5_finding_adapter.ts:141,180`].
Keep PLAN.md:20 ("native case fields stay read-only"). A later opt-in
"silence rule" effector (4.x `PUT /rules/files` overwrite + restart; 5.0
detector/rule toggles, admin-only) is possible but out of this plan (Q7).

Optional 2.6 (Q6): read-only projection of `wazuh.case.{status,severity,
priority,tlp,tags}` into the 5.0 alert record and flyout ("Native case" chip)
so analysts see continuity with the Wazuh Cases view. Adapter currently
ignores `wazuh.case` (`wazuh5_finding_adapter.ts:150` sets `case_id: null`).

**2.5 Playwright - BUILD.** Unchanged.

### Phase 1: notifications

**1.1 Settings - BUILD, reshaped.** Channel model becomes three kinds:

1. `indexer_channel` (**REUSE**): `{id, name, configId, events[]}` referencing a
   Notifications channel (slack, teams, chime, webhook, email, sns). Channel
   CRUD stays in the Notifications app (link out to
   `/app/notifications-dashboards#/channels`); our picker lists
   `GET /_plugins/_notifications/configs?config_type=...` (as built in 1.1; `/channels` omits `header_params`) as the logged-in user (needs
   `notifications_read_access`; show a clear empty state on 403 [STACK]). On
   5.0, pre-select the four `default_*_channel` ids when present but mark them
   "disabled placeholder, configure in Notifications" until `is_enabled` is
   true (test send returns LOCKED otherwise) [SRC+STACK].
2. `webhook` (**BUILD**): direct `boundedFetch` POST with HMAC-SHA256
   `x-wam-signature`, for receivers that need signatures, sub-minute delivery
   without the inline-monitor hop, private-LAN targets on 5.0, or HTTPS
   endpoints the indexer JVM cannot trust.
3. `email` (**decision Q1**; recommended REUSE): default to an `indexer_channel`
   of type email (operator configures `smtp_account`/`email` in Notifications;
   SMTP auth lives in the indexer keystore; delivered text-only, no
   attachments [STACK]). The minimal SMTP client in PLAN 1.2 becomes an
   optional later step for HTML/attachment mail.

Event list unchanged. `POST /notifications/test/{channelId}`: for
`indexer_channel` use the inline-monitor send with a fixed body (the
Notifications test endpoint needs `notifications_full_access` and sends a
fixed body; `_execute` needs only `alerting_full_access` [STACK]).

**1.2 Outbox and dispatcher - BUILD outbox + dispatcher; REUSE Notifications
for transport.** The outbox index (`wazuh-alert-manager-v2-notifications`),
lease-based worker, backoff, dead-lettering and `GET /notifications/outbox`
stay exactly as planned: Alerting cannot replace them (doc-level monitors
never retry failed deliveries, lose pre-monitor backlog, degrade above 50
matches, leak an alert+finding per event; query-level digests repeat until
status flips and cap at `size`) [STACK]. The dispatcher gains a second
transport next to `boundedFetch`: for `indexer_channel` it calls
`POST /_plugins/_alerting/monitors/_execute?dryrun=false` with an inline
`query_level_monitor` (`enabled:false`, `schedule` 1000 DAYS, input = a
`match_all` size-0 search on the outbox index, trigger `return true`, one
action `destination_id=<configId>` with `subject_template` and
`message_template` = the already-rendered JSON/text, Mustache-escaped) and
reads `delivery_status.status_code` from the response (verified 200/500
surfaced inline; nothing persisted; 0.4-1.4 s) [STACK]. Service identity: the
dispatcher runs `asInternalUser`, so install.sh / docs must map
`alerting_full_access` to `kibanaserver` and grant it read on the outbox index
(Q2); without it the dispatcher marks `indexer_channel` deliveries failed with
the 403 as `last_error`. Payloads remain allowlisted projections; for webhook
channels the operator must set `Content-Type: application/json` in
`header_params` (documented; our picker warns when it is missing [STACK]).
Email bodies are plain text with a dashboard link.

**1.3 Emitters - BUILD.** Unchanged (activity hook, SLA scanner, scheduled
summaries -> outbox).

**1.4 Rule action `notify` - BUILD.** Unchanged; idempotent outbox `_id`
`notify:{ruleId}:{alertId}:{channelId}` (one outbox entry per channel).

**1.5 Playwright - BUILD.** Add a second scenario: create a Notifications
webhook channel pointing at the test receiver (admin), bind it as an
`indexer_channel`, create a case, assert the receiver gets the rendered JSON
with `Content-Type: application/json` and the inline-monitor delivery status
is recorded on the outbox doc.

Refuted (and therefore not in the plan): "Notifications can deliver only when
triggered by a scheduled Alerting monitor"; "doc-level monitor = per-event
retried delivery"; "query-level monitor re-sends every minute" (cron +
throttle exist); "integratord cannot see plugin events" (it can on 4.x via
`POST /events`, but it is 4.x-only and config-invasive); "5.0 default
channels are ready to reference" (disabled placeholders); "our plugin only
needs a channel picker" (needs a delivery path and role guidance too).

---

## 3. Revised step list (owner's order 6, 5, 3, 2, 1 kept)

Legend: [B] build, [R] reuse, [I] ingest, [opt] optional / pending owner
decision. Unchanged steps keep their PLAN.md text.

### Phase 0
- 0.1 [B] `boundedFetch` + `validateEgressUrl` (unchanged; document the
  private-range stance, Q9).
- 0.2 [B] `lease.ts` (unchanged).
- 0.3 [B] `plugin_settings.ts` (unchanged; fewer secrets).
- 0.4 [B] route helpers (unchanged).
- 0.5 [B] Playwright helpers (unchanged).
- 0.6 [B] `native_read.ts` read-only helper; extend `NATIVE_WAZUH_PREFIXES`
  with `wazuh-threatintel-`, `.wazuh-cti-`, `wazuh-active-responses`; unit
  tests that it refuses writes and tolerates 403/404.
- 0.7 [B] install.sh / Security-Model docs: optional read grants
  (`wazuh-states-*`, `wazuh-threatintel-enrichments*`), `notifications_read_access`
  for channel pickers, `alerting_full_access` + outbox read for the service
  identity; stock-install warning (only `all_access` has these).
- 0.8 [opt, Q3] `optionalPlugins: ["wazuhCore"]` + `server/lib/wazuh_api.ts`
  wrapper (sync-job use only).

### Phase 6
- 6.1 [B+I] indicator extraction incl. 4.x raw fields, sibling VT/Maltiverse/
  CDB verdicts, 5.0 `wazuh.threat.enrichments[]` bounded copy and
  `<entity>.geo/.as`; new `threat`/`geo` mapping; new hash/domain/url entity
  kinds; fix PLAN.md:23 wording.
- 6.2 [B+I] enrichment sources as planned + built-in `wazuh_cti_local` source
  on 5.0 builds (local `wazuh-threatintel-enrichments*` read); no CTI API
  connector; fix PLAN.md:22 wording.
- 6.3 [B] UI lookups + CTI Explorer deep link; flyout array rendering fix.
- 6.4a [B+I] asset settings matcher + `agent.groups` match key (5.0 native;
  4.x via 0.8 when accepted); projection-time stamping; mapping bump.
- 6.4b [I+R] asset context chips from `wazuh-states-*` with per-family field
  map and deep links to IT Hygiene / Vulnerability Detection; graceful
  no-access/no-data states.
- 6.5 unchanged.
- 6.6 [B] Playwright with 5.0-shaped fixtures.

### Phase 5
- 5.1 [B] own CSV routes (unchanged).
- 5.1b [opt, Q8] provision `wam-alerts` / `wam-cases` index patterns + default
  saved searches via the internal saved-objects repository; Settings card
  linking Discover / Reporting with role notes.
- 5.2 [B] case report HTML/Markdown + print (unchanged).
- 5.3 [B] attachments (unchanged).
- 5.4 [B] scheduler + Markdown; delivery through 1.x channels; doc recipe for
  scheduled saved-search CSV (4.14: no email).
- 5.5 [B] Playwright (unchanged).

### Phase 3
- 3.1 [B], 3.2 [B], 3.3 [B] scanner (unchanged; Alerting mirror removed),
  3.4 [B], 3.5 [B].

### Phase 2
- 2.1 [B] tasks, 2.2 [B] task lists, 2.3 [B] timeline, 2.4 [B] disposition
  (no native mirror), 2.5 [B] Playwright.
- 2.6 [opt, Q6] read-only `wazuh.case.*` projection on 5.0 alert records.

### Phase 1
- 1.1 [B+R] settings with channel kinds `indexer_channel` (reuse) / `webhook`
  (build) / `email` (Q1); picker over `GET /_plugins/_notifications/channels`;
  5.0 default channel ids pre-listed as placeholders; test send via inline
  `_execute`.
- 1.2 [B+R] outbox + dispatcher (unchanged) with the inline-monitor transport
  for `indexer_channel`; service-identity role mapping (Q2); SMTP client
  deferred unless Q1 says build.
- 1.3 [B] emitters, 1.4 [B] rule `notify`, 1.5 [B] Playwright (+ indexer
  channel scenario).

### Phase 7
- Add to the docs list: PLAN.md overlap-table corrections (rows for CTI
  Explorer, engine enrichment, Reporting, Notifications, Alerting), the new
  role grants, the 5.0 deny-list caveat, and a "What we deliberately reuse
  from Wazuh" section in the wiki Architecture page.

---

## 4. Open questions for the owner

- **Q1 Email.** Reuse the Notifications email channel (operator-managed SMTP in
  the indexer keystore; plain text; no attachments; delivered via inline
  `_execute`) as the only email path for now, and defer the SMTP client?
  Recommendation: yes; build the client later only if HTML/attachment mail is
  demanded.
- **Q2 Service identity for sends.** Map `alerting_full_access` (+ read on
  `wazuh-alert-manager-v2-notifications`) to `kibanaserver` in install.sh, or
  require a dedicated internal user configured in `wazuh_alert_manager.*`?
  Mapping to `kibanaserver` is simplest but widens the dashboard identity;
  note that on 5.0 `kibanaserver` maps to `dashboard_server` (read-only on
  `wazuh-*`) [SRC].
- **Q3 `wazuhCore` optional dependency.** Accept a manifest dependency on the
  Wazuh dashboard plugin (present on 4.14.10 and 5.0.0) to call the server
  API as `wazuh-wui` from the sync job (4.x agent groups, cached MITRE
  table, later 4.x SCA)? Without it, asset criticality on 4.x is name/glob
  (+labels) only.
- **Q4 Read grants.** Should install.sh add `read` on `wazuh-states-*` and
  (5.0) `wazuh-threatintel-enrichments*` to the plugin analyst role, or leave
  it to the operator with the chips degrading to "no access"?
- **Q5 Alerting breach mirror.** Confirm dropping the opt-in "provision
  Alerting monitors" idea from phase 3 (kept only as a documented
  possibility).
- **Q6 5.0 native case continuity.** Project `wazuh.case.*` read-only onto
  5.0 alert records (cheap, 2.6)? And confirm **no** write-back to native
  cases.
- **Q7 Disposition -> detection effector.** Interest in a later opt-in
  "silence rule" action (4.x `PUT /rules/files` overwrite + manager restart;
  5.0 detector/rule `enabled` toggles, admin-only, with the findings-loss
  caveat)? Not in this plan either way.
- **Q8 Discover/Reporting integration.** Include 5.1b (index patterns + saved
  searches) now, or leave it for a later release?
- **Q9 Private receivers.** PLAN 0.1's URL policy and 5.0's Notifications
  deny list both block RFC1918 targets by default. Accept
  `WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS` as the documented escape hatch for
  the direct webhook, and document the `opensearch.notifications.core.http.host_deny_list`
  override for indexer channels?
- **Q10 Leader lease.** Keep `lease.ts` (recommended) rather than the
  job-scheduler REST lock API, whose permissions for `kibanaserver` are
  unverified.
- **Q11 5.0 verification.** Everything 5.0-specific here is from source/docs.
  Before phase 6 ships, can a 5.0 instance (or the rc2 capture environment)
  be used to verify: inline-monitor send through the fork, `wazuh-threatintel-enrichments`
  reads and role grants, `wazuh.threat.enrichments` population on default
  installs, `wazuh-states-*` reads, and the default channel placeholders?
- **Q12 GeoIP hints.** Surface 4.x `GeoLocation` at all, given the 2019 DB and
  last-IP-wins semantics, or show only 5.0 ECS geo/as?

---

## 5. Corrections to PLAN.md's overlap table

| PLAN.md line | Current text | Correction |
|---|---|---|
| 22 (CTI Explorer) | "look up ... against Wazuh CTI (subscription)" | Local reader of `wazuh-threatintel-enrichments*`; add the local index read as a built-in source on 5.0, keep the deep link. |
| 23 (engine enrichment) | "`threat.*` / `geo.*`" | `wazuh.threat.enrichments[]` (indicator + matched.field) and `<entity>.geo.*` / `<entity>.as.*`; lone IPs are never matched. |
| 24 (Reporting) | "scheduled ... email delivery" | 4.14 scheduler delivers nothing; 5.0 fork emails a link to an unrendered instance; saved-object sources only. Conclusion unchanged. |
| 25 (Notifications) | "cannot be driven from a dashboard plugin" | Can be driven on demand via Alerting inline `_execute` with `alerting_full_access`; no send REST API on 2.19.6 or OpenSearch 3.6. Reuse channels as transport; keep direct webhook for HMAC/private/sub-minute. |
| 26 (Alerting) | "Keep our escalation scanner" | Confirmed; additionally drop the Alerting mirror option (50-alert degradation, role mapping, no ack feedback). |

---

## 6. Refuted research claims (register)

Each line: claim -> what survives.

1. Notifications "only via scheduled monitor" -> inline `_execute` on-demand send works; no REST send API on either line.
2. Doc-level monitor as outbox -> works for small volumes only; no retry, backlog loss, 50-alert degradation, state leakage; dispatcher still required.
3. Query-level digest re-sends every minute -> artefact of a 1-minute schedule without throttle; cron + throttle fine; `size` cap; still no consumption.
4. Bundled admin UIs mean "only a channel picker" -> plus a delivery path plus role guidance.
5. 5.0 default channels usable -> disabled placeholders; Jira/PagerDuty/Shuffle are bare webhooks; deny list blocks private hosts.
6. integratord cannot carry plugin events -> it can on 4.x (`POST /events` + rule + shuffle), but needs config rewrite/restart and server-API creds; gone in 5.0.
7. 4.x GeoLocation "never look it up again" -> stale, unattributable, usually absent; hint only.
8. CDB lists writable via API; rules 99901-99914 -> shipped subdir lists not writable; rules are 99901-99920 incl. domains.
9. MITRE on-demand as the logged-in user -> 401/403 for unmapped users; cache the table via wazuhCore `asInternalUser`; `/rules?mitre=` is 4.x only.
10. Wazuh CTI needs device-code auth, no rate limits/terms -> Open feed unauthenticated; 429 documented; third-party licences apply; still no lookup endpoint.
11. Engine GeoIP on six entities -> `.as` only for client/destination/server/source; optional stage; DB download required.
12. Community TI integrations "none ship" -> VT and Maltiverse do ship (unconfigured); mechanism replaced, not just removed, in 5.0.
13. Agent groups as primary asset key -> not on 4.x alerts; agent 000 ungrouped; needs wazuhCore; additional key only.
14. States indices "verified" -> 0 docs on 4.14 (manager never indexes itself); shapes from mappings; read grant needed.
15. SCA "passed|failed", "no index" -> third value "not applicable"; SCA alerts exist as a changefeed; 5.0 field names differ.
16. Stamp `agent.groups`/`asset.*` into `PLUGIN_OWNED_FIELDS` -> top-level only; would freeze values; do not protect.
17. Reporting CSV reusable programmatically -> response shapes, required query params, three extra permissions, concurrency corruption, `fields` requirement.
18. Discover CSV "added by Wazuh 5.0" -> upstream OSD 3.x; Wazuh made the cap configurable; 4.14 Reporting is not limited to 10k.
19. No PDF engine exposed anywhere -> 5.0 exposes `generateInContextPDFReport` (saved objects only); pdfmake require-able on 4.x by path coupling only.
20. 5.0 scheduled reports have no sender -> fork sends a "New Report Available" link; file still unrendered.
21. Index-pattern registration "avoid createAndSave because setDefault" -> real blocker is the server-side fields fetcher; use the internal repository; needs `fields`; `kibana_user` for analysts.
22. Stack-state claims about leftover channels/instances -> channels gone, 51 instances; `.opendistro-reports-instances` is a plain index deletable by admin.
23. Alerting per-query SLA detection -> one alert per trigger; roles; no actions beyond notify; no latency gain.
24. Bucket-level monitor per record -> degrades above `max_actionable_alert_count=50`.
25. Alerting action to arbitrary HTTPS -> JVM trust, Content-Type, Mustache JSON, plaintext creds.
26. ISM "cannot call HTTP" -> it can (index-level notification); still no per-document conditions.
27. job-scheduler "no REST registration" -> REST registration exists but targets Extensions SDK; still unusable from Node; lock API works.
28. Monitors run as the plugin's internal user -> run with snapshotted role names of the last saver; `kibanaserver` cannot create monitors.
29. Native Alerting UI "visible/acknowledgeable natively" -> admin-only on a stock install; ack does not flow back.
30. 5.0 status `error` has no reusable effector -> detector/rule toggles (admin) and 4.x rule overwrite exist as effectors; trigger still ours.
31. Native case mirror via `event_index` -> wrong field (`source_index`); no shipped write role; not recommended.
32. 5.0 case embedding "no service at all" -> HTTP routes exist; no component/contract; no per-case URL by design.
33. "Nothing task-list-shaped" -> Jira/PagerDuty/Shuffle channels and Active Response monitors exist; no ticket round trip.

---

## 7. Key evidence commands (for re-verification)

```bash
# plugin inventory
curl -sk -u admin:SecretPassword https://localhost:9200/_cat/plugins?v
curl -sk -u admin:SecretPassword https://localhost:8443/api/status | jq '.status.statuses[].id'

# no Notifications send API; test endpoint only
curl -sk -u admin:SecretPassword -X POST https://localhost:9200/_plugins/_notifications/send      # no handler found
curl -sk -u admin:SecretPassword -X POST https://localhost:9200/_plugins/_notifications/feature/test/<config_id>

# on-demand send through an inline monitor (works with alerting_full_access only)
curl -sk -u <user> -X POST 'https://localhost:9200/_plugins/_alerting/monitors/_execute?dryrun=false' \
  -H 'Content-Type: application/json' --data-binary @inline-monitor.json
#   -> trigger_results.*.action_results.*.output.messageId contains delivery_status.status_code

# schedule floor
#   {"period":{"interval":30,"unit":"SECONDS"}} -> 400 "Timezone Seconds is not supported expected [Minutes, Hours, Days]"

# Reporting scheduler is a no-op on 4.14
curl -sk -u admin:SecretPassword https://localhost:9200/_plugins/_reports/instances   # Success instances, no file, no delivery

# native case endpoint absent on 4.14
curl -sk -u admin:SecretPassword -X PUT https://localhost:9200/_plugins/_security_analytics/findings/_update -d '{"findings":[]}'

# states indices exist but are empty on this stack
curl -sk -u admin:SecretPassword 'https://localhost:9200/_cat/indices/wazuh-states*?h=index,docs.count'

# 5.0 Open IoC feed is public (live CTI API)
curl -s -H 'User-Agent: Wazuh Indexer 5.0.0' \
  'https://api.pre.cloud.wazuh.com/api/v1/catalog/contexts/t1-iocs-5/consumers/public-iocs-5/changes?from_offset=0&to_offset=3'
```

Primary 5.0 sources: `wazuh/wazuh@5.0.0` (`docs/guide/migration/*.md`,
`src/engine/source/builder/src/builders/enrichment/{ioc,geo}.cpp`,
`api/api/spec/spec.yaml`), `wazuh/wazuh-indexer@5.0.0`
(`build-scripts/assemble.sh`, `distribution/src/config/security/roles.wazuh.yml`),
`wazuh/wazuh-indexer-plugins@5.0.0` (`plugins/setup/.../templates/{streams,states,content}/*.json`,
`docs/ref/modules/{content-manager,ruleset-management,notifications}/*.md`),
`wazuh/wazuh-indexer-notifications@5.0.0` (`DefaultChannelInitializer.kt`,
`PluginSettings.kt`), `wazuh/wazuh-indexer-reporting@5.0.0`
(`ReportInstancesIndex.kt`, `NotificationApiUtils.kt`),
`wazuh/wazuh-dashboard-plugins@5.0.0` (`docs/ref/modules/{case-management,cti-explorer,cti-feed,notifications-alerting}`,
`plugins/main/server/{routes,controllers}/wazuh-elastic.ts`,
`plugins/main/server/lib/cti-explorer/queries.ts`,
`plugins/main/common/constants.ts`), `wazuh/wazuh-dashboard@5.0.0`
(`dev-tools/build-packages/base/base-builder.sh`, PR #1442).
