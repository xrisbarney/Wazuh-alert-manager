# E2E (Playwright)

Specs in this directory drive a live dashboard. Configuration comes from the
ignored `.env.e2e.local` (loaded by `playwright.config.ts`):

| Variable | Purpose |
| --- | --- |
| `WAM_E2E_URL`, `WAM_E2E_USERNAME`, `WAM_E2E_PASSWORD` | dashboard base URL and sign-in |
| `WAM_E2E_MUTATING=1` | enables the mutating specs (`ui_layering`, `queue_layout`, `lifecycle`, `alert_retirement`, `full_ui`, `seed_check`, `trial_case_structure`, `trial_enrichment`, `trial_export`, `trial_notifications`, `trial_sla`) |
| `WAM_DOC_SCREENSHOTS=1` (+ `WAM_E2E_MUTATING=1`) | enables `wiki_screenshots.spec.ts` (switches the global `theme:darkMode` setting while it runs; captures to `<WAM_DOC_EVIDENCE_DIR>/<light|dark>/`) |
| `WAM_DOC_EVIDENCE_DIR` | capture directory of `wiki_screenshots.spec.ts` (default `runtime-evidence/browser/ui-polish-2`; the light set is copied over `wiki/images/*.png` by hand) |
| `WAM_E2E_SEED=local` | seed fixtures from this machine through the indexer (Docker stack) instead of `vagrant ssh` |
| `WAM_SEED_URL`, `WAM_SEED_USERNAME`, `WAM_SEED_PASSWORD` | indexer endpoint and credentials for local seeding (defaults: `https://localhost:9200`, the e2e credentials) |
| `WAM_SEED_PYTHON` | Python executable for local seeding (default `python`) |
| `WAM_E2E_WEBHOOK_PORT` | host port of the notifications bench's webhook receiver (default `18087`) |
| `WAM_E2E_PROFILE=wazuh5`, `WAM_E2E_VAGRANT_DIR` | Vagrant-lab seeding (5.0 lab, lab directory override) |
| `WAM_E2E_LAB=1` (+ `WAM_E2E_MUTATING=1`) | enables the live-lab tour `lab_setup.spec.ts` (see "Lab tour") |
| `WAM_E2E_ABUSEIPDB_KEY`, `WAM_E2E_MISP_KEY` | API keys the lab tour types into the enrichment sources (never printed or captured; `lab/misp/bootstrap.sh` writes the MISP key) |
| `WAM_E2E_SLOWMO=<ms>` | slows every browser action of the lab tour (headed walkthroughs) |
| `WAM_E2E_LAB_GENERATE=1` | lets the lab tour run `lab/agent/generate.sh` through `vagrant ssh` when no lab alert exists in the last 24 h |

```bash
npx playwright test e2e/smoke.spec.ts                       # read-only, always runs
WAM_E2E_MUTATING=1 npx playwright test e2e/seed_check.spec.ts   # seed + wait for projection
```

## Removing the synthetic data (`cleanup_synthetic.py`)

The mutating benches seed alerts for the agent `wam-e2e-agent` and create
cases titled `WAM e2e ...` / `=WAM e2e ...` / `E2E ...`, rules named
`E2E ...` / `WAM e2e ...`, and their side records. `cleanup_synthetic.py`
removes all of that from a dev stack through the indexer API so only the lab
and manual data remain:

```bash
python -I -X utf8 e2e/cleanup_synthetic.py            # dry run: counts per index, cases and rules kept
python -I -X utf8 e2e/cleanup_synthetic.py --apply    # delete
```

It deletes the projected `wam-e2e-agent` rows of every
`wazuh-alert-status-v2-*` generation and the seeder's own
`wazuh-alerts-4.x-wam-e2e` index, the matching cases, the named rules with
their revision docs, the evidence / activity (comments, alert and case audit,
rule audit events) / attachment / notification outbox / automation queue
records of those alerts, cases and rules, and the `automation-preview:`
documents of the meta index. Before the cases go it clears `case_id` on the
non-synthetic alerts the benches linked to them (`full_ui.spec.ts` links the
first alerts of the live queue), so no real-agent alert keeps pointing at a
deleted case (alerts whose `case_id` already points at a missing case get
the same reset); the dry run reports that count too. Retired (write-blocked)
generations are unblocked for the deletes and blocked again afterwards, also
when a delete fails. Nothing else is touched (`Lab:` cases, manual cases, the
real agent / manager alerts, task lists, settings, the enrichment cache).
Credentials come from `.env.e2e.local` (`WAM_SEED_URL`, `WAM_SEED_USERNAME`,
`WAM_SEED_PASSWORD`, falling back to `WAM_E2E_USERNAME` / `WAM_E2E_PASSWORD`,
the same variables `seedAlerts` hands to `seed_alerts.py`) or from the same
variables in the environment, which win; the password is never stored in the
script. Run it after a bench session on the shared dev stack, and always
before refreshing the wiki screenshots.

## Shared helpers (`helpers.ts`)

- `signIn(page, username, password)` — login form, waits for the workbench.
- `api(page, method, path, body?)` — `fetch` inside the browser session with
  `credentials: 'same-origin'` and the `osd-xsrf` header; throws on non-2xx.
- `apiRaw(page, method, path, body?)` — same session fetch, but returns
  `{ status, ok, headers, text }` for routes that answer with a file (CSV,
  Markdown, HTML, attachment bytes); a non-2xx answer is returned, not thrown.
  `parseCsvLine(line)` splits one RFC 4180 record into cells.
- `seedAlerts({ count? })` — runs `seed_alerts.py` (locally or on the Vagrant
  lab) and returns `{ seeded, index, run }`; seeded ids are `wam-e2e-<run>-<n>`.
- `seedFindingsV5({ count?, severity? })` — runs `seed_findings_v5.py` (locally
  with `WAM_E2E_SEED=local`, otherwise on the 5.0 Vagrant lab) and returns
  `{ seeded, findings_index, run, rule_id, threat_ip, agent_groups }`; every
  finding of the run carries `wazuh.rule.id = rule_id`, and the findings whose
  source IP is `threat_ip` carry one `wazuh.threat.enrichments[]` hit.
- `collapseOsdNav(page)` — clears `core.chrome.isLocked`, reloads and closes
  the dashboard's own side navigation so layout checks measure the content
  width an analyst sees (no-op when it is already collapsed).
- `openAlertFlyout(page, alertId)` / `openCaseFlyout(page, caseId)` — load the
  workbench with `?alert=` / `?tab=cases&case=` and return the flyout locator.
- `pollUntil(page, probe, { timeoutMs?, label? })` — poll an async probe until
  it returns a truthy value.
- `queueRow(page, alertId)` — the anchor cell of one record's alert queue row
  (`.wamAlertRow[data-alert-id]`). The queue is an `EuiDataGrid` (PLAN.md
  13.1) and renders no row element, so anything in another cell of the same
  row is reached with `queueRowCell(page, alertId, selector)` and the row's
  selection checkbox with `queueRowCheckbox(page, alertId)`.
  `applyQueueFilters(page)` clicks the filter bar's Apply button after a quick
  filter (status / SLA chip) was toggled.
- `indexerRequest(method, path, body?)` — direct HTTPS call to the indexer
  (`WAM_SEED_URL`, `WAM_SEED_USERNAME` / `WAM_SEED_PASSWORD`, self-signed
  certificate accepted) for test fixtures that only the indexer API can
  create, such as a Notifications channel; returns `{ status, ok, body }` and
  never throws on a non-2xx. Never route such calls through the dashboard's
  `/api/console/proxy`.
- `waitForProjectedAlert(page, predicate, { agentName?, timeoutMs? })` — polls
  `GET /api/wazuh_alert_manager/alerts` until the sync job (fixed interval,
  30-60 s) projects a matching record. `fromSeedRun(run)` builds the predicate
  for a seed run.

Seeders only write to test-owned indices (`wazuh-alerts-4.x-wam-e2e`,
`wazuh-findings-v5-wam-e2e`), never to native Wazuh indices.

## Queue layout bench (`queue_layout.spec.ts`)

`WAM_E2E_MUTATING=1 npx playwright test e2e/queue_layout.spec.ts` checks step
10.2: at 1280x800 and 1920x1080, with the dashboard nav collapsed
(`collapseOsdNav`), the alert and case queue wrappers (`.wamAlertTable`,
`.wamCaseTable`) have `scrollWidth <= clientWidth + 1` (no horizontal
scroll), the case table has no "Created by" column, and for an alert linked
to a case whose title is exactly 80 characters the Case badge
(`wamAlertCaseBadge`, full title in `title`) ends before the expand button
(`wamAlertExpand`) and `document.elementFromPoint` at the button's centre
returns the button. `beforeAll` picks one open alert of the last 24 hours and
creates the case through `POST /cases`; `afterAll` unlinks the alert
(`PUT /cases/{id}` with `removeAlertIds`) and closes the case with the alert
excluded (cases cannot be deleted through the API). About 1 minute.

## SLA bench (`trial_sla.spec.ts`)

`WAM_E2E_MUTATING=1 npx playwright test e2e/trial_sla.spec.ts` replaces the SLA
policy with a 1-minute resolve/assign target for the `high` band (the seeder's
`rule.level = 10`) and one `unassigned` alert escalation (`wam-e2e-sla`,
50 % threshold, auto-assign + comment), seeds two alerts and waits (up to two
60-s scanner ticks each) for the escalation marker / auto-assignment and the
single `sla_breached` history row, then checks the Breached quick filter, the
flyout, `GET /reports/metrics` and the due-date backfill routes. While the
1-minute policy is in force every open unassigned high-band alert of the stack
is breached and escalated, so `afterAll` restores the policy and closes every
alert assigned to `wam-e2e-sla`. The bench takes about 2 minutes on the Docker stack (up to ~6 minutes
if every poll runs to its budget).

## Case-structure bench (`trial_case_structure.spec.ts`)

`WAM_E2E_MUTATING=1 npx playwright test e2e/trial_case_structure.spec.ts`
covers Phase 2 on a 4.x stack: an administrator creates a three-task task list
through `POST /task-lists` (one task with `dueOffsetMinutes: 60`) and
Settings > Task lists lists it; two seeded alerts become a case through the
queue's "Create case from selected" modal with the task list picked (a native
`<select>`, driven with `selectOption`), the case carries the three tasks and
`applied_task_lists`, and a second `POST .../task-lists/{id}/apply` answers
`applied: false`; a task is ticked in the Tasks tab (`1/3 tasks` chip in the
cases table, `task_completed` history row) and one is added with the inline
form; the Timeline tab and `GET /cases/{id}/timeline` list the alerts, the
task list and the task events in order, page with `limit=2` + `next_cursor`,
and answer 400 to a garbage or foreign-case cursor; the case is closed from
the flyout as "False positive" with a reason, which closes both alerts with
the same disposition (list API `disposition=` filter, queue badge and
Disposition filter, alert flyout); `GET /reports/metrics` and the Reporting
app's Dispositions section count them for rule `930001`; and on the 4.x build
`GET /system/version` reports `targetWazuhMajor: 4` and the alert flyout has
no "Native case" block. `afterAll` deletes the task list (the closed case
stays; cases cannot be deleted through the API). About 2-3 minutes.

## Notifications bench (`trial_notifications.spec.ts`)

`WAM_E2E_MUTATING=1 npx playwright test e2e/trial_notifications.spec.ts`
covers Phase 1 on the Docker stack. `webhook_receiver.ts` starts a Node HTTP
server on `0.0.0.0:<WAM_E2E_WEBHOOK_PORT>` (default 18087) that records every
request (`{ method, path, headers, body, json, at }`) and exposes them to the
spec in-process (`receiver.requests`, `byPath(path)`, `waitFor(predicate)`);
both containers reach it at `http://host.docker.internal:<port>`, so the
dashboard service needs `WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS=host.docker.internal`
and `WAZUH_ALERT_MANAGER_ENCRYPTION_KEY` (both written by
`scripts/dev/e2e-deploy.sh`), the indexer's Notifications `host_deny_list`
must not deny that host (empty on the dev stack), and the dashboard user must
carry `wazuh_alert_manager_notify` (install.sh / docker/dev/README.md).

The bench never removes the operator's channels from the settings document
(a webhook channel left out of a PUT loses its stored secret): every write
carries them switched off, and `afterAll` restores the original document
(original `enabled` flags, `secret: ''` = keep the stored value). It refuses
to run when a stored channel is flagged `invalid` (its URL no longer passes
the egress policy, so every write would be a 400). If the restore fails the
hook falls back to the operator's channels without the bench's (or, failing
that, `enabled: false, channels: []`) and then fails the run.

Six serial tests: (1) channel A = direct `webhook` at `/direct` with the
secret `wam-e2e-secret` and `allowInsecure` (plain http is only honoured for
allowlisted hosts) is saved, `POST /notifications/test/A` lands with
`content-type: application/json` and an `x-wam-signature` the spec
recomputes (`verifySignature`, HMAC-SHA256 over `"<x-wam-timestamp>.<body>"`),
and Settings > Notifications shows the channel with a "Delivered" test badge;
(2) a Notifications webhook channel `wam-e2e-channel` is created on the
indexer (`indexerRequest('POST', '/_plugins/_notifications/configs', ...)`,
`Content-Type: application/json` header so the picker raises no warning),
polled in `GET /notifications/channels` (the config index is not refreshed on
write, so the new config is listable a few seconds later), bound as channel B
(`indexer_channel`, event `case.created`) and its test send reaches
`/indexer` (the Notifications plugin posts the rendered text message as the
body; no WAM signature headers, the indexer is the sender); (3) two seeded
alerts become a case through `POST /cases`, the outbox entries
`case:case.created:<caseId>:<key>:A|B` reach `sent` (dispatcher tick 5 s),
the receiver holds the signed `/direct` payload with `case.id` and the
`/indexer` text, `GET /notifications/outbox/{id}` returns the byte-identical
payload, and the outbox panel shows both rows as "Sent"; (4) a rule with
`notify: { channelIds: [A] }` + `assignTo` is created disabled, previewed and
enabled (a rule naming an unknown channel is refused 400 with
`attributes.unknownChannelIds`), two alerts are seeded afterwards
(ingestion-time evaluation), both are assigned and the entries
`notify:<ruleId>:<alertId>:A` reach `sent` with a signed `rule.action` payload
carrying `rule`, `alert` and `actions.assignee`; (5) negative: a channel URL
`http://10.1.2.3/x` is rejected 400 and nothing is written, a channel with an
unknown Notifications config id still saves but its test send answers
`ok: false` with the error text (route 200, "Failed" badge in the UI), an
unsaved channel id answers 404; (6) the rule is disabled (`PUT {enabled:
false}`), the SLA policy gets the 1-minute `high` targets of
`trial_sla.spec.ts` plus an alert escalation at 50 % on unassigned alerts
with `actions.notify: [A]`, one alert is seeded and, once the scanner has
escalated it (assigned to `wam-e2e-sla-notify`), the entry
`sla:sla.escalated:alert:<alertId>:wam-e2e-notify-sla:A` reaches `sent` with
`delivery.statusCode` 200 and the receiver holds the signed `sla.escalated`
payload with `escalation` and `alert`. `afterAll` restores the previous
notification settings first (so the closes below enqueue nothing), restores
the SLA policy, deletes the rule and the Notifications config, closes the
case and every alert the run seeded or the rule / escalation assigned, and
stops the receiver. Outbox entries of the run stay (there is no delete API).
About 6 minutes. Like the SLA bench, every open unassigned high-band alert of
the stack is escalated while the 1-minute policy is in force (those alerts
are closed by `afterAll` too).

## Live automation bench (`automation_live.spec.ts`)

```bash
# 5.0 stack
source scripts/dev/env-5.0.sh
WAM_AUTOMATION_LIVE=1 WAM_E2E_MUTATING=1 WAM_LAB_DIR=lab/agent5 npx playwright test e2e/automation_live.spec.ts
# 4.14 stack (credentials from .env.e2e.local, no 5.0 exports in the shell)
WAM_AUTOMATION_LIVE=1 WAM_E2E_MUTATING=1 WAM_LAB_DIR=lab/agent npx playwright test e2e/automation_live.spec.ts
```

Phase 12 (PLAN.md 12.1 / 12.2): automation rules proven on **live device
data**. Nothing is seeded: every alert the rules act on comes from the
enrolled lab agent, whose events the bench produces by running the lab
generator over `vagrant ssh -c <WAM_LAB_GENERATE>` from `WAM_LAB_DIR`
(defaults: `lab/agent5` + `sudo WAM_LAB_SECOND_IP=10.0.2.78 bash
/lab4/generate.sh` on 5.0, `lab/agent` + `sudo bash /vagrant/generate.sh` on
4.x). Everything the bench does, it does by clicking the plugin UI, and every
assertion reads the UI; the only direct API calls are the three the step
allows, each marked `ALLOWED API CALL` in the spec: the alert snapshot before
any rule is enabled (`GET /alerts`, saved as `snapshot.json`) and its restore
(`POST /alerts/bulk-update`, only with `WAM_AUTOMATION_REVERT=1`), the
read-only `_count` cross-check behind scenario D (`indexerRequest`, so
`WAM_SEED_URL` / `WAM_SEED_PASSWORD` must point at the stack's indexer), and
the stdlib HTTPS receiver scenario G starts on this host (self-signed
certificate from `openssl`, `https://host.docker.internal:<WAM_E2E_WEBHOOK_PORT|18443>/automation`;
plain HTTP without openssl). The dashboard service must allowlist the
receiver host (`WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS=host.docker.internal`)
and carry `WAZUH_ALERT_MANAGER_ENCRYPTION_KEY`.

The line is detected from Settings > About (`reads wazuh-findings-v5-*` =
5.0). Line identifiers: 4.x uses the numeric rule ids / groups of the
preamble (`authentication_failed`, `sudo`, `5402`/`5301`, `audit_command`,
`syscheck`, srcip `10.0.2.77`); on 5.0 the groups are tags
(`attack.t1110`, `attack.t1548`, `wazuh-generic-1`, `wazuh-fim`, srcip
`10.0.2.78`) and the UUID rule ids are read live from the snapshot's
projected records (sudo = `attack.t1548` + process `sudo`; su = process `su`
+ srcuser `vagrant`; F's informational `wazuh-generic-1` ids), never
hard-coded (`WAM_AUTOMATION_SUDO_RULE_ID` / `_SU_RULE_ID` /
`_BENIGN_GROUP` / `_AGENT` override). The Assign-to select only offers the
security plugin's internal users, so the assignee is the first of
`WAM_AUTOMATION_ASSIGNEE`, `automation-test`, `wazuh-manager`, `admin` that
it lists; E uses a different one when possible, the first of
`WAM_AUTOMATION_ASSIGNEE_E`, `automation-test`, `admin`, `wazuh-manager`
(the 4.14 run passes `WAM_AUTOMATION_ASSIGNEE_E=wam-tester`).

Scenarios, in file order (default mode, one worker, each guarded on the
setup): `setup` (About, snapshot, identifiers; it refuses to run, before
writing anything, while `Automation test:` rules from an earlier run exist or
while another bench process still owns `.current-run.json`), `tasklist` (Settings >
Task lists: `Automation test: triage`, 3 tasks), `channel` (Settings >
Notifications: direct webhook `automation-test-webhook` with the
`rule.action` event, its Test button must read Delivered), `asset`
(Settings > Assets: the lab agent at criticality high, tag `lab`), `rule-A`
.. `rule-G` (each rule is created in the editor stage by stage, saved as a
draft, reopened, previewed with "Preview last 24 hours" — the count is read
from the preview panel — and enabled through "Enable after save"; D's count
is compared with the `_count`; E creates the high and the critical rule),
`H_lifecycle` (draft with "Never" in Last fired, the list's activation
switch opens the preview, enable, edit the match while switching the rule
off in the same save, Revisions shows 3, rollback to 1 makes 4 and the Match
pills revert, delete), `generator-1` (queue baseline, generator, wait until
the lab agent's last-hour queue grew and stayed stable), then the
assertions `A_per_alert_triage` (queue filtered on agent + assignee + In
progress, the alert flyout History shows `correlation-rule rule:<id>`, a
snapshot alert from before the enable is still Open and unassigned),
`B_burst_case` (Cases queue search: exactly one `<rule>: automated
incident`, Linked alerts >= 5, Tasks section with the 3 tasks, Overview 0 of
3 done; the search is repeated with the full title, colons included, and must
find the same case, the 12.2 cross-check of the 12.3 `cases.ts` phrase-prefix
fix), `C_cooccurrence_all` (one medium case), `D_min_level_band` (band
rows of the hour are In progress; because D is forward-only and the 4.x lab
agent produces band alerts naturally, the band is counted from the first
generator run on, `@timestamp:[<run 1 start> TO *]`; a low sudo alert carries
no in-progress rule entry), `E_asset_criticality` (sudo alerts assigned by E carry the
asset badge; no sudo alert is In progress, so the critical floor never
fired; the stamping lag is recorded), `F_auto_close_noise` (benign alerts
Closed with the False positive disposition in the queue, the flyout's
Closure reason row and History), `G_notify_only` (bounded: the line's sudo
rule id on the lab agent, `outbox sent >= 1` and `receiver POSTs >= 1`, see
below), `runtime` (Automation runtime card
values, every test rule enabled, Last fired column), `generator-2` (second
run inside B's 30-minute cooldown: still one B case), `revert` (skipped
unless `WAM_AUTOMATION_REVERT=1`).

Playwright restarts its worker after a failed test, so the bench persists its
state (`state.json`, pointer `runtime-evidence/automation-live/.current-run.json`)
after every scenario and restores it in `beforeAll`; a failure therefore costs
one scenario, not the rest of the run. Reruns: `WAM_AUTOMATION_KEEP_EXISTING=1`
accepts the `Automation test:` rules already on the stack, reuses
`snapshot.json`, merges the earlier `results.json` and brings the receiver back
(run with `--grep "setup: |<scenario id>: "`, the ids are the test-title
prefixes, so `A_per_alert_triage: ` re-runs the assertion and not `rule-A`);
`WAM_AUTOMATION_DEDUPE=1` enables the `dedupe` scenario that deletes duplicate
disabled drafts through the list (the rules API accepts duplicate names).
`WAM_AUTOMATION_SCENARIOS=G,generator-1` (step 12.3) runs only the listed
scenario ids after `setup` (a bare letter selects `rule-<letter>` and
`<letter>_...`; with `WAM_AUTOMATION_KEEP_EXISTING=1` an existing rule of that
letter is kept as saved and only asserted enabled, so the 4.14 rerun
`WAM_AUTOMATION_SCENARIOS=generator-1,A,B,C,D,E,F,G,runtime,generator-2` runs the
assertions on top of the rules the first attempt created). Only one bench may
run against a stack at a time: `setup` reads `.current-run.json` and refuses
while its runner pid is alive (a second run on 2026-11-22 overwrote the first
run's `snapshot.json` before that check existed). A failed generator run
writes its reason (message, exit status, signal, stderr, stdout) to the
scenario row and the partial output to `generator-run-<n>.log`. On a rerun the
receiver comes back on the transport the earlier `results.json` recorded, so it
answers the URL the saved channel carries (`WAM_E2E_WEBHOOK_TRANSPORT=http|https`
pins it explicitly; an `http://` channel from a shell without `openssl` would
otherwise fail every outbox row against an HTTPS receiver). A's forward-only check compares a pre-enable failed-auth alert with
the status / assignee the snapshot recorded (an open unassigned one is
preferred, not required: on 4.14 all of them were already closed and assigned by
the earlier lab benches), and the queue cell selectors accept both the 13.1
grid (`.wamAlertCell`) and the pre-13.1 table rows (`tr.wamAlertRow`) a stack
may still serve. Scenario G matches the line's sudo rule id on the
lab agent (a bounded group) and asserts `outbox sent >= 1` (read from the
Notifications outbox view) and `receiver POSTs >= 1` within
`WAM_AUTOMATION_NOTIFY_DRAIN_MS` (default 120 s; the outbox retries 30 s /
2 m / 10 m / 30 m / 1 h and G clicks Retry on dead rows). A scenario row in
`REPORT.md` carries the final attempt's message only. The receiver's certificate needs `openssl` on PATH (Node picks
the Windows build, so the spec passes its own minimal `-config`).

Nothing is reverted by default (owner decision): the rules stay enabled and
the cases, task list, channel binding and asset entry stay for inspection,
all named `Automation test:`. Evidence goes to `WAM_DOC_EVIDENCE_DIR`
(default `runtime-evidence/automation-live/<line>/`, ignored): a screenshot
per stage, `generator-run-<n>.log`, `snapshot.json`, `results.json` (per
scenario: pass/fail, reason, counts read from the UI, ids, wall time;
generator timestamps; defects) and `REPORT.md`, both rewritten after every
scenario. About 25-35 minutes, most of it the two generator runs and the
sync waits.

## Lab tour (`lab_setup.spec.ts`)

`WAM_E2E_LAB=1 WAM_E2E_MUTATING=1 npx playwright test e2e/lab_setup.spec.ts`
walks the plugin through the live lab of `lab/` (PLAN.md 9.3): the Vagrant
agent `wam-lab-agent` (9.1) and the MISP instance reachable from the
dashboard container as `https://misp.internal:8445` (9.2). It is a
configuration tour meant to be watched, not a bench: fourteen serial tests on
one browser page, each writing a numbered screenshot to
`runtime-evidence/browser/lab/NN-<name>.png` so the folder reads as a
walkthrough:

| # | file | what it shows |
|---|---|---|
| 01 | `01-signed-in.png` | the workbench after `signIn` |
| 02 | `02-settings-enrichment-start.png` | Settings > Enrichment before the lab sources exist (any previous `AbuseIPDB (lab)` / `MISP (lab)` source is removed first through the API) |
| 03 | `03-abuseipdb-source-editor.png`, `03-abuseipdb-source-saved.png` | the AbuseIPDB editor with the key field masked, then the saved row (`Configured`, enabled) |
| 04 | `04-abuseipdb-test-result.png` | the Test callout (`AbuseIPDB (lab): reachable`, verdict for the benign `8.8.8.8` probe) |
| 05 | `05-misp-source-editor.png`, `05-misp-source-saved.png` | the MISP editor (`https://misp.internal:8445`, ip / domain / hash, *Insecure transport (lab only)* on, key masked) and the saved row |
| 06 | `06-misp-test-result.png` | the MISP Test callout (`MISP (lab): reachable`, `unknown` for the probe value) |
| 07 | `07-settings-notifications.png` | Settings > Notifications exactly as configured (nothing is changed) |
| 08 | `08-queue-lab-agent.png` | the alert queue with `agent.name:"wam-lab-agent"` and *Last 24 hours* applied |
| 09 | `09-alert-overview-indicators.png` | one lab alert expanded, Overview with the Indicators block |
| 10 | `10-alert-enrichment-verdicts.png` | its Enrichment tab after *Lookup all*, with an `AbuseIPDB (lab)` and a `MISP (lab)` badge per indicator |
| 11 | `11-queue-selection.png`, `11-create-case-modal.png` | up to ten lab alerts selected and the *Create case from selected* modal (`Lab: wam-lab-agent activity`) |
| 12 | `12-case-indicators.png` | the case's Indicators section: aggregated indicators with the stored verdicts, then *Lookup all* |
| 13 | `13-case-attack-graph.png` | the case's Attack graph |
| 14 | `14-case-timeline.png` | the case's Timeline |

Headed, slowed down for a live demo:

```bash
WAM_E2E_LAB=1 WAM_E2E_MUTATING=1 WAM_E2E_SLOWMO=300 npx playwright test e2e/lab_setup.spec.ts --headed
```

`WAM_E2E_SLOWMO` (milliseconds between browser actions) is read by the spec
itself through `test.use({ launchOptions: { slowMo } })`; `playwright.config.ts`
is unchanged. The keys come from `.env.e2e.local` (`WAM_E2E_ABUSEIPDB_KEY`,
`WAM_E2E_MISP_KEY`); the spec types them into the key field and never prints,
asserts or captures them (the field is passed as `mask` to the screenshot),
and it sets `test.use({ trace: 'off', video: 'off' })` because the
`retain-on-failure` trace of `playwright.config.ts` would otherwise record the
typed keys in its `fill` action params.
The alert for steps 09-10 is picked through the plugin API: the newest lab
alert with a public `data.srcip` / `data.dstip`, else the newest one with a
syscheck hash (the stock 4.14 auditd decoder leaves `data.dstip` empty, see
`lab/README.md`, so on the current lab it is the `/etc/wam-lab-marker.conf`
checksum alert whose sha256 the MISP event holds). Test outcomes, the picked
alert and the verdict badges observed are recorded as annotations of the
Playwright report (`runtime-evidence/browser/report`).

Re-runnable: the previous run's `NN-*.png` captures are deleted first, the
two lab sources are deleted by name before they are created again, and an open
case titled `Lab: wam-lab-agent activity` is reused (found through
`GET /cases?q=title:"..."`; the *Create case from selected* modal is still
opened for `11-create-case-modal.png` and then cancelled; the selected alerts,
and the enriched alert of step 10, are linked to the case through the API when
missing). The lab sources are left in place afterwards: they are
the point of the tour. When the queue holds no lab alert in the last 24 h the
spec fails with the `vagrant ssh -c 'sudo bash /vagrant/generate.sh'` command
to run, unless `WAM_E2E_LAB_GENERATE=1` lets it run that itself and wait for
the projection. Needs the dashboard allow list to carry `api.abuseipdb.com`
and `misp.internal` and `WAZUH_ALERT_MANAGER_ENCRYPTION_KEY` to be set (both
written by `scripts/dev/e2e-deploy.sh`); an AbuseIPDB quota / auth failure is
recorded and the tour continues with MISP, any other Test failure (including
an egress refusal) fails the step with its message. About 2 minutes.

## Local stubs (`stubs/`)

`stubs/enrichment_stub.ts` starts a node HTTP server on `0.0.0.0` that answers
every GET with a fixed enrichment verdict; `trial_enrichment.spec.ts` points a
`generic_http` source at `http://host.docker.internal:<port>` (the host the
Docker dashboard reaches this machine through). The dashboard service needs
`WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS=host.docker.internal`, which
`scripts/dev/e2e-deploy.sh` writes into the stack's compose override; override
the hostname with `WAM_E2E_STUB_HOST` (and `WAM_EGRESS_ALLOWED_HOSTS` for the
deploy script). The override must keep a local suffix (`.internal`, `.local`,
`.home.arpa`): only an allowlisted local-suffix name may resolve to a private
address, every other allowlisted host still has to resolve publicly.
