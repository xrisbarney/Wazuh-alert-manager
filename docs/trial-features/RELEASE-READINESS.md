# Release readiness: v3.0.0-rc.1 (PLAN.md step 14.2)

Gate run 2026-11-23 (local), branch `trial-features`, working tree uncommitted.
This is the **trimmed** gate the owner approved on 2026-11-22 21:35 ("go for
trimmed gate"); section 6 names exactly what the trim did not re-prove.

Everything below was run from the repository root. Result lines are copied
verbatim from the command output.

## 1. Build and type gate

| # | Command | Result line | Verdict |
|---|---|---|---|
| 1 | `bash scripts/dev/test.sh` (full Jest, dev image `wam-dev:4.14.10`) | `Test Suites: 126 passed, 126 total` / `Tests: 1678 passed, 1678 total` (209.468 s) | PASS |
| 2 | `bash scripts/dev/tsc.sh` | `tsc: plugin type errors found (67)` - the recorded 67-diagnostic baseline, unchanged; none in a file this step touched (`e2e/` is outside `tsconfig.json`: 0 diagnostics) | PASS (baseline) |
| 3 | `bash scripts/dev/build.sh` (OSD 2.19.6) | `info compressing plugin into [wazuhAlertManager-2.19.6.zip]` / `Done in 38.47s.` / `build/wazuhAlertManager-2.19.6.zip` 2 516 895 B | PASS |
| 4 | `source scripts/dev/env-5.0.sh && bash scripts/dev/build.sh` (OSD 3.6.0) | `Done in 29.67s.` / `build/wazuhAlertManager-3.6.0.zip` 2 457 364 B | PASS |
| 5 | `bash scripts/dev/build.sh` (2.19.6, rebuilt - see note) | `Done in 73.02s.` / `build/wazuhAlertManager-2.19.6.zip` 2 516 883 B | PASS |

Note on #5: `yarn build` (plugin-helpers) **empties `build/` first**, so the
3.6.0 build of #4 deleted the 2.19.6 zip of #3. The 2.19.6 zip was rebuilt
immediately before its deploy. `scripts/dev/build.sh` now copies each zip into
`build-archive/` (a gitignored sibling of `build/`, which `yarn build` deletes
wholesale) right after producing it, so a two-line run keeps both artifacts;
its header still says each line must be built immediately before its own
deploy, because the deploy reads `build/<name>.zip`. Both builds restore `package.json`, `opensearch_dashboards.json`
and `common/build_info.ts` afterwards, verified: the tree still reads
`PLUGIN_VERSION 3.0.0-rc.1`, `TARGET_OSD_VERSION 2.19.6`.

## 2. Deployed builds

| Stack | Dashboard | Image | `GET /system/version` | Agents enrolled |
|---|---|---|---|---|
| Wazuh 4.14.10 / OSD 2.19.6 | https://localhost:8443 | `wam-e2e-dashboard:dev` | `pluginVersion 3.0.0-rc.1`, **buildId `3.0.0-rc.1-20261122233426620-unknown`**, `targetOsdVersion 2.19.6`, `targetWazuhVersion 4.14.10` | `000 wazuh.manager` (server/local), `001 wam-lab-agent` Active, `002 cyberwarrior` Disconnected (`agent_control -l`) |
| Wazuh 5.0.0-rc2 / OSD 3.6.0 | https://localhost:8444 | `wam-e2e-dashboard:5.0` | `pluginVersion 3.0.0-rc.1`, **buildId `3.0.0-rc.1-20261122232802464-unknown`**, `targetOsdVersion 3.6.0`, `targetWazuhVersion 5.0.0-rc2`, `targetWazuhMajor 5` | `001 wam-lab-agent-5`, `002 CYBERWARRIOR` (read from `wazuh-states-inventory-system`; the 5.0 manager image has no `/var/ossec/bin/agent_control`) |

Both deploys are gate commands in their own right; they ran interleaved with
the builds of section 1 (each line was deployed immediately after its own
build, because `yarn build` empties `build/`):

| # | Command | Ran after | Result line | Verdict |
|---|---|---|---|---|
| 6 | `source scripts/dev/env-5.0.sh && bash scripts/dev/e2e-deploy.sh` | build #4 | `dashboard ready at https://localhost:8444 (6x5s)` | PASS |
| 7 | `bash scripts/dev/e2e-deploy.sh` | build #5 | `dashboard ready at https://localhost:8443 (9x5s)` | PASS |

`scripts/dev/e2e-deploy.sh` recreates only the `wazuh.dashboard` service of each
stack. The 5.0 manager and indexer containers were **not** restarted (uptime
unbroken), no `docker prune` was run, and both lab VMs, the MISP containers and
the (already exited) `wam-tunnel` container were left alone.

## 3. Playwright benches

| # | Stack | Command | Result line | Verdict |
|---|---|---|---|---|
| 8 | 5.0 | `source scripts/dev/env-5.0.sh && npx playwright test e2e/smoke.spec.ts` | `2 passed (59.2s)` | PASS |
| 9 | 5.0 | `... WAM_E2E_MUTATING=1 WAM_E2E_PROFILE=wazuh5 npx playwright test e2e/full_ui.spec.ts` | `1 skipped` / `7 passed (5.7m)` | PASS |
| 10 | 4.14 | `npx playwright test e2e/smoke.spec.ts` | `2 passed (1.1m)` | PASS |
| 11 | 4.14 | `WAM_E2E_MUTATING=1 npx playwright test e2e/full_ui.spec.ts` | `1 skipped` / `7 passed (5.6m)`, `WAM_E2E_AUTOMATION_OUTCOME={"immediateAlerts":2,"burstCases":2,"burstAlerts":[3,3]}` | PASS |
| 12 | 4.14 | `WAM_E2E_MUTATING=1 npx playwright test e2e/queue_layout.spec.ts` | `2 passed (41.9s)` (1280x800 and 1920x1080) | PASS |
| 13 | - | `bash scripts/dev/test.sh` re-run on the final tree (after the e2e / script fixes of section 7, including the review round) | `Test Suites: 126 passed, 126 total` / `Tests: 1678 passed, 1678 total` (201.867 s) | PASS |
| 14 | - | `bash scripts/dev/tsc.sh` re-run on the final tree | `tsc: plugin type errors found (67)` - the same baseline as #2; the review round touched only `e2e/`, `scripts/dev/`, `docs/` and `.gitignore`, none of them in `tsconfig.json` | PASS (baseline) |

The single `full_ui` skip on both stacks is the known, documented one: the first
test waits for the fixture rule a later test in the same file creates.

Benches 11 and 12 were re-run here rather than quoted from 13.3, because the
bundle this gate deployed carries a new build id (13.3 and 14.1 ran against
`3.0.0-rc.1-20261122225604601-unknown`).

Bench 9 is the **first ever run of `full_ui` against a Wazuh 5.0 stack**.

## 4. Wazuh 5.0 specific checks (v3 plan)

Read live from the 5.0 stack after the 3.6.0 deploy:

- **Findings adapter sync** - `GET /system/health`: `sync.source_family =
  wazuh5_findings`, cursor document `sync_state:wazuh5_findings`,
  `counts.alerts 1870` and rising, `dlq 0`. Bench 9 proved the whole ingest
  path end to end:
  `WAM_E2E_AUTOMATION_OUTCOME={"immediateAlerts":2,"burstCases":2,"burstAlerts":[3,3]}`
  - findings seeded into the plugin-owned `wazuh-findings-v5-wam-e2e` stream
  were projected, matched by automation rules and deduplicated into cases.
- **`source_state` ready** - meta document `source_state`: `status "ready"`,
  `family "wazuh5_findings"`, `pattern "wazuh-findings-v5-*"`, `mode "auto"`,
  `reason "auto selected wazuh5_findings for a Wazuh 5.0 build."`, probe
  `{indices 0, dataStreams 8, aliases 0, timestampMapped true}`.
- **Severity labels in the queue** - re-read **after** the section 5 cleanup
  (2026-11-23, `wazuh-alert-status-v2-*` on the 5.0 indexer; an earlier reading
  of the same sample was recorded here with `medium` and `informational`
  transposed). The 50 newest records: every one has `rule.level = null` and a
  `severity_label` - `medium` 23, `informational` 21, `low` 6. Over all 1876
  projected records: `medium` 917, `low` 840, `informational` 119, and **no
  `high`** - the only `high`-label records this stack ever held were the 8
  findings bench 9 seeded with `--severity high` (`e2e/seed_findings_v5.py`
  writes the label into `wazuh.rule.level`, `wazuh5_finding_adapter.ts` keeps it
  verbatim in `severity_label`), and the cleanup of section 5 deleted them along
  with the rest of the `wam-e2e-agent` data. Bench 9 therefore **did** exercise
  the `high` label end to end; this post-cleanup sample simply no longer
  contains those records. `alerts_view.tsx` renders them through
  `SeverityBadge label={severity_label}`.
- **`wazuh_cti_local` listed** - `GET /enrichment/settings` returns
  `wazuh_cti_local | kind wazuh_cti_local | enabled true | builtIn true` ahead
  of the configured `abuseipdb` source (the built-in source is injected only
  when `targetWazuhMajor === 5`).

## 5. Synthetic-data cleanup

`e2e/cleanup_synthetic.py` gained 5.0 support in this step: it now deletes the
plugin-owned test **data streams** `wazuh-findings-v5-wam-e2e` and
`wazuh-events-v5-wam-e2e` (`DELETE /_data_stream/<name>`, which drops their
backing `.ds-*` indices) next to the 4.x native index
`wazuh-alerts-4.x-wam-e2e`. It also deletes the test-owned index templates `wam-e2e-<stream>` that
`benchmark/bench.py` creates for those streams. The source deletion now happens
**before any id is read**, because a sync tick between the two re-projected the
synthetic alerts (observed on the first 5.0 run: `deleted
wazuh-alert-status-v2-*: 8` followed by a dry run that still counted 8), and an
`--apply` run now re-counts the synthetic status rows afterwards, retries once
and exits non-zero rather than leaving residue for a later dry run to find.
Credentials for the 5.0 run come from `scripts/dev/env-5.0.sh`, whose exported
`WAM_SEED_*` beat `.env.e2e.local`.

| Stack | Command | Final dry run | What remains |
|---|---|---|---|
| 5.0 | `source scripts/dev/env-5.0.sh && python -I -X utf8 e2e/cleanup_synthetic.py --apply` | every counter `0`; both test data streams `absent` | cases `Automation test: B burst case: automated incident`, `Automation test: C cooccurrence all: automated incident` and the human `test`; the 8 enabled `Automation test:` rules plus their revisions |
| 4.14 | `python -I -X utf8 e2e/cleanup_synthetic.py --apply` | every counter `0`; `wazuh-alerts-4.x-wam-e2e` `absent` | cases `Automation test: B burst case: automated incident`, four `Lab: wam-lab-agent activity`, the human `manual case` and `test`; the 8 enabled `Automation test:` rules plus `H lifecycle` |

The 4.14 apply lifted and restored the write block on the two retired
generations (`wazuh-alert-manager-v2-cases-000001`,
`wazuh-alert-manager-v2-evidence-000001`), both back to `200` blocked, and
cleared `case_id` on the 2 real-agent alerts the bench had linked to a deleted
e2e case. No `Automation test:` rule, case, task list, channel or asset entry
was deleted on either stack; no `Lab:` or human case was touched.

The review round added three things to the script after those runs (template
deletion, the post-delete residue re-count, and reading case existence from the
pre-alias singleton as well), so it was re-run against both live stacks to
exercise them:

| Stack | Command | Result |
|---|---|---|
| 5.0 | `source scripts/dev/env-5.0.sh && python -I -X utf8 e2e/cleanup_synthetic.py --apply` | `delete index template wam-e2e-wazuh-findings-v5-wam-e2e: 200`, `delete index template wam-e2e-wazuh-events-v5-wam-e2e: 200`, every delete counter `0`, `synthetic projected alerts remaining: 0`, exit `0`; cases remaining unchanged (the two `Automation test:` cases and the human `test`) |
| 4.14 | `python -I -X utf8 e2e/cleanup_synthetic.py` (dry run; nothing synthetic was left to delete) | both templates `absent`, every counter `0`, `real-agent alerts linked to synthetic cases (case_id to clear): 0 (of which case already missing: 0)` - the singleton-aware existence read flags no orphan on a stack holding 4 `Lab:` cases and 2 retired generations |

## 6. What this trimmed gate did NOT re-prove

The trim moved these benches off the gate. **CI does not run them**:
`.github/workflows/build-and-release.yml` runs `yarn build` + `yarn test` (Jest)
for each of the seven matrix entries and no Playwright at all. For each spec
below the newest green run is named; each ran against an older build id.

| Spec | Last green run | What it covers |
|---|---|---|
| `ui_layering.spec.ts` | Phase 11.3 (2026-11-22) | flyout / nav stacking and overlay order |
| `trial_case_structure.spec.ts` | Phase 11.3 | case tasks, task lists, attachments, timeline |
| `trial_export.spec.ts` | Phase 11.3 | queue CSV, case report, page export |
| `trial_enrichment.spec.ts` | Phase 11.3 | enrichment sources, lookups, indicators, asset chips |
| `trial_sla.spec.ts` | Phase 11.3 | SLA policy, due dates, escalation |
| `trial_notifications.spec.ts` | Phase 8.5 (2026-11-21) | channels, outbox, dispatcher, retries |
| `lifecycle.spec.ts`, `alert_retirement.spec.ts` | Phase 8.5 | rollover, retention, retirement / restore |
| `wiki_screenshots.spec.ts` | Phase 13.3 | documentation captures (not a product gate) |
| `automation_live.spec.ts` | Phase 12 (both lines) | automation rules on live device data |
| `seed_check.spec.ts` | Phase 0 environment | harness spec, not a product gate: asserts the seeder reached the indexer |
| `lab_setup.spec.ts` | Phase 9 lab tour | lab-provisioning spec, not a product gate: needs `WAM_E2E_LAB=1` + `WAM_E2E_MUTATING=1` and the live lab (VM + MISP + redeployed stack) |

Those 11 rows cover 12 specs (`lifecycle` and `alert_retirement` share one
row); with the 3 this gate ran (`smoke`, `full_ui`, `queue_layout`) they
account for all 15 `e2e/*.spec.ts` files in the repository
(`ls e2e/*.spec.ts`).

The product code behind them was not touched after their last green run except
by 13.1-13.3 (the queue grid, re-proven here by `full_ui` + `queue_layout`) and
14.1 (version strings and release plumbing only).

## 7. Open defects and standing caveats

### From Phase 12 (automation rules on live device data)

| # | Severity | Defect / caveat |
|---|---|---|
| 12-a | low (device data, not a plugin defect) | `C_cooccurrence_all` cannot pass on 4.x: the 4.x `su` decoder gives rule 5301 no `data.srcuser` / `data.dstuser` (11 of 11 such alerts in 24 h), so a co-occurrence keyed on `srcuser` never pairs the failed `su` with the sudo alerts. It passes on 5.0, where the same event carries `process.name su` + `srcuser vagrant`. |
| 12-b | low (coverage gap) | The **critical** severity band has never been exercised on either line; no lab fixture produces it. |
| 12-c | low (coverage gap) | On 5.0 the `D min level band` rule matches nothing **against live lab device data**: the numeric floor maps through `common/severity.ts` to the labels high/critical, and the 5.0 lab VM/agent produces only low / medium / informational. This is a property of the lab's event mix, not of the stack: the seeded `--severity high` findings of bench 9 projected with `severity_label = high` and were matched by that bench's rules (section 4). |
| 12-d | medium (unproven in production shape) | Notification delivery is proven only against the bench's local HTTP/HTTPS receiver. No real transport (Slack, Teams, email, a live indexer channel) has been exercised end to end. |
| 12-e | low | Asset-criticality lag: only records the sync projects **after** an asset entry is saved carry `asset.criticality`, so an asset-floor rule sees nothing already projected (~60 s, both lines). Documented in `wiki/Automation-Rules.md`. |
| 12-f | low | A rule that matched but acted on nothing still reads "Never" under Last fired. |
| 12-g | low | An entity-group edit still requires the rule to be disabled first. |
| 12-h | low | Duplicate rule names are accepted by the rules API. |
| 12-i | low (environment) | The Assign-to select lists only the security plugin's internal users of each stack; it is not a plugin user directory. |

### From Phase 13 (queue grid)

| # | Severity | Defect / caveat |
|---|---|---|
| 13-a | low (pre-existing, not introduced by 13.x) | `wiki_screenshots.spec.ts` reports the Phase 9 lab case as "not open" and skips `case-indicators.png` / `alert-enrichment.png`; the quoted-title case query finds nothing although an open `Lab: wam-lab-agent activity` case exists. |
| 13-b | low (flake) | One `full_ui` run failed the rule-wizard preview tab once under host load and passed on the rerun. |
| 13-c | low (cosmetic) | A 64-character hash still wraps in the case Indicators table at 1920 (carried from Phase 10). |

The three product defects 13.3 found (unclipped grid cell wrapper, three-line
Agent / IP cell, EUI default column width counting hidden columns) were **fixed**
in 13.1 / 13.2 code and are not open.

### Found and fixed by this gate

| Finding | Fix |
|---|---|
| `full_ui.spec.ts` could not seed a 5.0 **Docker** stack: the `WAM_E2E_PROFILE=wazuh5` branch hard-coded `vagrant ssh` into a `wazuh-vagrant` directory that does not exist here, and under `env-5.0.sh` (which exports `WAM_E2E_SEED=local`) the fallback would have seeded 4.x-shaped alerts into a native-prefix index on the 5.0 indexer. | The branch now calls the existing `seedFindingsV5()` helper of `e2e/helpers.ts`, which already honours `WAM_E2E_SEED=local` and falls back to `vagrant ssh` otherwise. |
| The same hazard was still reachable: `scripts/dev/env-5.0.sh` never exported `WAM_E2E_PROFILE`, so sourcing it and running `full_ui` fell through to the `WAM_E2E_SEED=local` branch and would have created the native-prefix index `wazuh-alerts-4.x-wam-e2e` on the 5.0 indexer (forbidden by AGENTS.md). The gate's 5.0 benches avoided it only because the variable was passed on the command line. | `env-5.0.sh` now exports `WAM_E2E_PROFILE=wazuh5` next to the other `WAM_E2E_*` values (it also gates `trial_enrichment.spec.ts`), and `emitAutomationFixtures()` now **throws** instead of seeding 4.x alerts when the run targets a 5.0 stack (`WAM_WAZUH_VERSION` starting with `5`, or `WAM_SEED_URL` on `:9201`) without that profile. |
| `cleanup_synthetic.py` deleted the projected alerts before the seeder's source index / stream, so a sync tick in between re-projected them. | The source deletion moved ahead of **the whole id snapshot**, so neither the status rows nor the side records (evidence, activity, automation queue, outbox - all keyed on the snapshotted id list) are taken while projection is still possible. The script now also **verifies its own result**: after the deletes it re-counts the synthetic agent's status rows, retries the delete once after 20 s if a tick already in flight re-projected anything, and exits non-zero if residue survives. |
| `cleanup_synthetic.py` read case existence only from `wazuh-alert-manager-v2-cases-*`, missing the pre-alias singleton `wazuh-alert-manager-v2-cases`. On a stack where `migrateCaseAliases()` has not completed, every real-agent alert linked to a case would have been classified an orphan and silently unlinked by `--apply`. | Existence is now read from both (`wazuh-alert-manager-v2-cases,wazuh-alert-manager-v2-cases-*`), and the orphan reset is skipped entirely when neither index resolves, so a pre-migration or mis-targeted stack clears nothing. |
| `cleanup_synthetic.py` deleted the 5.0 test data streams but left the test-owned index templates `wam-e2e-wazuh-findings-v5-wam-e2e` / `wam-e2e-wazuh-events-v5-wam-e2e` (created by `benchmark/bench.py#ensure_v5_stream`, priority 500) behind. | The stream loop now deletes the matching `_index_template` too (tolerating 404), and the module docstring lists it. |
| `scripts/dev/build.sh`: the two lines' builds silently overwrite each other, because `yarn build` empties `build/`. | The script now copies each zip (and its `.sha256`, when present) into `build-archive/` right after the build, so both lines' artifacts survive in one tree; `build-archive/` is gitignored. It is a **sibling** of `build/`, not `build/archive/`: `yarn build` deletes the whole `build/` directory, verified here with a marker file that did not survive a run. Deploys still read `build/<name>.zip`, so each line is still built immediately before its own deploy. |
| `e2e/__pycache__/` was untracked junk in `git status`. | Added to `.gitignore`. |

## 8. Owner steps left (nothing in this step was committed)

1. Review `git status` (289 entries when this step started: 129 modified, 158
   untracked, 1 added, 1 modified-and-staged) and the diff.
2. **One** signed commit, authored as `Chris Bassey <chrixsbassey@gmail.com>`,
   with a plain message and **no** attribution or `Co-Authored-By` lines.
3. `git tag -s v3.0.0-rc.1`
4. `git push --tags`. The tag build runs the seven-entry matrix and publishes a
   GitHub **pre-release** (`prerelease: ${{ contains(github.ref_name, '-') }}`,
   body from `RELEASE_NOTES_v3.0.0.md`).
5. Make the GHCR package public.
6. Tear down the tunnel - `docker rm wam-tunnel` (the container is already
   `Exited (0)`) - and remove the `wam-tester` user from the 4.14 stack's
   security internal users.

## 9. Verdict

**READY** - every command of the trimmed gate passed on both stacks against the
builds that will be tagged (Jest 1678/1678, tsc at its 67 baseline, both zips
built and deployed, 4 smoke/bench specs green per line, every 5.0-specific
check satisfied, both stacks cleaned back to human and `Automation test:` data),
and no open defect is above "medium: notification delivery proven only against
a local receiver", which the release notes already document as a known issue of
a pre-release.
