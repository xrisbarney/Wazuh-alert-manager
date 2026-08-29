# 🚨 wazuhAlertManager

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22093124.svg)](https://doi.org/10.5281/zenodo.22093124)

An OpenSearch Dashboards plugin that turns Wazuh alerts into a small SOC
work desk: status workflow, comments, audit history, cross-alert linking,
case management with multi-alert bulk actions, dropdown-based filtering,
and optional AI-assisted analysis via OpenAI, DeepSeek, Gemini or Claude.

Release artifacts are built against official Wazuh Dashboard source for
**Wazuh 4.12–4.14**; the full browser bench runs on **Wazuh 4.14.7 / OSD
2.19.5**. See [SUPPORTED_VERSIONS.md](./SUPPORTED_VERSIONS.md) for the exact
version-to-artifact matrix.

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
  through a case) from the alert flyout's "Related Alerts" tab.
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
    sync_job.ts           copies wazuh-alerts-* into the v2 alert store on a timer
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
    egress/               AI egress allowlist projection (raw _source cannot cross)
    attack_graph.ts       entity/kill-chain/hop extraction from a case's alerts
  routes/
    alerts.ts             search/count/bulk-update/get/related/suggested/precedent
    comments.ts           comments + audit on an alert or a case
    cases.ts              case CRUD + linking alerts + attack-path
    filters.ts            dropdown option aggregations
    ai.ts                 AI settings + on-demand analysis generation
    users.ts              real dashboard users, for the assignee picker
    reports.ts            SLA / MTTA / MTTR metrics for a time period
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
server start. It never writes to Wazuh's native `wazuh-alerts-*` indices — those
are read-only evidence sources.

| Index | Purpose |
|---|---|
| `wazuh-alert-status-v2-*` | Operational projection of each alert (compact, explicit fields) plus workflow state: `status`, `case_id`, `assigned_to`, `related_alert_ids`, `ai_analysis`, and a `history` audit trail. Exposed through read/write aliases and numeric rollover generations (`-000001`, `-000002`, …). |
| `wazuh-alert-manager-v2-activity` | Comments and audit events, keyed by `alert_id` or `case_id` (read/write aliases + generations). |
| `wazuh-alert-manager-v2-cases` | Cases: title, description, severity, status, linked `alert_ids`, history. |
| `wazuh-alert-manager-v2-rules` | Automation (correlation) rules. |
| `wazuh-alert-manager-v2-meta` | Internal state: sync watermark, leader lock, lifecycle settings, AI settings, retirement records. |
| `wazuh-alert-manager-v2-migration` | Legacy v1 -> v2 migration progress/checkpoint. |
| `wazuh-alert-manager-v2-sync-dlq` | Dead-letter queue for alerts that fail to sync. |

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
in with automatic rollback on failure. It never modifies `wazuh-alerts-*`, never
deletes plugin data on upgrade, and fails closed on an unsupported dashboard
version.

```bash
# Latest compatible release
curl -fsSL https://github.com/xrisbarney/Wazuh-alert-manager/releases/latest/download/install.sh | sudo bash

# Pinned release (recommended)
curl -fsSL https://github.com/xrisbarney/Wazuh-alert-manager/releases/latest/download/install.sh | sudo bash -s -- --version 2.0.1

# Supply-chain-safe: download and verify the installer first
curl -fsSLO https://github.com/xrisbarney/Wazuh-alert-manager/releases/download/v2.0.1/install.sh
curl -fsSLO https://github.com/xrisbarney/Wazuh-alert-manager/releases/download/v2.0.1/install.sh.sha256
sha256sum -c install.sh.sha256
sudo bash install.sh --version 2.0.1
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
   sudo /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin install file:///path/to/wazuhAlertManager-2.19.5.zip --allow-root
   sudo systemctl start wazuh-dashboard
   ```

2. Open **Wazuh Dashboard → Wazuh Alert Manager**. On first start the
   plugin creates its indices and starts copying alerts automatically -
   there is nothing else to configure. Give it a minute (default sync
   interval is 60s) and alerts will start appearing with `status: open`.

3. (Optional) Configure AI analysis - see **AI analysis integration** below.

### Configuring the sync job

Defaults live in `server/config.ts` (`sync.enabled`, `sync.intervalSeconds`,
`sync.sourceIndexPattern`, `sync.initialLookbackMinutes`, `sync.batchSize`,
`sync.minRuleLevel`). These are meant to be overridable via
`opensearch_dashboards.yml` (e.g. `wazuhAlertManager.sync.intervalSeconds: 30`)
the standard OSD way - **but see the config-loading caveat below** before
relying on that on a Wazuh-packaged dashboard. If you hit it, change the
default in `server/config.ts` and rebuild instead.

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
  resolution time based on its rule level:

  | Severity | Rule level | Target |
  |---|---|---|
  | Critical | 12+ | 1 hour |
  | High | 7-11 | 4 hours |
  | Medium | 4-6 | 24 hours |
  | Low | 0-3 | 3 days |

  Compliance % = alerts resolved within their tier's target / all resolved
  alerts with a tracked SLA in the period. The breakdown table shows this
  per severity tier so you can see e.g. "Critical: 8/10 within SLA" rather
  than just one blended number.

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
git clone --branch v4.14.7 https://github.com/wazuh/wazuh-dashboard.git
cd wazuh-dashboard
git clone <this repo> plugins/wazuhAlertManager
yarn osd bootstrap
cd plugins/wazuhAlertManager
node scripts/set-target-version.js --osd-version 2.19.5   # already the checked-in default
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

Build a custom image:

```dockerfile
FROM wazuh/wazuh-dashboard:4.14.7

COPY wazuhAlertManager-2.19.5.zip /tmp/wazuhAlertManager.zip

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
  OpenSearch indices (`wazuh-alert-status`, `wazuh-alert-manager-meta`,
  etc.). No PVC is needed for this plugin specifically, and dashboard
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
*real* wazuh-dashboard source tree for all three supported versions
(4.12/2.19.1, 4.13/2.19.2, 4.14/2.19.5) - the same process documented
under **Building from source**, not just a relabeled manifest. Building
this way is the point: it catches real API incompatibilities between OSD
releases, not just a version-string mismatch.

- **Manual run**: use the "Run workflow" button on the Actions tab for a
  one-off build of all three versions (e.g. to sanity-check a branch)
  without cutting a release. Zips land as downloadable workflow artifacts.
- **Release**: push a tag matching `v*` to build all three versions and
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
- **"Suggest related alerts."** A lighter-weight cousin of the above: given
  an open alert, suggest other open/unlinked alerts sharing a host, user,
  or technique within a recent window, as one-click candidates for the
  existing "Related Alerts" linking feature - no new search algorithm
  needed, just a scoped query against data that already exists.
- **Configurable SLA policy.** The severity -> resolution-time targets in
  `server/routes/reports.ts` are currently a source-level constant; making
  them editable from AI Settings-style UI (with sane defaults) is on the
  list once there's a real need for per-deployment targets.
- **Saved/scheduled reports.** Exporting or emailing the Reports tab's
  metrics on a schedule, rather than only viewing them live.

None of these are started - this section exists so the project's
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
- The SLA policy (severity level -> resolution time target) is defined in
  `server/lib/reporting_fields.ts` - if you need different thresholds, that's
  currently a source edit + rebuild, not a UI setting.

## Disclaimer

This plugin is not officially supported by Wazuh.
