# 🚨 wazuhAlertManager

An OpenSearch Dashboards plugin that turns Wazuh alerts into a small SOC
work desk: status workflow, comments, audit history, cross-alert linking,
case management with multi-alert bulk actions, dropdown-based filtering,
and optional AI-assisted analysis via OpenAI, DeepSeek, Gemini or Claude.

Built and tested against **Wazuh 4.14.7 / wazuh-dashboard 2.19.5**. See
[SUPPORTED_VERSIONS.md](./SUPPORTED_VERSIONS.md) for how to retarget a
different dashboard version.

---

## What's new since v1.0.1

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
  link back to the case they belong to.
- **Cross-alert linking**: relate alerts to each other directly (not just
  through a case) from the alert flyout's "Related Alerts" tab.
- **Full-screen flyouts**: the alert and case detail panels have an
  expand toggle in the header (top-right) to go full width when you need
  the room - e.g. reading the raw JSON or a long AI analysis.
- **Reporting**: a "Reports" tab computes mean time to assign, mean time
  to resolve, and SLA compliance (by a severity-based target) for a
  selected time period, with a per-severity breakdown table. See
  **Reporting & SLA metrics** below for the methodology.
- **AI-assisted analysis**: configure an API key for OpenAI, DeepSeek,
  Gemini, or Anthropic Claude under the "AI Settings" tab, then generate
  a summary/severity assessment/next-steps writeup from an alert's
  "AI Analysis" tab. The key is encrypted at rest (AES-256-GCM) with a
  key you supply via an environment variable, and is never sent to the
  browser - see **AI analysis integration** below before using this.
- **A nav icon**: the plugin has its own logo in the side navigation
  instead of the default generic icon (`public/assets/logo.svg`).
- Real server-side routes with request validation, replacing the
  original's direct browser -> `/api/console/proxy` calls (see
  **Security note** below).

---

## Architecture

```
common/                 shared TypeScript types + constants (index names, statuses...)
server/
  config.ts             plugin config schema (sync interval, lookback, etc.)
  plugin.ts             provisions indices + starts the background sync job on start()
  lib/
    mappings.ts          index mappings this plugin owns
    provision.ts         idempotent "create index if missing"
    sync_job.ts           copies wazuh-alerts-* into wazuh-alert-status on a timer
    history.ts            shared painless snippet for audit-trail append
    opensearch.ts          best-effort "who is the logged in user" lookup
    ai_providers.ts         one function per AI provider's HTTP API
  routes/
    alerts.ts             search/count/bulk-update (status/case/assignee)/get/related-alerts
    comments.ts            comments on an alert or a case
    cases.ts                case CRUD + linking alerts to a case
    filters.ts              dropdown option aggregations (rule id/agent/type/assignee/level range)
    ai.ts                    AI settings + on-demand analysis generation
    users.ts                 real dashboard users, for the assignee picker
    reports.ts                SLA / MTTA / MTTR metrics for a time period
public/
  assets/logo.svg         side-nav icon
  services/api.ts         typed HTTP client for all of the above
  components/             one component per concern (filter bar, bulk actions,
                          alert/case flyouts, comments thread, AI panels,
                          assignee picker, reports view, ...)
```

### Data model

Four indices, all auto-created on first server start:

| Index | Purpose |
|---|---|
| `wazuh-alert-status` | One doc per alert copied from `wazuh-alerts-*`, plus `status`, `case_id`, `assigned_to`, `related_alert_ids`, `ai_analysis`, and a `history` audit trail. |
| `wazuh-alert-manager-comments` | Comments, keyed by `alert_id` or `case_id`. |
| `wazuh-alert-manager-cases` | Cases: title, description, severity, status, linked `alert_ids`, history. |
| `wazuh-alert-manager-meta` | Small internal state: the sync job's watermark, and the AI provider settings doc. |

The background sync job (`server/lib/sync_job.ts`) copies new alerts using
a **scripted partial-update upsert**, not a full-document reindex - so a
status change, comment, or case link you've already recorded on an alert
is never clobbered if that alert's timestamp falls into a later sync
window.

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

1. Install the plugin zip:

   ```bash
   sudo systemctl stop wazuh-dashboard
   sudo /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin remove wazuhAlertManager --allow-root   # if upgrading
   sudo /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin install file:///path/to/wazuhAlertManager-1.2.0.zip --allow-root
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

### Building from source

This plugin follows the standard OpenSearch Dashboards plugin layout and
must be built from inside a `wazuh-dashboard` checkout:

```bash
git clone --branch 4.14.9 https://github.com/wazuh/wazuh-dashboard.git
cd wazuh-dashboard
git clone <this repo> plugins/wazuhAlertManager
yarn osd bootstrap
cd plugins/wazuhAlertManager
node scripts/set-target-version.js --osd-version 2.19.5   # already the checked-in default
yarn build
```

The zip is written to `plugins/wazuhAlertManager/build/`.

To target a different Wazuh/dashboard release, see
[SUPPORTED_VERSIONS.md](./SUPPORTED_VERSIONS.md).

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
- Reporting samples up to 5000 matching alerts per request (`size` query
  param) rather than scanning unboundedly; the response's `truncated` flag
  and `sampledAlerts`/`totalAlerts` counts tell you when a period's figures
  are based on a sample. Narrow the time range for exact numbers on very
  high-volume periods.
- The SLA policy (severity level -> resolution time target) is hardcoded
  in `server/routes/reports.ts` - if you need different thresholds, that's
  currently a source edit + rebuild, not a UI setting.

## Disclaimer

This plugin is not officially supported by Wazuh.
