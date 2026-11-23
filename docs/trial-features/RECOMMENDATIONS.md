# Incident-management recommendations (trial-features)

Reviewed 2026-11-20 against branch `3.0`. The plugin is strong on alert state,
cases, evidence and storage lifecycle. What it lacks is everything that happens
*around* a case: getting people's attention, structuring the response, and
getting data out. The code has no notifications, no export, no tasks or
task lists, no tags and no closure taxonomy.

Items marked **selected** are being built on the `trial-features` branch (see
[PLAN.md](PLAN.md)) in the order 6, 5, 3, 2, 1. Item 4 (multi-tenancy) is
dropped: most clients keep their own SIEM in house and the MSSP connects to it,
so a per-client model inside one dashboard is not needed.

## 1. Notifications and outbound integrations (selected)

Nothing leaves the plugin today except the optional AI call.

- Generic JSON webhook action on automation rules and on case events (created,
  assigned, severity raised, SLA breached). One generic webhook covers Slack,
  Teams, Shuffle, n8n, PagerDuty and ticketing with no per-vendor code.
- Email through SMTP settings guarded by the same egress policy as AI.
- Reuse the `egress/` URL allowlist so webhooks get the same "no raw document,
  allowlisted projection" boundary as AI.

## 2. Response structure inside a case (selected)

Cases are a bag of alerts plus comments. Incident management needs a shape.

- Task checklist per case: title, owner, due, done, with an audit event per
  change.
- Task list templates: a named list of tasks applied when a case opens,
  selectable manually or by an automation rule.
- Case timeline merging alert timestamps, status changes, comments and task
  completions into one chronological view.
- Closure reason and disposition (true positive, false positive, benign,
  duplicate) with an optional root-cause note. Reporting then gets a
  false-positive rate per rule.

## 3. SLA enforcement, not just SLA measurement (selected)

- SLA clocks on open alerts and cases with a "due in" column, breach badges and
  sorting by time remaining.
- Escalation rules: when an alert or case passes N% of its SLA unassigned or
  untouched, reassign, raise severity, or fire a webhook. A third trigger type
  next to immediate and burst.
- Configurable SLA targets per severity instead of the fixed table.

## 4. Multi-tenancy for MSSPs (dropped)

- Tenant/client tag on alerts and cases, per-tenant reporting, SLA targets and
  automation scoping. Not needed for the current target users.

## 5. Evidence and reporting output (selected)

- Case export: Markdown and PDF incident report with summary, timeline, linked
  alerts, graph image and comments.
- CSV export of any filtered alert or case list.
- Attachments on cases: links and small files with size caps, stored in a
  plugin-owned index.
- Scheduled reports: weekly SLA and workload report delivered through the
  webhook/email path.

## 6. Enrichment and context (selected)

- Pluggable enrichment on IP, hash and domain against configurable sources
  (MISP, OpenCTI, AbuseIPDB, generic HTTP) with allowlisted egress and caching,
  surfaced in the flyout and usable as an automation predicate.
- Asset context: criticality tags on hosts, severity bumps when a critical
  asset is involved.
- Observable extraction into a per-case indicators list.

## 7. Ingestion resilience (not selected)

- Wazuh active response as a gated, audited, opt-in action with per-command
  allowlists and an approval step.
- Alert suppression and deduplication windows separate from auto-close.
- Bulk reassign and bulk comment on cases.

## 8. Operations hardening (not selected)

- Health endpoint for probes and a Prometheus-style metrics route: sync lag,
  queue depth, DLQ size, SLA breaches.
- Per-user activity audit export.
- Role granularity below `all_access`: read-only reporting role, analyst role
  that cannot change rules.

## If only three

Webhooks, task checklists with task lists, and closure dispositions with a
false-positive rate in reporting. Those turn a triage queue into incident
management and reuse the rule engine, activity index and reporting already
present.
