# Notifications

**Settings > Notifications** binds workbench events to delivery channels. Nothing is sent until an administrator enables notifications and binds at least one channel to at least one event. Channel bindings are stored in the plugin's meta index (document `notification_settings`); every event is queued in the **outbox** and delivered by a background dispatcher (see [Outbox and delivery semantics](#outbox-and-delivery-semantics)).

## Channel kinds

| Kind | What it is | When to use it |
|------|------------|----------------|
| **Notifications channel** (`indexer_channel`) | A channel of the indexer **Notifications** plugin: Slack, Microsoft Teams, chime, email, SNS or a webhook. Channel CRUD stays in the Notifications app (`/app/notifications-dashboards#/channels`); the plugin only stores the channel's `config_id`. Delivery runs an on-demand Alerting execution (an inline, never-persisted, disabled query-level monitor with one action that targets the channel). | The default. Reuses the channels, SMTP accounts and rate limits an operator already has; email is text only, no attachments. |
| **Direct webhook** (`webhook`) | A signed JSON `POST` from the dashboard server to a URL you provide, with optional extra headers. | Receivers that need a signature (SOAR, ticketing), sub-minute delivery, a private-LAN target on Wazuh 5.0, or an HTTPS endpoint the indexer JVM cannot trust. |

Every channel has an **id** (`^[a-z0-9][a-z0-9_-]{0,63}$`, unique; referenced by automation rules and SLA escalations), a name, an **enabled** switch and the list of **events** it receives. At most 50 channels can be configured.

## Events

| Event | Fired when | Goes to | Payload fields (besides the common ones) |
|-------|------------|---------|------------------------------------------|
| `case.created` | `POST /cases` succeeded (after the evidence linkage), or an automation rule opened a case (its `case_auto_created_evidence` activity event). | Channels bound to the event. | `case`, `actor` (the creator, or `automation`). |
| `case.assigned` | A case's assignee changed to a non-empty value: `PUT /cases/{id}`, the bulk assign (each also when the request changes the status in the same body), or an SLA escalation's `assignTo`. A request that repeats the current assignee, or unassigns, fires nothing. | Channels bound to the event. | `case`, `actor`, `from` (previous assignee or null), `to`. |
| `case.severity_raised` | A case's severity moved to a **higher** band: `PUT /cases/{id}` or an SLA escalation's `raiseSeverity`. Lowering the severity fires nothing. | Channels bound to the event. | `case` (with the new severity and recomputed `sla_due_at`), `actor`, `from`, `to`. |
| `case.closed` | `POST /cases/{id}/close` closed the case (not on a re-close of an already closed case: its audit row carries `already_closed`), or an automation rule's case consolidation closed a duplicate case (disposition `duplicate`, actor `correlation-rule`). | Channels bound to the event. | `case` (with `closed_at` and `disposition`), `actor`, `to: closed`. |
| `sla.breached` | The SLA scanner stamped `sla.breached_at` on an alert or case whose due date passed (once per record), unless the due date passed more than `wazuh_alert_manager.sla.escalation.breachNotifyGraceMinutes` (default 1440 = 24 h; 0 = no cut-off) before the stamp: such a backlog record is stamped (badge, history, `sla_breached` activity) but not notified, and the server logs how many were skipped. One scan page (500 records) is enqueued in one bulk write. | Channels bound to the event. | `alert` **or** `case`, `actor: system:sla`, `message` (`SLA due <date> passed`). |
| `sla.escalated` | An SLA escalation wrote its marker on an alert or case (once per record and escalation). The case actions it applied also fire `case.assigned` / `case.severity_raised`. | The escalation's `notify` channel ids when the list is not empty, **else** the channels bound to the event. | `alert` or `case` (post-action state), `actor: system:sla`, `escalation {id, name}`, `message` (the actions applied, e.g. `assigned to tier-2; severity raised medium -> high; comment added`). |
| `rule.action` | An automation rule with a `notify` action matches an alert (step 1.4). | The rule action's channel ids. | `alert`, `rule {id, name}`. |
| `report.scheduled` | A schedule rendered successfully (the scheduler's slot or an administrator's **Run now**); a failed render sends nothing. | The schedule's `channelIds`. | `report {id, name, slot, link, markdown}` where `markdown` is the rendered summary cut on a UTF-8 boundary at 24 KiB (under the 28 KB Microsoft Teams incoming-webhook limit, with room for the header lines) and `link` the `last-run.md` download of the full report; `actor` = `scheduler` or the administrator. For a Notifications channel the message body is the Markdown itself after the header lines. |

Explicit channel ids (an escalation's `notify`, a rule's `notify`, a schedule's `channelIds`) bypass the event binding but the channel must still exist and be **enabled** (and notifications globally enabled): unknown or disabled ids are logged by the dashboard server and skipped, never an error for the action that fired. Every notification is enqueued under a deterministic outbox id (`case:<event>:<caseId>:<key>:<channelId>`, `sla:<event>:<alert|case>:<recordId>:<escalationId|dueDate>:<channelId>`, `report:<scheduleId>:<slot>:<channelId>`), so a retried write, a second dashboard replica or a **Run now** of an already delivered slot never produces a second delivery. Enqueueing never fails the action that fired it: a failure to reach the outbox is logged (`wazuh-alert-manager notifications: ...`) and the case update, scan or render completes as usual.

Payloads are **allowlisted projections**, never a raw alert or case document: identifiers, title, status, severity band, assignee, timestamps, rule id and description, agent id and name, disposition, SLA due dates, plus event detail (actor, previous/new value, escalation or rule name) and a deep link into the workbench. The deep link is app-relative (`/app/wazuh-alert-manager?tab=cases&case=<id>`) unless `wazuh_alert_manager.notifications.dashboardUrl` (the public base URL of the dashboard, e.g. `https://soc.example.com`) is set in `opensearch_dashboards.yml`. The value must be an absolute `http`/`https` URL (the dashboard refuses to start otherwise) and must include `server.basePath` when one is configured, because `/app/wazuh-alert-manager` is appended to it as given.

**Egress allowlist changes after a save.** The policy (`WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS`) is enforced when the settings are saved and again by the sender at delivery time. If the allowlist is narrowed later, a stored direct webhook whose URL no longer passes is not an error on read: the settings still load, the other channels keep delivering, and that one channel is answered `enabled: false` with the reason in a read-only `invalid` field. The Notifications tab shows it as **Blocked by egress policy**; edit the URL or remove the channel, then save (a save that still contains the blocked URL is refused with 400).

## Roles

| Who | Needs |
|-----|-------|
| Administrator editing bindings (`PUT /notifications/settings`, test sends) | `all_access` (the plugin's administrator check). |
| Any signed-in user | May read the bindings (`GET /notifications/settings` answers `redacted: true` with each channel reduced to id, name, kind, enabled and events: no receiver URL, no extra headers, no egress allowlist). Administrators get the full masked document; webhook secrets are never returned to anyone, only `secretConfigured`. |
| The channel picker (`GET /notifications/channels`) | Lists `GET /_plugins/_notifications/configs` **as the signed-in user**, so it needs `notifications_read_access`. Without it the picker shows an empty state explaining the role and lets you paste a channel id. A 403 is never an error toast. |
| Test send through a Notifications channel | Runs **as you**: your account needs the alerting `cluster:admin/opendistro/alerting/monitor/execute` permission (the `wazuh_alert_manager_notify` role `install.sh` creates, or `alerting_full_access`). |
| The dispatcher (background delivery) | Runs as the dashboard service user, which `install.sh` maps to `wazuh_alert_manager_notify` (alerting `monitor/execute`, notifications `configs/get` + `feature/publish`, read on the outbox index). Opt out with `--skip-notification-role`; the dispatcher then records the 403 on every Notifications-channel delivery. |

## Notifications channels: things to check

- **Webhook channels and `Content-Type`.** The indexer sends a webhook channel's `header_params` verbatim. With an *empty* header map it sends `application/json`; with any header set and no explicit `Content-Type: application/json` it sends `text/plain`. The picker flags such channels (`missing_json_content_type`); add the header in the Notifications app.
- **Wazuh 5.0 placeholder channels.** A 5.0 indexer ships four disabled channels (`default_slack_channel`, `default_jira_channel`, `default_pagerduty_channel`, `default_shuffle_channel`) with placeholder URLs. The picker marks them `disabled_placeholder` on a 5.0 build; sending to a disabled channel is refused by the indexer ("The channel is muted"). Configure and enable them in the Notifications app first. This hint never appears on a 4.x build.
- **Wazuh 5.0 `host_deny_list`.** The 5.0 Notifications plugin refuses loopback, RFC 1918, CGNAT, link-local and ULA receivers by default. A private receiver therefore needs either a direct webhook (sent from the dashboard server, see below) or an operator override of the indexer's `host_deny_list` (the override *replaces* the default list). On 4.x the list ships empty.
- **TLS.** The indexer JVM truststore does not contain the Wazuh CA, so a Notifications webhook channel pointing at an HTTPS service signed by that CA fails with `certificate_unknown`; use a direct webhook or a publicly trusted certificate.
- **Email** is delivered text only, without attachments; SMTP credentials live in the indexer keystore, not in the plugin.

## Direct webhooks

The receiver URL goes through the same egress policy as enrichment sources: HTTPS, a public hostname (no `localhost`, no IP literals, no host that resolves to a private, loopback or link-local address), no embedded credentials, no redirects, 10-second deadline, 64 KiB response cap. `WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS` on the wazuh-dashboard service narrows egress to the listed hosts; listing a local-suffix name (`.internal`, `.local`, `.home.arpa`) is the documented way to reach a private receiver, and the channel's "Insecure transport (lab only)" switch is honoured only for listed hosts: plain http for any listed host, and an unverified (self-signed) certificate only for a listed local-suffix name. A public receiver always gets verified HTTPS.

Each delivery is a `POST` with `Content-Type: application/json` and these headers (operator headers may not override them):

| Header | Value |
|--------|-------|
| `x-wam-event` | The event name (`case.created`, ..., or `test`). |
| `x-wam-delivery` | A UUID per delivery (retries reuse it; use it for idempotency). |
| `x-wam-timestamp` | ISO-8601 time the request was signed. |
| `x-wam-signature` | `sha256=<hex>` where `<hex>` = HMAC-SHA256 over the string `"<x-wam-timestamp>.<raw request body>"` with the channel's secret. Absent when the channel has no secret (unsigned). |

The secret is encrypted at rest with `WAZUH_ALERT_MANAGER_ENCRYPTION_KEY` and never returned to the browser; the editor only shows "Configured", and "Clear saved secret" removes it. Up to 10 extra headers (`Name: value`) may be added; `Content-Type`, `Authorization` and the `x-wam-*` names are reserved.

### Verifying the signature

Recompute the HMAC over the **raw** body bytes (do not re-serialise the JSON), compare in constant time, and reject stale timestamps:

```python
import hmac, hashlib, time
from datetime import datetime, timezone

def verify(headers, raw_body: bytes, secret: str, max_skew_seconds=300) -> bool:
    ts = headers.get("x-wam-timestamp", "")
    sig = headers.get("x-wam-signature", "")
    if not sig.startswith("sha256="):
        return False
    signed_at = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    if abs(time.time() - signed_at) > max_skew_seconds:
        return False
    expected = hmac.new(secret.encode(), ts.encode() + b"." + raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig[len("sha256="):])
```

```js
// Node.js (Express with `express.raw({ type: 'application/json' })`)
const crypto = require('crypto');
function verify(req, secret, maxSkewSeconds = 300) {
  const ts = req.get('x-wam-timestamp') || '';
  const sig = req.get('x-wam-signature') || '';
  if (!sig.startsWith('sha256=')) return false;
  if (Math.abs(Date.now() - Date.parse(ts)) > maxSkewSeconds * 1000) return false;
  const expected = crypto.createHmac('sha256', secret).update(`${ts}.`).update(req.body).digest('hex');
  const given = Buffer.from(sig.slice('sha256='.length), 'hex');
  return given.length === 32 && crypto.timingSafeEqual(Buffer.from(expected, 'hex'), given);
}
```

Test vector: secret `secret`, timestamp `2026-01-01T00:00:00.000Z`, body `{"a":1}` signs as `sha256=` + `HMAC-SHA256("secret", "2026-01-01T00:00:00.000Z.{\"a\":1}")` in hex (the unit test `server/lib/notifications/transports.test.ts` pins it).

## Outbox and delivery semantics

Nothing is sent inline. An emitter (a case action, the SLA scanner, an automation rule's `notify` action, a scheduled report) writes **one outbox entry per bound channel** into the fixed index `wazuh-alert-manager-v2-notifications` and returns; the **dispatcher** delivers them in the background.

**Entry.** `id`, `event`, `channel_id` / `channel_kind`, `target_type` / `target_id` (the case, alert or report it is about), `subject`, the allowlisted `payload` (what is sent; never a raw document), `status`, `attempts`, `created_at`, `next_attempt_at`, `sent_at`, `last_error` (text), `last_status_code`, a `delivery` summary (transport, delivery id, status code, duration) and an optional `dedupe_key`. Entry ids are chosen by the emitter (the per-event formats listed under [Events](#events): `case:...`, `sla:...`, `report:...`, and `notify:<rule>:<alert>:<channel>` for rule actions) and written with `op_type: create`, so a repeated emit is a silent no-op: an event is never queued twice for the same channel.

**Status lifecycle.**

| Status | Meaning |
|--------|---------|
| `pending` | Queued; due at `next_attempt_at` (immediately when created). |
| `sending` | Claimed by a dispatcher replica. A claim older than 10 minutes (crashed replica) is reclaimed. |
| `sent` | Delivered: a 2xx from the direct webhook receiver, or a successful `delivery_status` from the Notifications channel. |
| `failed` | The attempt failed; retried at `next_attempt_at` with growing delays: **30 s, 2 min, 10 min, 30 min, 1 h** after attempts 1-4 (a webhook whose secret cannot be decrypted because `WAZUH_ALERT_MANAGER_ENCRYPTION_KEY` is missing is retried after 1 h instead, so a missing key never produces a retry storm; a transient failure to *read* the secret consumes no attempt: the claim is left `sending` and reclaimed as stale). |
| `dead` | Given up after **5 attempts**, or the channel was removed or disabled (the reason is in `last_error`). Administrators can retry a dead or failed entry from the panel or `POST /notifications/outbox/{id}/retry`: it becomes `pending`, due now, with its attempt count kept, so a persistent failure is dead again after one more attempt. |

A **403** from either transport (the dashboard service user lacks the alerting `monitor/execute` grant, or the Notifications channel refuses it) is recorded verbatim in `last_error` with the hint `map role wazuh_alert_manager_notify to the dashboard user` and counts as an attempt.

**Dispatcher.** Runs on every dashboard replica but only the holder of the `notification_dispatcher` lease (meta index, TTL = max(3 x tick, 30 s)) delivers; the tick is `wazuh_alert_manager.notifications.dispatcher.tickSeconds` (default 5, range 1-300) and `...dispatcher.enabled: false` turns the loop off on a replica. Each tick claims up to 50 due entries (optimistic concurrency per entry), resolves the channel from the cached settings (30 s), sends through the direct webhook (`boundedFetch`, HMAC signature) or the inline Alerting `_execute` targeting the Notifications channel, and records the outcome. While notifications are globally disabled (**Enable notifications** off) nothing is claimed: entries stay `pending` until an administrator enables them. The lease is renewed every 5 deliveries (and whenever a third of the TTL has elapsed), so a batch of slow receivers never outlasts it; if another replica has taken the lease meanwhile, the holder stops, puts its undelivered claims back to `pending` (due now, no attempt counted) and leaves the status doc to the new holder. The last tick's summary (`claimed`, `sent`, `failed`, `dead`, last ten errors) is in the meta doc `notification_dispatcher_status`; an idle tick (nothing claimed, no errors) rewrites it at most once a minute.

**Panel and routes.** Settings > Notifications shows the **Delivery outbox** to every signed-in user: counts by status, the last tick, the entries with event, channel, a link to the target, attempts, status and the last error, a status filter, "Load more" and (administrators) **Retry**; it refreshes every 15 s while the tab is open (keeping the pages loaded with "Load more"). What non-administrators see follows the settings contract above: no lease holder (`holder`, `claimed_by`), no dispatcher error texts, and each entry's `last_error` reduced to `Delivery failed (HTTP <code>); an administrator can read the recorded error.` (plus the role hint of a 403), because the recorded text names the receiver host, the egress-policy reason or up to 200 bytes of the receiver's answer. Administrators get everything verbatim. Routes: `GET /notifications/outbox?status=&channelId=&event=&cursor=&limit=` (any user; the payload is not listed; redacted as above for non-administrators), `GET /notifications/outbox/{id}` (administrators; includes the payload), `POST /notifications/outbox/{id}/retry` (administrators; audited as `notification_retried`), `GET /notifications/status` (dispatcher status, this replica's `enabled` / `tickSeconds`, counts by status; `holder` and `errors` only for administrators).

## Test sends

The **Test** button on a saved channel sends a fixed payload (`event: "test"`, no case or alert) through the channel as the signed-in user and shows **Delivered** or **Failed** with the receiver's HTTP status (direct webhook) or the channel's delivery status (Notifications channel, read from the inline Alerting execution). A failed test names the cause: egress policy, timeout, non-2xx answer, a missing `monitor/execute` grant, a muted 5.0 placeholder channel, or a missing encryption key (HTTP 409) for a webhook with a saved secret.

## Audit

Every save writes an activity event `notification_settings_updated` on `system/notification_settings` with a compact `from` / `to` summary (`enabled=<bool>;channels=<n>;<id>:<kind>[(off)],...`).
