# Security Model

This plugin handles security data, so it is deliberately conservative about identity, data at rest, and data egress.

## Identity & attribution

- The acting user is resolved **only** from the OpenSearch Security plugin — there is no request-header fallback that a client could spoof.
- When identity cannot be established, actions are attributed to an explicit **`anonymous`** state rather than a guessed user.
- Workflow changes write an activity/audit event with the actor and timestamp, alongside a bounded embedded history where the mutable alert or case record requires one. Automation activity uses deterministic identities so a retry cannot append the same event twice.

## Data isolation

- The plugin **never modifies** native Wazuh storage. Writes are allowed only to the exact prefixes `wazuh-alert-status-v2-` and `wazuh-alert-manager-v2-`, and the guard additionally refuses every native prefix **by name**, independent of the service account's privileges: `wazuh-alerts-`, `wazuh-archives-`, `wazuh-events-`, `wazuh-findings-`, `.ds-wazuh-`, `wazuh-states-`, `wazuh-monitoring-`, `wazuh-statistics-`, `wazuh-case-management-`, `wazuh-threatintel-`, `.wazuh-cti-`, `wazuh-active-responses`. It reads the alert/finding family its build targets and stores workflow state in its own indices (see [[Architecture]]).
- Native indices **outside** that family — `wazuh-states-*` for the asset chips and, on Wazuh 5.0, `wazuh-threatintel-enrichments*` for the local CTI source — are read through a dedicated read-only helper that refuses writes and reads as the **signed-in user** (`asCurrentUser`), so the role grant decides what an analyst sees and a 403 becomes a "no access" chip rather than an error. On 5.0 the native `wazuh.case.*` fields are projected read-only onto the record; the plugin has no write path to findings and never writes a native case back.
- Plugin-owned fields (`status`, `assigned_to`, `case_id`, history) are **protected on re-sync** — a same-named field arriving from Wazuh cannot clobber an analyst's decision.
- Case attachments live in the plugin-owned `wazuh-alert-manager-v2-attachments` index and never on disk. A file is capped at **2 MiB of decoded bytes** (the base64 length is not what is measured), a case holds at most **20** attachments, and only an allowlisted media type is accepted (`text/plain`, `text/csv`, `application/json`, `application/pdf`, `image/png`, `image/jpeg`, `application/zip`, `application/x-pcap`, `application/vnd.tcpdump.pcap`); the file name never decides the type. A write is refused with `503` while the index is not provisioned (it is never auto-created with a dynamic mapping). Bytes are stored base64-encoded in a field that is not indexed and leave the server only through the download route, which always answers `Content-Disposition: attachment` with a sanitised ASCII `filename` (extension kept, so a non-ASCII name such as `отчёт.pdf` still saves as `attachment.pdf`) plus an RFC 5987 `filename*` carrying the percent-encoded original name, the stored allowlisted `Content-Type`, `X-Content-Type-Options: nosniff` and `Cache-Control: no-store` — an uploaded file is never rendered inline on the dashboard origin. Link attachments accept http/https URLs without embedded credentials (internal hosts included, as the server never fetches them); every attachment carries its `case_id`, every route checks it against the path, and removal is limited to the author or an `all_access` administrator with `attachment_added` / `attachment_removed` audit events on the case.

<a name="secrets"></a>
## Secrets at rest

Every secret the plugin stores — the AI provider API key, each enrichment source's API key, and each direct webhook's HMAC secret — goes through the same path (`server/lib/plugin_settings.ts` + `crypto.ts`):

- It is encrypted with **AES-256-GCM** using a key derived from the `WAZUH_ALERT_MANAGER_ENCRYPTION_KEY` environment variable before it is written to the plugin's meta index. **Without that variable a secret cannot be saved at all** — the plugin refuses rather than storing plaintext.
- It is **never returned to the browser**, not even encrypted. A read replaces the secret with a sibling boolean (`<field>Configured`), so the UI can say "configured" without ever holding the value. Writing back `{ hasSecret: true }` is the keep-marker that leaves the stored secret untouched.
- It is decrypted in memory, server-side, only for the duration of the request that uses it.
- The variable is deliberately **not** a config-schema key, so it cannot end up in a copied or committed `opensearch_dashboards.yml`. Treat it like any other credential. Rotating it makes previously saved secrets undecryptable: they must be re-entered. A webhook secret that cannot be decrypted is retried an hour later rather than on the usual backoff table; each of those retries still consumes a delivery attempt, so the entry is dead-lettered after five.
- In a multi-replica deployment **every replica must be given the same value**, because a secret encrypted by one replica is decrypted by whichever replica later serves the request.

<a name="egress"></a>
## Outbound request policy

Enrichment lookups and direct webhooks are the only paths on which the dashboard server makes a request to something that is not the indexer. Both go through one policy (`server/lib/egress/url_policy.ts` + `http.ts`):

- **https only.** No `localhost` or `*.localhost`, no IP literals, no local-suffix names (`.local`, `.internal`, `.home.arpa`), no private or link-local ranges.
- **The resolved address is checked too**, so a public name that resolves to a private, loopback or link-local address is refused *before* the connection is made. (A DNS rebind *after* that lookup is a documented residual risk.)
- **No redirects are followed**, the response size is capped, and an abort timeout covers DNS as well as the transfer.
- `WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS` (an environment variable on the dashboard service, comma-separated hostnames) is the **one documented escape hatch**: a host named there may be a private or local-suffix receiver, which is how an on-premises webhook receiver or a lab MISP is reached. `localhost` and IP literals are never accepted, even on the allowlist.
- An enrichment source or webhook channel may additionally set **insecure transport** (skip certificate verification), and that flag is honoured **only** for an allowlisted local-suffix https host. It is a lab affordance, not a production one.
- The policy is enforced both when the settings are saved and again at send time. If the allowlist later changes so a stored URL no longer passes, that channel is read back as disabled with the reason rather than failing the whole settings document.
- Direct webhook deliveries are signed **HMAC-SHA256 over the raw body** in the `x-wam-signature` header when a secret is configured; see [[Notifications]] for the verification recipe. An unsigned webhook is allowed but says so in the UI.
- Delivery through an indexer **Notifications channel** makes no outbound request from the dashboard at all — the indexer owns that egress, and its own `host_deny_list` applies (it denies private hosts by default on 5.0).

<a name="ai-egress"></a>
## AI egress boundary

When [[AI Analysis]] is enabled, what leaves your network is tightly controlled:

- Only a **branded, allowlisted projection** of an alert can be sent to the provider. Passing a raw `_source` through the egress boundary is a **compile-time error**, not a runtime check — it cannot happen by accident.
- **Comment bodies are never sent** — only a count.
- Long free-text fields such as `full_log` are **truncated**.
- Nothing is sent unless AI analysis is explicitly enabled and a provider/key is configured.

## Automation & blast radius

- Automation administration is authorized only from the effective Wazuh/OpenSearch Security identity. Create, edit, preview, activation, rollback, deletion, queue settings, retry, and resolve require `all_access`; SSO/LDAP/OU labels are not trusted directly. See the [Wazuh user administration documentation](https://documentation.wazuh.com/current/user-manual/user-administration/index.html).
- The durable automation queue uses a fenced worker lease and deterministic execution identities, so replicas, retries, restarts, and lease loss cannot duplicate actions.
- Events retain the ruleset snapshot and exact rule revisions captured at ingestion. Queue resume and DLQ retry complete that ingestion-time work; they do not evaluate old alerts against current rules.
- Entity values are normalized before comparison and identity-key construction. Missing entities do not become an attacker-controlled `unknown` aggregation bucket.
- Case creation is deduplicated by the configured routing scope. Optimistic concurrency and deterministic keys prevent simultaneous threshold crossings from creating duplicates. Deduplication lookup errors defer/retry rather than being treated as "no case."
- Per-run action/case caps, execution rate limits, queue backlog/deferred caps, cooldown, and quiet-period rearm bound noisy rules. Preview exposes truncation, conflicts, missing entities, and cap/rate skips before activation.
- **Auto-close / auto-assign** act on attacker-influenceable fields. Scope Match and entity predicates carefully, preview the exact saved revision, and prefer a deduplicated case over silently closing when uncertain.

## Deliberately not included

**Active Response** (pushing commands back to agents) is intentionally not shipped in this release. It warrants a dedicated review of the command path and authorization model before it can be trusted.

## Recommended hardening

- Apply document-level security to the `wazuh-alert-status-v2-*` operational indices if you restrict who can see which alerts. Restrictions on native `wazuh-alerts-*` indices (or 5.0 findings streams) do **not** carry through the sync copy.
- Set `WAZUH_ALERT_MANAGER_ENCRYPTION_KEY` before anyone configures AI analysis, an enrichment source or a signed webhook (see **Secrets at rest** above), and give every dashboard replica the same value.
- Leave `WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS` unset unless you genuinely need a private receiver, and list only the exact hostnames you need.
- Grant `wazuh_alert_manager_native_read` to analyst groups rather than widening `all_access`, and do not map the reserved `alerting_full_access` to the dashboard user — the plugin's own `wazuh_alert_manager_notify` role is deliberately narrower.

## Who can do what

| Action | Required identity |
|---|---|
| Read alerts, cases, comments, timeline, indicators, reports, exports | any signed-in dashboard user (routes run as `asCurrentUser`, so index permissions still apply) |
| Change alert status/assignment/disposition, comment, create and edit cases, add and tick tasks, apply a task list, add attachments, run an enrichment lookup | any signed-in dashboard user |
| Delete an attachment | its author or a plugin administrator |
| Delete a case task | its author, the case assignee, or a plugin administrator |
| Automation rule create/edit/preview/activate/rollback/delete, queue settings, dead-letter retry and resolve | plugin administrator (effective `all_access`) |
| Edit the SLA policy and its escalations, enrichment sources, asset rules, notification channels, report schedules; start the SLA backfill; retry an outbox entry; read a full delivery error or the lease holder | plugin administrator |
| Lifecycle rollover, retirement, restore, purge | the effective Wazuh lifecycle role — see [[Lifecycle Retention and RBAC]] |

Identity comes only from the OpenSearch Security plugin. SSO, LDAP or organizational-unit names are not authorization inputs by themselves; map them to Wazuh user roles as described in the [Wazuh user administration documentation](https://documentation.wazuh.com/current/user-manual/user-administration/index.html). Non-administrators reading `GET /notifications/settings` receive a redacted summary with no URLs, headers or allowlists.

## Roles the trial features need

The trial features (enrichment, asset context, notifications) touch three things the base plugin never did: native Wazuh **asset-state** indices, the **threat-intel enrichment** index on Wazuh 5.0, and the indexer's **Alerting/Notifications** plugins for delivery. On Wazuh 5.0 the plugin additionally needs a grant to write **its own** two index families, because that line ships the dashboard's indexer user read-only on `wazuh-*`. On a stock install only `all_access` holds any of these, so `install.sh` applies the grants below when it has indexer admin credentials: on Wazuh 5.0 it reads the installer's `/etc/wazuh-indexer/export/credentials.env` by default; on Wazuh 4.x (where that file does not exist) pass `--indexer-admin-password` or set `WAZUH_INDEXER_ADMIN_PASSWORD`, or run `--grant-roles` with them later. The completion banner lists exactly which grants were applied and which were not; each grant has an opt-out flag. Every grant is read-only or delivery-only; the plugin still never writes to native Wazuh storage.

| Grant | Who needs it | What it allows | Installer |
|---|---|---|---|
| `wazuh_alert_manager_store` (new role: `indices_all` on `wazuh-alert-status-v2-*` and `wazuh-alert-manager-v2-*`, plus point-in-time and bulk) | The dashboard's indexer user, **Wazuh 5.0 only** | Lets the plugin write its own two index families at all — 5.0 ships that user read-only on `wazuh-*`. It grants nothing on any native Wazuh index | Created and mapped to the dashboard user. `--skip-store-role` |
| `wazuh_alert_manager_native_read` (new role: `read` on `wazuh-states-*`, `wazuh-threatintel-enrichments*`) | The dashboard's indexer user **and every analyst** who should see asset chips and local CTI verdicts | Read-only search of native inventory/SCA/vulnerability state and the 5.0 CTI enrichment index | Created and mapped to the dashboard user; **map it to your analyst groups yourself** (the installer prints the exact `rolesmapping` call). `--skip-native-read-role` |
| `wazuh_alert_manager_notify` (new role: cluster `cluster:admin/opendistro/alerting/monitor/execute`, `cluster:admin/opensearch/notifications/configs/get`, `cluster:admin/opensearch/notifications/feature/publish`; `read` on `wazuh-alert-manager-v2-notifications*`) | The dashboard's indexer user only | Lets the dispatcher execute an inline Alerting monitor whose action targets a Notifications channel: load the channel config, publish to it, and run the monitor's query on the outbox. It cannot create, list or modify monitors or channels, and holds no permission on any other index. The reserved `alerting_full_access` role is deliberately **not** used: it is cluster-wide alerting administration plus `indices_monitor`/aliases/mappings read on every index | Created and mapped to the dashboard user (verified on a 4.14.10 stack: delivery succeeds, monitor search and native index reads stay 403). `--skip-notification-role` |
| `notifications_read_access` (reserved role) | Analysts/admins who pick channels in the plugin's notification settings | Lists Notifications channels | **Not** granted by the installer; map it to the people who configure notifications |

Without the grants the plugin degrades rather than fails: asset and enrichment chips show "no access", and the dispatcher records a 403 as `last_error` and leaves notifications queued. The optional `wazuhCore` dependency (agent groups on 4.x) uses the Wazuh server API credential that plugin already holds and only from the background sync job, never on an analyst's behalf.
