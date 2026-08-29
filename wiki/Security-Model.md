# Security Model

This plugin handles security data, so it is deliberately conservative about identity, data at rest, and data egress.

## Identity & attribution

- The acting user is resolved **only** from the OpenSearch Security plugin — there is no request-header fallback that a client could spoof.
- When identity cannot be established, actions are attributed to an explicit **`anonymous`** state rather than a guessed user.
- Every workflow change (status, assignment, case link, automated rule action) is written to an append-only **history** with the actor and timestamp.

## Data isolation

- The plugin **never modifies** `wazuh-alerts-*`. It reads them and stores workflow state in its own indices (see [[Architecture]]).
- Plugin-owned fields (`status`, `assigned_to`, `case_id`, history) are **protected on re-sync** — a same-named field arriving from Wazuh cannot clobber an analyst's decision.

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

- Apply document-level security to the `wazuh-alert-status-v2-*` operational indices if you restrict who can see which alerts. Restrictions on native `wazuh-alerts-*` indices do **not** carry through the sync copy.
- Enable at-rest encryption for the stored AI key (see [[AI Analysis]]).
