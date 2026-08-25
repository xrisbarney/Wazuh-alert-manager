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

- Rules run under a **leader lock** (single writer) inside the sync tick, so there is no double-execution across replicas.
- Automatic case creation is **de-duplicated per rule + entity** and **rate-limited per pass**, so a noisy source cannot flood you with cases.
- **Auto-close / auto-assign** act on attacker-influenceable fields (source IP, user). Treat these like any detection content: scope the match conditions, and use **Dry run** before enabling. Prefer opening a case over silently closing when in doubt.

## Deliberately not included

**Active Response** (pushing commands back to agents) is intentionally not shipped in this release. It warrants a dedicated review of the command path and authorization model before it can be trusted.

## Recommended hardening

- Apply document-level security to `wazuh-alert-status` directly if you restrict who can see which alerts — restrictions on `wazuh-alerts-*` do **not** carry through the sync copy.
- Enable at-rest encryption for the stored AI key (see [[AI Analysis]]).
