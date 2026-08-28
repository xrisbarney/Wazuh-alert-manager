# Roadmap

Planned work and design notes. Nothing here is shipped yet.

## Date-partitioned `wazuh-alert-status` with lifecycle retention (target: v1.6)

### Problem

`wazuh-alert-status` is today a **single, non-rolling** index that keeps a copy of
every synced alert plus its workflow state. Unlike Wazuh's own
`wazuh-alerts-4.x-*` (one index per day), it never rolls over or expires, so on
high-volume deployments it grows unbounded and can pressure disk/heap. Growth is
currently bounded only operationally (via `wazuhAlertManager.sync.minRuleLevel`).

### Design

Mirror Wazuh's own alert-index pattern — date-partitioned indices + wildcard
search + ISM age-delete:

1. **Partition on write.** The sync writes each alert's workflow document to
   `wazuh-alert-status-4.x-<YYYY.MM.DD>` derived from the alert's `@timestamp`,
   exactly like `wazuh-alerts-4.x-2026.08.24`. (Use weekly/monthly buckets on very
   large clusters to keep shard count sane.)
2. **Wildcard on read.** The plugin queries `wazuh-alert-status-4.x-*`. It already
   reads a wildcard today (`sync.sourceIndexPattern` = `wazuh-alerts-*`), so search
   semantics are unchanged.
3. **Route updates to the concrete index.** Changing an alert's status / assignee /
   case link must target the specific dated index the alert lives in (resolve by
   the alert's date, or search-then-update by `_id`).
4. **ISM retention.** Attach an index template to `wazuh-alert-status-4.x-*` plus an
   ISM policy that deletes whole old daily indices after `retentionDays`
   (configurable; **generous default**, e.g. 180–365 days). ISM is well-suited to
   small, per-day indices — unlike the current single index.
5. **Aged-out alerts are accepted as gone (design decision).** When an alert ages
   out of the status indices it is removed — full stop — including alerts linked to
   a case. A case keeps its own metadata, comments, history, and the alert-id
   references, but the *details* of an aged-out linked alert are no longer
   displayable. We deliberately do **not** snapshot alert data into cases;
   retention is by age and applies uniformly. (The raw event may still exist in
   Wazuh's own `wazuh-alerts-4.x-*` within Wazuh's retention, but the plugin does
   not re-fetch it.)
6. **Migration.** Reindex/cut over the existing single `wazuh-alert-status` into the
   dated scheme (or dual-read during a transition window).

### Retention behaviour (accepted trade-off)

Age-deleting a whole old day-index removes every alert in it — including any
still-**open** or **case-linked** alert. This is accepted: with a **generous
retention window** active work rarely lives past it, and an aged-out alert is
simply gone (a case retains its own record but not the aged-out alert's details).
Set `retentionDays` to your investigation horizon accordingly.

### Trade-offs

- Update routing is slightly more complex (resolve the dated index per update).
- More indices → more shards; bound with weekly/monthly buckets and/or `minRuleLevel`.
- One-time migration of the existing index.

### Scope — which owned indices this applies to

| Index | Retention treatment | Rationale |
|-------|--------------------|-----------|
| `wazuh-alert-status` | **Date-partition + ISM age-delete** (this plan) | Only index that scales with alert volume (a copy of alerts). |
| `wazuh-alert-manager-cases` | **No auto-delete** (optional archive/close-out only) | Durable investigation record + audit trail; low volume; the value to preserve. |
| `wazuh-alert-manager-comments` | None (optionally prune comments whose parent alert/case is gone) | Small; parent-tied. |
| `wazuh-alert-manager-rules` | None | Configuration; static; tiny. |
| `wazuh-alert-manager-meta` | None | Internal watermark/lock state; tiny. |

### TODO

- [ ] Add a `retentionDays` config knob (default generous; `0` = unlimited).
- [ ] Write the sync to date-named `wazuh-alert-status-4.x-<date>` indices.
- [ ] Switch reads to the `wazuh-alert-status-4.x-*` wildcard.
- [ ] Route per-alert updates to the concrete dated index.
- [ ] Provision an index template + ISM policy on `wazuh-alert-status-4.x-*`.
- [ ] Migration/cutover from the legacy single `wazuh-alert-status`.
- [ ] Confirm cases/comments/rules/meta are explicitly **excluded** from age-delete.
