# Troubleshooting

<a name="indexer-503"></a>
## Dashboard shows HTTP 503 / "failed to start wazuh-indexer"

**Symptom.** After a restart (especially an unclean shutdown, or on a smaller VM), the dashboard returns **503** and `systemctl status wazuh-indexer` shows `Active: failed (Result: timeout)`. The indexer log shows steady startup progress that simply gets cut off.

**Cause.** This is **stock Wazuh**, not the plugin. `wazuh-indexer` (OpenSearch) loads many plugins (ML, KNN, neural-search, …) on a modest heap and can take **longer than systemd's default 3-minute start timeout** to become ready. systemd then SIGTERMs it mid-boot.

**Fix — raise the start timeout:**

```bash
sudo mkdir -p /etc/systemd/system/wazuh-indexer.service.d
printf '[Service]\nTimeoutStartSec=900\n' | \
  sudo tee /etc/systemd/system/wazuh-indexer.service.d/override.conf
sudo systemctl daemon-reload
sudo systemctl start wazuh-indexer
```

Then wait for it to come up (watch the cluster health go **red → yellow**):

```bash
curl -sk -u admin:<password> https://localhost:9200/_cluster/health | jq .status
```

On a **single-node** cluster, **yellow is normal and healthy** (replicas have nowhere to go). Once the indexer is yellow/green, the dashboard clears its 503. In Kubernetes, raise the dashboard/indexer pod probe timeouts instead (see [[Installation#container-deployments-docker--kubernetes]]).

---

## "No API available" / Wazuh API connection error (dashboard-wide)

This is a Wazuh server-side issue, not the plugin — usually the `wazuh-manager` API daemon (e.g. `wazuh-modulesd`) is down. Restart the manager:

```bash
sudo systemctl restart wazuh-manager
```

---

## The plugin doesn't appear in the navigation

- Confirm it installed: `sudo /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin list`.
- The **first start after install** rebuilds browser bundles and can take several minutes — wait, then hard-refresh the browser.
- Check `wazuh-dashboard` is active and healthy: `sudo systemctl status wazuh-dashboard`.
- In a container, confirm the running image actually contains the plugin:
  `docker run --rm --entrypoint /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin <image> list`
  should print `wazuhAlertManager@2.0.3`. The prebuilt images under
  `ghcr.io/xrisbarney/wazuh-dashboard-alert-manager` do; a plain
  `wazuh/wazuh-dashboard` image does not. See [[Installation#container-deployments-docker--kubernetes]].

---

## Alerts stop syncing after a dashboard or VM restart

**Symptom.** Native `wazuh-alerts-*` indices continue receiving alerts, but the
newest alert in Wazuh Alert Manager remains fixed at the time of a restart. The
dashboard and indexer services may both report `active (running)`, while the
plugin's sync watermark never advances.

First check the services and the plugin version:

```bash
sudo systemctl --no-pager --full status \
  wazuh-dashboard wazuh-indexer wazuh-manager
sudo /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin list | \
  grep -i wazuhAlertManager
sudo cat \
  /usr/share/wazuh-dashboard/plugins/wazuhAlertManager/common/build_info.js
```

The background sync runs inside `wazuh-dashboard`; it does not have a separate
service or log file. Query its logs through the systemd journal:

```bash
# Current boot
sudo journalctl -u wazuh-dashboard -b --no-pager | \
  grep -iE 'wazuhAlertManager|wazuh-alert-manager|ResponseError'

# Across previous boots (adjust the date)
sudo journalctl -u wazuh-dashboard \
  --since '2026-08-28 00:00:00' --no-pager | \
  grep -iE 'failed to provision|wazuh-alert-manager sync|sync lock|ResponseError'
```

Related Wazuh logs are available through:

```bash
sudo journalctl -u wazuh-indexer -b --no-pager
sudo journalctl -u wazuh-manager -b --no-pager
sudo tail -n 200 /var/log/wazuh-indexer/wazuh-cluster.log
sudo tail -n 200 /var/ossec/logs/ossec.log
sudo journalctl -u filebeat -b --no-pager
```

In **Indexer management → Dev Tools**, compare the native and projected data
and inspect the sync control documents:

```http
GET wazuh-alerts-*/_search
{
  "size": 1,
  "sort": [{ "@timestamp": "desc" }],
  "_source": ["@timestamp", "agent.name", "rule.level"]
}

GET wazuh-alert-status-v2-read/_search
{
  "size": 1,
  "sort": [{ "@timestamp": "desc" }],
  "_source": ["@timestamp", "agent.name", "rule.level", "source_index"]
}

GET wazuh-alert-manager-v2-meta/_doc/sync_state
GET wazuh-alert-manager-v2-meta/_doc/sync_settings
GET wazuh-alert-manager-v2-meta/_doc/sync_lock
GET _cat/indices/wazuh-alerts-*,wazuh-alert-status-v2-*,wazuh-alert-manager-v2-*?v
GET _cat/aliases/wazuh-alert-status-v2-*?v
```

`sync_settings.enabled` should be `true`. A missing `sync_lock` is normally
harmless for no more than one polling interval because a running sync worker
recreates it. A missing lock combined with a frozen `sync_state.updated_at`
means the worker probably never started.

**Known early-v2 failure.** Some development builds labelled `2.0.0` queried
the `_id` metadata field with a prefix query during retirement recovery. On the
OpenSearch version shipped with Wazuh 4.14, startup then logs:

```text
wazuhAlertManager: failed to provision indices:
search_phase_execution_exception: [query_shard_exception]
Reason: Can only use prefix queries on keyword and text fields - not on [_id]
which is of type [_id]
```

The dashboard process remains healthy, but plugin initialization stops before
the lifecycle, automation, and sync workers are started. A restart exposes the
problem because initialization and retirement recovery run again; repeated VM
shutdowns do not themselves corrupt the watermark.

**Fix.** Install the current supported build (2.0.3; the installer selects the
archive for the dashboard's exact OpenSearch Dashboards version) and let it
restart the dashboard:

```bash
curl -fsSL \
  https://github.com/xrisbarney/Wazuh-alert-manager/releases/latest/download/install.sh | \
  sudo bash -s -- --version 2.0.3
```

For a container deployment, switch to the matching prebuilt image instead
(see [[Installation#container-deployments-docker--kubernetes]]).

Do not delete the sync state, reset its watermark, or manually create the lock.
The stored watermark is the safe resume point. After the upgrade, verify that
there is no new `failed to provision indices` message and query `sync_state`
again after one polling interval. Its `updated_at` and `completed_at` values
should advance. If the backlog exceeds the configured batch size, the plugin
persists a point-in-time cursor and continues draining batches immediately; the
native and projected newest timestamps should converge.

---

## Alerts stop syncing after a dashboard or VM restart

**Symptom.** Native `wazuh-alerts-*` indices continue receiving alerts, but the
newest alert in Wazuh Alert Manager remains fixed at the time of a restart. The
dashboard and indexer services may both report `active (running)`, while the
plugin's sync watermark never advances.

First check the services and the plugin version:

```bash
sudo systemctl --no-pager --full status \
  wazuh-dashboard wazuh-indexer wazuh-manager
sudo /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin list | \
  grep -i wazuhAlertManager
sudo cat \
  /usr/share/wazuh-dashboard/plugins/wazuhAlertManager/common/build_info.js
```

The background sync runs inside `wazuh-dashboard`; it does not have a separate
service or log file. Query its logs through the systemd journal:

```bash
# Current boot
sudo journalctl -u wazuh-dashboard -b --no-pager | \
  grep -iE 'wazuhAlertManager|wazuh-alert-manager|ResponseError'

# Across previous boots (adjust the date)
sudo journalctl -u wazuh-dashboard \
  --since '2026-08-28 00:00:00' --no-pager | \
  grep -iE 'failed to provision|wazuh-alert-manager sync|sync lock|ResponseError'
```

Related Wazuh logs are available through:

```bash
sudo journalctl -u wazuh-indexer -b --no-pager
sudo journalctl -u wazuh-manager -b --no-pager
sudo tail -n 200 /var/log/wazuh-indexer/wazuh-cluster.log
sudo tail -n 200 /var/ossec/logs/ossec.log
sudo journalctl -u filebeat -b --no-pager
```

In **Indexer management → Dev Tools**, compare the native and projected data
and inspect the sync control documents:

```http
GET wazuh-alerts-*/_search
{
  "size": 1,
  "sort": [{ "@timestamp": "desc" }],
  "_source": ["@timestamp", "agent.name", "rule.level"]
}

GET wazuh-alert-status-v2-read/_search
{
  "size": 1,
  "sort": [{ "@timestamp": "desc" }],
  "_source": ["@timestamp", "agent.name", "rule.level", "source_index"]
}

GET wazuh-alert-manager-v2-meta/_doc/sync_state
GET wazuh-alert-manager-v2-meta/_doc/sync_settings
GET wazuh-alert-manager-v2-meta/_doc/sync_lock
GET wazuh-alert-manager-v2-meta/_doc/source_state
GET _cat/indices/wazuh-alerts-*,wazuh-alert-status-v2-*,wazuh-alert-manager-v2-*?v
GET _cat/aliases/wazuh-alert-status-v2-*?v
```

On **Wazuh 5.0** the native source is the `wazuh-findings-v5-*` data streams
and the sync cursor document is `sync_state:wazuh5_findings`:

```http
GET wazuh-findings-v5-*/_search
{
  "size": 1,
  "sort": [{ "@timestamp": "desc" }],
  "_source": ["@timestamp", "wazuh.agent.name", "wazuh.rule.level", "wazuh.rule.title"]
}

GET wazuh-alert-manager-v2-meta/_doc/sync_state:wazuh5_findings
GET wazuh-alert-manager-v2-meta/_doc/source_state
GET _data_stream/wazuh-findings-v5-*
```

`source_state` records what the sync worker decided on its last tick:
`status` is `ready` (syncing), `waiting` (the expected source does not exist
yet, for example a fresh install before the first alert or finding), or
`blocked` (the configured `sync.sourceMode` or `sync.sourceIndexPattern` is
not valid for this build, or the pattern does not look like the expected
source). The `reason` field explains it, and Storage Health shows the same
information. The plugin never falls back to a different pattern; fix the
configuration or wait for Wazuh to create the source.

`sync_settings.enabled` should be `true`. A missing `sync_lock` is normally
harmless for no more than one polling interval because a running sync worker
recreates it. A missing lock combined with a frozen `sync_state.updated_at`
means the worker probably never started.

**Known early-v2 failure.** Some development builds labelled `2.0.0` queried
the `_id` metadata field with a prefix query during retirement recovery. On the
OpenSearch version shipped with Wazuh 4.14, startup then logs:

```text
wazuhAlertManager: failed to provision indices:
search_phase_execution_exception: [query_shard_exception]
Reason: Can only use prefix queries on keyword and text fields - not on [_id]
which is of type [_id]
```

The dashboard process remains healthy, but plugin initialization stops before
the lifecycle, automation, and sync workers are started. A restart exposes the
problem because initialization and retirement recovery run again; repeated VM
shutdowns do not themselves corrupt the watermark.

**Fix.** Install the current stable build (2.0.3; the installer picks the
artifact for the running dashboard's exact OpenSearch Dashboards version) and
let the installer restart the dashboard:

```bash
curl -fsSL \
  https://github.com/xrisbarney/Wazuh-alert-manager/releases/latest/download/install.sh | \
  sudo bash -s -- --version 2.0.3
```

Do not delete the sync state, reset its watermark, or manually create the lock.
The stored watermark is the safe resume point. After the upgrade, verify that
there is no new `failed to provision indices` message and query `sync_state`
again after one polling interval. Its `updated_at` and `completed_at` values
should advance. If the backlog exceeds the configured batch size, the plugin
persists a point-in-time cursor and continues draining batches immediately; the
native and projected newest timestamps should converge.

---

## Analyst/assignee metrics are empty

Current operational data is stored under the `wazuh-alert-status-v2-*` aliases and generations, where `assigned_to` is mapped as a keyword. Check system health and dashboard migration logs for a failed v2 provisioning or legacy migration step. Do not point the plugin at a native Wazuh index or broaden its managed write prefixes. Repair the failed v2 migration/provisioning issue before rebuilding an affected plugin-owned generation.

---

## A rule isn't firing

- Confirm the rule is enabled and the runtime badge says **Queue running**. A disabled rule and a paused queue are independent states.
- Preview the exact saved revision. Check matching totals, missing-entity count/rate, truncation, precondition skips, conflicts, and safety/rate-cap skips.
- Match owns agent scope. On Trigger, verify each AND predicate can resolve from the same alert and that at least one OR group can match. Missing values do not form an `unknown` group.
- Entity comparison is normalized: ports must be 0-65535, user/process values are lowercased, and IP values must be valid canonicalizable addresses.
- Entities read fixed Wazuh fields (`data.srcip`, `data.dstuser`, and so on; see the entity field table in [[Automation-Rules]]). Alerts decoded by Wazuh's JSON decoder, including Windows Event Channel events, usually have no `data.srcuser`/`data.dstuser`, so user entities do not match them and Preview counts them as missing entities. JSON-decoded fields such as `data.win.eventdata.*` are not supported as entities in 2.0.x.
- For a burst, threshold and sliding window apply independently to each resolved group/key. Cooldown and quiet-period rearm can legitimately suppress a repeated sustained burst.
- Rules act only on alerts newly ingested into the plugin. Creating, editing, or enabling a rule does not evaluate alerts already ingested, and there is no replay/backfill control.

## Automation queue is paused or admission is closed

- **Queue paused** preserves enabled rules and durable events but stops processing. An `all_access` administrator can resume it from the Automation runtime panel.
- Admission closes when the active backlog or deferred-event cap is reached. Review queue state counts and increase caps only after checking worker health and capacity.
- Work completed after resume is delayed completion of ingestion-time events using their captured ruleset revisions, not a historical replay using current rules.
- If controls are read-only, the effective Wazuh/OpenSearch Security identity lacks `all_access`. Configure role mappings using the [Wazuh user administration documentation](https://documentation.wazuh.com/current/user-manual/user-administration/index.html); an SSO/LDAP group name alone is not sufficient.

## Automation dead-letter events

- The dead-letter list is cursor-paginated. Use **Next** and **Previous** rather than assuming the first page is complete.
- **Retry** requeues the recoverable event with its captured ruleset snapshot and is idempotent. It does not apply current rules to historical alerts.
- **Resolve** removes the dead-letter document without running it. Use this only after determining that the event should not be retried or its payload is unrecoverable.
- Both mutations require `all_access`. A recurring stage/error after retry indicates an underlying mapping, payload, authorization, or storage issue; inspect the dashboard log before repeatedly retrying.

---

## Wazuh 5.0: nothing appears in the Findings queue

A Wazuh 5.0 build reads the `wazuh-findings-v5-*` data streams, never the 4.x
`wazuh-alerts-*` indices. Source detection runs every sync tick and records its
outcome in the plugin's meta index as the document `source_state`, which is
also what **Settings > Storage & lifecycle** shows. Read it first:

```bash
curl -sk -u admin:<password>   'https://localhost:9200/wazuh-alert-manager-v2-meta/_doc/source_state?pretty'
```

| `state` | Meaning | What to do |
|---|---|---|
| `ready` | The family resolved and `@timestamp` is mapped | Nothing; look at the cursor below |
| `waiting` | The pattern is valid but nothing matches it yet | Wait for the first finding to be written; confirm the manager is shipping |
| `blocked` | The configured pattern is outside the family this build may read, or the probe failed | Fix `wazuh_alert_manager.sync.sourceIndexPattern` / `sync.sourceMode`, or grant the read. The plugin never falls back to another pattern |

Then check that the source actually holds data, and what shape it is in:

```bash
# the findings family exists and has documents
curl -sk -u admin:<password>   'https://localhost:9200/_cat/indices/wazuh-findings-v5-*?v&s=index'

# newest finding, with the fields the adapter reads
curl -sk -u admin:<password> -H 'Content-Type: application/json'   'https://localhost:9200/wazuh-findings-v5-*/_search?pretty' -d '{
    "size": 1,
    "sort": [{"@timestamp": {"order": "desc", "numeric_type": "date"}}],
    "_source": ["@timestamp","wazuh.rule.level","wazuh.agent","event.index","event.doc_id","wazuh.case"]
  }'
```

`numeric_type: date` is required because 5.0 `@timestamp` is `date_nanos`; a
plain sort against a nanosecond field is what the plugin's own cursor uses.

Finally, the 5.0 sync cursor lives in its **own** document so a 4.x cursor is
never replayed against findings:

```bash
curl -sk -u admin:<password>   'https://localhost:9200/wazuh-alert-manager-v2-meta/_doc/sync_state%3Awazuh5_findings?pretty'
```

(The 4.x cursor is `sync_state`.) If the cursor is advancing but the queue is
empty, check `sync.minSeverityLabel` — on 5.0 `sync.minRuleLevel` is ignored,
and a label floor set too high silently filters everything at the source.

---

## Wazuh 5.0: provisioning or writes fail

- **`cluster_block_exception` on create index.** The 5.0 indexer sets
  `cluster.blocks.create_index: true`. The plugin works around this with a
  temporary plugin-owned template plus a bootstrap write and logs
  `Created ... through a bootstrap write`. If you see the block instead, the
  template could not be created — check the dashboard user's privileges.
- **403 writing `wazuh-alert-status-v2-*`.** The 5.0 dashboard indexer user is
  read-only on `wazuh-*`. Run `install.sh --grant-roles` (or create
  `wazuh_alert_manager_store` by hand from the role the installer prints).

---

## Asset or enrichment chips read "no access"

The asset chips read `wazuh-states-*` and the 5.0 local CTI source reads
`wazuh-threatintel-enrichments*`, both **as the signed-in user**, so a 403
becomes a "no access" chip rather than an error. Map
`wazuh_alert_manager_native_read` to the analyst's role (the installer prints
the exact `rolesmapping` call), or re-apply the grants with
`install.sh --grant-roles`. A chip reading "not available" means the index does
not exist on this line — for example, there is no `wazuh-states-sca` on Wazuh
4.x, where the SCA chip reads *not indexed on 4.x* and links to Configuration
Assessment instead.

---

## Notifications stay queued

Open **Settings > Notifications** and read the outbox:

- **`failed` with a 403** — the dashboard's indexer user is missing
  `wazuh_alert_manager_notify`; the recorded error says so. Re-apply with
  `install.sh --grant-roles --indexer-admin-password <pw>`.
- **`failed` on a direct webhook with an egress reason** — the URL is not https
  to a public host. Add the hostname to
  `WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS` on the dashboard service and
  restart it.
- **Retried an hour later rather than on the backoff table** — the webhook
  secret could not be decrypted: `WAZUH_ALERT_MANAGER_ENCRYPTION_KEY` is unset,
  or differs from the value the replica that saved it used. Each of those
  retries still consumes a delivery attempt, so the entry is `dead` after five:
  set the variable and then use **Retry** on the dead entries.
- **`dead`** — five attempts failed, or the channel was deleted or disabled. An
  administrator can **Retry** it, which keeps the attempt count.
- **Nothing is claimed at all** — `notifications.dispatcher.enabled` is false,
  or no replica holds the `notification_dispatcher` lease. `GET
  /api/wazuh_alert_manager/notifications/status` shows the last tick.

---

## Upgrade didn't pick up new fields

Mapping changes are applied idempotently on start. If an additive change couldn't be applied it is logged and skipped (fail-safe). Check the dashboard log for `wazuh-alert-manager` migration lines; a reindex resolves anything incompatible.
