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

On a **single-node** cluster, **yellow is normal and healthy** (replicas have nowhere to go). Once the indexer is yellow/green, the dashboard clears its 503. In Kubernetes, raise the dashboard/indexer pod probe timeouts instead (see [[Installation#kubernetes--custom-image-recommended]]).

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

---

## Analyst/assignee metrics look empty on an old install

On installs whose `wazuh-alert-status` index predates the explicit `assigned_to` **keyword** mapping, that field stays `text` and won't aggregate. The plugin fail-safes (falling back to the `.keyword` subfield where possible) rather than forcing an incompatible mapping change. A **reindex** of `wazuh-alert-status` is the full fix. **Fresh installs are unaffected.**

---

## A rule isn't firing

- Use the rule's **Dry run** to confirm it matches anything over the last 24h.
- Remember **create case** requires the **burst** trigger; a per-alert rule can only set status / assign.
- For **All of** conditions, the *same entity* must have seen **every** listed value within the window — and the **threshold** is a separate volume floor (set it to the number of required values for a pure "one of each" rule).
- Rules act on **newly synced** alerts, so back-dated data already ingested won't be re-evaluated.

---

## Upgrade didn't pick up new fields

Mapping changes are applied idempotently on start. If an additive change couldn't be applied it is logged and skipped (fail-safe). Check the dashboard log for `wazuh-alert-manager` migration lines; a reindex resolves anything incompatible.
