# Wazuh Alert Manager v2.0.1 volume benchmark

This reproducibility kit evaluates the real Wazuh Alert Manager pipeline at
**100,000 synthetic alerts**: native-format source index, bounded v2 projection,
durable automation queue, lifecycle actions, deduplicated cases, and evidence
links. It measures exact outcomes; it does not sample.

## Recorded v2.0.1 result

The clean 30 August 2026 run did **not** pass the automation drain gate.
Injection completed at 2,974.1 alerts/s and projection reached all 100,000
documents after 589.028 seconds, but only 1,376 of 100,000 durable admissions
were complete after the 1,800-second deadline. The v2.0.1 worker's global,
single-event execution is the limiting stage. Do not present this as positive
100k automation capacity or extrapolate the earlier small run. Sanitized raw
facts are in [`evidence/v2.0.1-100k`](evidence/v2.0.1-100k/).

## Corpus and ground truth

| Scenario | Alerts | Rule behaviour | Exact expected outcome |
|---|---:|---|---:|
| A | 1,000 | Every matching alert; `User is present`; create case | 10 open cases, 1,000 evidence links (one active case per observed user) |
| B | 2,000 | Burst; `Source IP is present`; threshold 20 | 10 open cases, 2,000 evidence links (one per source IP) |
| C | 1,200 | `(srcip=10.30.0.10 AND dstport=22) OR (user=svc_backup AND process=rsync)` | 2 critical cases, 1,200 evidence links, separate by matching group |
| D | 500 | Every matching alert; `Agent is present`; create case | 10 cases and 500 links, validating active-case deduplication |
| E | 5,000 | Every matching alert; rule `920005`; close | 5,000 closed alerts |
| F | 2,500 | Every matching alert; `Destination IP=10.50.0.10`; assign and progress | 2,500 assigned, in-progress alerts |
| G | 600 | Burst per agent; rule IDs `920010 AND 920011`; threshold 6 | 10 critical cases, 600 links |
| Negative control | 87,200 | No rule matches | 0 status, assignment, or case actions |

Total: **100,000 alerts**. The rules are created disabled, previewed through the
read-only historical preview endpoint, then activated. They are therefore
forward-only: the benchmark injects the corpus only after activation.

## Safety boundary

The kit uses only the synthetic source index
`wazuh-alerts-4.x-paperbench-v201`. Despite its Wazuh-compatible name, it is
benchmark-owned. The reset script accepts only:

- exact `wazuh-alert-status-v2-*` plugin indices;
- exact `wazuh-alert-manager-v2-*` plugin indices; and
- the exact synthetic source index above.

It refuses wildcards outside those prefixes and never deletes normal
`wazuh-alerts-*` indices. Legacy v1 indices are left untouched; disable v1
migration in the benchmark dashboard configuration so they cannot contaminate
the clean v2 run.

## Clean benchmark configuration

Add these non-secret settings to `/etc/wazuh-dashboard/opensearch_dashboards.yml`:

```yaml
wazuh_alert_manager.sync.sourceIndexPattern: "wazuh-alerts-4.x-paperbench-v201"
wazuh_alert_manager.sync.intervalSeconds: 15
wazuh_alert_manager.sync.initialLookbackMinutes: 60
wazuh_alert_manager.sync.batchSize: 10000
wazuh_alert_manager.sync.overlapSeconds: 5
wazuh_alert_manager.migration.enabled: false
```

After a clean provision, set the queue caps from **Settings → Automation
rules → Queue controls** or via the admin-only endpoint to at least 200,000
active and 500,000 deferred entries. This is test capacity, not a recommended
production default.

## Run

Run on the Wazuh dashboard/indexer node. Supply credentials only through the
environment or an ignored secret file:

```bash
export WAM_USER=admin
export WAM_PW='<development credential>'
python3 benchmark/reset_v2.py --yes
sudo systemctl restart wazuh-dashboard
bash benchmark/run_reliability.sh
```

The runner writes an immutable evidence directory under `benchmark/results/`
containing rule IDs, injection timing, exact outcome comparison, queue high
water mark, before/after storage, environment metadata, wall clock, and
SHA-256 checksums.

For a publication result, perform one warm-up and at least three clean measured
trials. Report each trial, median, range, environment, queue settings, sync
interval, and whether the benchmark shared the node with the indexer/dashboard.
Do not generalise a single-node synthetic result to production capacity.
