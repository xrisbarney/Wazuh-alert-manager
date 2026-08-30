# Wazuh Alert Manager v2.0.2 volume benchmark

This reproducibility kit evaluates the real Wazuh Alert Manager pipeline at
**100,000 synthetic alerts**: native-format source index, bounded v2 projection,
durable automation queue, lifecycle actions, deduplicated cases, and evidence
links. It measures exact outcomes; it does not sample.

## Recorded v2.0.2 result

Three clean 30 August 2026 trials passed every exact ground-truth and queue
drain gate on the Wazuh 4.14 single-node test VM. One trial deliberately
restarted Wazuh Dashboard with 9,232 durable admissions active; leased work was
recovered and the final result still contained no retry, deferred or failed
entries and no duplicate actions.

| Trial | Injection | End-to-end | Queue high-water | Result |
|---|---:|---:|---:|---|
| 26 | 5,270.4/s | 246.181 s | 11,988 | Pass |
| 27 | 5,573.3/s | 219.596 s | 11,276 | Pass |
| 28, restart | 5,001.6/s | 238.081 s | 11,264 | Pass |

The median end-to-end time was **238.081 s** (range 219.596–246.181 s). Every
trial ended with 100,000 projected alerts, 42 deduplicated cases, 5,300 exact
evidence links, 5,000 closed alerts, 2,500 assigned/in-progress alerts, zero
false actions across 87,200 controls, and a fully empty durable queue. Case
documents remained bounded; the largest alert-ID preview was 600 while the
evidence family retained exact relationship counts.

Sanitized evidence is in
[`evidence/v2.0.2-100k`](evidence/v2.0.2-100k/). The earlier v2.0.1 negative
result remains in [`evidence/v2.0.1-100k`](evidence/v2.0.1-100k/) and must not
be rewritten as a pass. These are single-node synthetic reproducibility
results, not a universal production-capacity guarantee.

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
`wazuh-alerts-4.x-wam-benchmark`. Despite its Wazuh-compatible name, it is
benchmark-owned. The reset script accepts only:

- exact `wazuh-alert-status-v2-*` plugin indices;
- exact `wazuh-alert-manager-v2-*` plugin indices; and
- the exact synthetic source index above.

It refuses wildcards outside those prefixes and never deletes normal
`wazuh-alerts-*` indices. Legacy v1 indices are left untouched by default. In a
disposable laboratory, `--include-legacy-v1` additionally deletes only the five
hard-coded v1 plugin indices. Disable v1 migration in the benchmark dashboard
configuration so an ordinary v2-only run cannot be contaminated.

## Clean benchmark configuration

Add these non-secret settings to `/etc/wazuh-dashboard/opensearch_dashboards.yml`:

```yaml
wazuh_alert_manager.sync.sourceIndexPattern: "wazuh-alerts-4.x-wam-benchmark"
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
python3 benchmark/reset_v2.py --yes --include-legacy-v1  # disposable lab only
sudo systemctl restart wazuh-dashboard
bash benchmark/run_reliability.sh
```

The runner writes an immutable evidence directory under `benchmark/results/`
containing rule IDs, injection timing, exact outcome comparison, queue high
water mark, before/after storage, environment metadata, wall clock, and
SHA-256 checksums.

For a formal result, perform one warm-up and at least three clean measured
trials. Report each trial, median, range, environment, queue settings, sync
interval, and whether the benchmark shared the node with the indexer/dashboard.
Do not generalise a single-node synthetic result to production capacity.
