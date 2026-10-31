# v2.0.3 100k evidence

These sanitized artifacts record three exact 100,000-document trials performed
on 23 October 2026 against Wazuh Alert Manager v2.0.3 build
`2.0.3-20261020171752946-990e83f54767`, Wazuh 4.14.9, and OpenSearch
Dashboards 2.19.6 in a single-node VirtualBox development VM.

The benchmark tree is identical in the v2.0.2 and v2.0.3 tags (Git tree
`ed25f2ffa510dbcef9203f572ec4182de7d98cc5`). One unreported warm-up preceded
the measured trials.

| Trial | Injection | Injection rate | Post-injection drain | Whole-run wall | Queue high-water | Special condition | Result |
|---|---:|---:|---:|---:|---:|---|---|
| `wam-100k-v203-trial01` | 30.438 s | 3,285.4 documents/s | 218.208 s | 253 s | 10,240 | clean uninterrupted | pass |
| `wam-100k-v203-trial02` | 31.705 s | 3,154.1 documents/s | 251.241 s | 288 s | 10,945 | clean uninterrupted | pass |
| `wam-100k-v203-trial03-restart` | 33.825 s | 2,956.4 documents/s | 369.732 s | 411 s | 11,133 | dashboard restart with queue active | pass |
| Median | 31.705 s | 3,154.1 documents/s | 251.241 s | 288 s | 10,945 | includes restart condition | 3/3 pass |

Each directory contains injection, progress/final result, rule IDs, storage,
queue configuration, plugin health, environment, wall-clock, and SHA-256
records. The restart trial also records the UTC systemd restart boundaries.
The copied evidence was independently checked against each generated
`SHA256SUMS` file before publication.

Exact final outcomes in every trial:

- 100,000 operational alert projections;
- 42 deduplicated cases and 5,300 evidence relationships;
- 5,000 closed and 2,500 assigned/in-progress alerts;
- zero actions on 87,200 deliberately non-matching controls; and
- zero pending, claimed, retry, deferred, failed, or DLQ work at completion.

Trial 1 temporarily placed 256 entries in retry; all recovered before the final
gate without missing or duplicate outcomes. Trial 3 restarted Wazuh Dashboard
at `2026-10-23T08:33:16Z`, after the preceding checkpoint recorded 11,133
active durable admissions. One expected connection-refused polling result was
recorded while the service restarted; durable work then recovered and every
final predicate passed.

## Measurement boundary

Injection begins before the first bulk request and ends after all source
documents are acknowledged and the source index is explicitly refreshed. The
post-injection drain timer starts after injection and synchronization are
enabled. It ends only after all exact outcome predicates pass and the active,
deferred, and failed queues are empty. The whole-run wall timer also includes
injection, synchronization control, and polling overhead.

The injection rate describes writes to the isolated synthetic source index. It
is not Wazuh agent, manager, Filebeat, network, or production ingestion
throughput. These artifacts establish configured software behavior at one
laboratory volume point; they do not establish a scaling curve, production
capacity, resource behavior across workloads, clustered performance, or
behavior under concurrent analyst activity. Trial 3 is a reliability condition
rather than a steady-state performance replicate.

## Configuration

- VirtualBox VM: 6 vCPUs, approximately 10.4 GB RAM, 65.3 GB virtual disk;
- source: `wazuh-alerts-4.x-wam-benchmark`;
- synchronization interval: 15 s;
- initial lookback: 60 min;
- synchronization batch: 10,000 documents;
- overlap: 5 s;
- legacy migration: disabled; and
- automation queue limits: 200,000 active and 500,000 deferred entries.

The dashboard was stopped before each safety-checked reset and started again
afterward. This prevents a background worker from recreating an index between
deletion and clean mapping provisioning; it occurs before the measured
injection and drain intervals.

