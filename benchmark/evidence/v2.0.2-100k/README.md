# v2.0.2 100k evidence

These sanitized artifacts record three exact 100,000-alert trials performed on
30 August 2026 against Wazuh 4.14 / OpenSearch Dashboards 2.19.5 in a
single-node VirtualBox development VM.

| Trial | Injection rate | End-to-end | Special condition | Result |
|---|---:|---:|---|---|
| `wam-100k-trial26` | 5,270.4 alerts/s | 246.181 s | clean uninterrupted | pass |
| `wam-100k-trial27` | 5,573.3 alerts/s | 219.596 s | clean uninterrupted | pass |
| `wam-100k-trial28-restart` | 5,001.6 alerts/s | 238.081 s | dashboard restarted with queue active | pass |

Each directory contains injection, progress/final result, rule IDs, storage,
queue configuration, environment, wall-clock and SHA-256 records. The restart
trial also records UTC restart boundaries. Exact final outcomes in every trial:

- 100,000 operational alert projections;
- 42 deduplicated cases and 5,300 evidence relationships;
- 5,000 closed and 2,500 assigned/in-progress alerts;
- zero actions on 87,200 negative controls;
- zero pending, claimed, retry, deferred, failed or DLQ work at completion.

The corpus enters at the synthetic benchmark-owned source index and bypasses
agent transport and manager decoding. This evidence characterizes the plugin
pipeline on the recorded machine; it does not establish universal Wazuh or
production throughput.
