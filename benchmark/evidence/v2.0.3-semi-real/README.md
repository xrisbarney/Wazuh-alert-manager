# Semi-real evaluation results

Final measurement window: 2026-10-23 10:00:24-10:03:59 UTC.

The endpoint actions ran from 10:01:59 to 10:03:29 UTC. Wazuh Alert Manager
completed the last matching rule execution at 10:03:47 UTC. These timestamps
describe this laboratory run only and are not reported as a performance or
response-time benchmark.

## Outcomes

| Use case | Native alerts used by WAM | Observed WAM outcome | Result |
|---|---:|---|---|
| SSH brute force | 1 x rule 5712 | 1 Critical case; 1 evidence link | Passed |
| Auditd command execution | 1 x rule 80792 | 1 High case; 1 evidence link | Passed |
| FIM lifecycle | 1 each x rules 554, 550 and 553 | 1 Medium case; 3 evidence links | Passed |
| Local account creation | 1 x rule 5902 | 1 High case; 1 evidence link | Passed |
| Sudo to root | 3 x rule 5402 | All 3 assigned to `admin` and set In progress; no case | Passed |
| Successful SSH control | 4 x rule 5715 | All 4 remained Open, unassigned and case-free | Passed |

The native Wazuh index contained 64 alerts for the endpoint in the frozen
window. All 64 reached the plugin projection. Nine matched the five automation
rules and received the exact configured actions. Four were successful-SSH
controls and 51 were other background or supporting alerts; none of those 55
received a status change, assignment or case link. The final active queue and
automation dead-letter queue counts were both zero.

Totals attributable to the final rule set:

- 4 cases
- 6 evidence links
- 9 completed matching rule executions
- 3 assigned/In-progress alerts
- 0 unexpected actions on controls or other alerts
- 0 active queue entries
- 0 failed/dead-letter entries

## Evidence files

- `evidence.json`: native alerts, operational projections, cases, evidence
  relationships, rule executions, exact summaries and queue state.
- `rule-manifest.json`: activated WAM rule IDs, native Wazuh rule IDs and
  configured actions.
- `endpoint-run.log`: ordered endpoint actions and UTC boundaries.
- `environment.txt`: endpoint, operating-system, Wazuh agent, Auditd and Hydra
  versions.
- `SHA256SUMS`: integrity hashes for the evidence bundle.

An earlier calibration run was excluded from this published bundle and from all
reported counts. The final run used synchronized clocks, a fresh five-rule
revision, an explicit sudo action, and rule-ID filters that isolate only the
final cases, evidence relationships, and executions.
