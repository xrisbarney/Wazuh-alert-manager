# Reliability run (reproducibility kit)

A controlled, ground-truth evaluation of Wazuh Alert Manager's automation engine:
it injects a **tagged synthetic alert corpus with known-correct outcomes**
through the plugin's real sync → automation-rule path and measures what the
engine actually did, including **false actions on benign filler alerts**
(precision). This is the evidence behind the paper's Impact section.

## What it exercises

Four automation rules covering the engine's modes, over **1,082 alerts**:

| Group | Alerts | Rule under test | Expected outcome |
|-------|-------:|-----------------|------------------|
| A | 39 | burst by **source IP**, threshold 5 → open High case | 5 IPs fire → **5 cases**, 30 alerts linked; 3 IPs below threshold → nothing |
| B | 20 | **per-alert** auto-close (rule id) | **20 alerts closed** |
| C | 17 | burst by **user**, threshold 4 → in-progress + assign | 3 users fire → **15 alerts** in-progress & assigned; 1 user below threshold → nothing |
| D | 6 | burst by **agent**, **all-of** rule ids (co-occurrence) | 2 agents cover both ids → **2 cases**, 4 linked; 1 agent misses coverage → nothing |
| F | 1,000 | (none — benign level-2 fillers) | **0 actions** (precision check) |

## Run it (on the Wazuh node)

```bash
export WAM_USER=admin
export WAM_PW='<indexer / dashboard admin password>'
bash run_reliability.sh
```

The script creates the rules, purges any prior synthetic data, injects the
corpus, waits for the sync + automation engine, and prints actual vs. expected.

## Expected result (100% correct, 0 false actions)

```json
{
  "total_synced": 1082,
  "rule_cases_created": 7,
  "closed_B": 20,
  "inprog_C": 15,
  "assigned_C": 15,
  "linked_A": 30,
  "linked_D": 4,
  "false_actions_on_fillers": 0
}
```

All 1,082 alerts are handled exactly as specified and **no filler alert is ever
touched** — the engine acts on precisely the intended alerts.

## Files

- `bench.py` — corpus generator (`gen`) and measurement (`measure`).
- `run_reliability.sh` — orchestrator (create rules → inject → wait → measure).

## Cleanup

Rules are named `Bench …` and re-purged on each run; synthetic alerts use the
`pbench-*` agent names. To remove everything:

```bash
curl -sk -u "$WAM_USER:$WAM_PW" -X DELETE "https://localhost:9200/wazuh-alerts-4.x-paperbench"
curl -sk -u "$WAM_USER:$WAM_PW" -X POST "https://localhost:9200/wazuh-alert-status/_delete_by_query?refresh=true" -H 'content-type: application/json' -d '{"query":{"prefix":{"agent.name":"pbench-"}}}'
```
