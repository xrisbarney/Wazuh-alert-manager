#!/bin/bash
# Node-local reliability run for Wazuh Alert Manager (SoftwareX Impact evaluation).
# Run ON the Wazuh node after the plugin is installed and the sync job is active.
#
#   export WAM_USER=admin
#   export WAM_PW=<indexer/dashboard admin password>
#   bash run_reliability.sh
#
# Creates 4 automation rules, injects a tagged 1082-alert corpus with known
# ground-truth outcomes, waits for the sync + automation engine, and prints
# actual vs. expected. Idempotent: purges prior synthetic data first.
set -o pipefail
USER="${WAM_USER:-admin}"; PW="${WAM_PW:?set WAM_PW}"
IDX="${WAM_INDEXER:-https://localhost:9200}"
API="${WAM_API:-https://localhost/api/wazuh_alert_manager}"
SRCIDX="wazuh-alerts-4.x-paperbench"
RUNID="paperbench-$(date +%s)"
A="-sk -u $USER:$PW"
HERE="$(cd "$(dirname "$0")" && pwd)"
echo "RUNID=$RUNID"

mkrule() { curl -sk -u "$USER:$PW" -H 'osd-xsrf: true' -H 'content-type: application/json' -X POST "$API/rules" -d "$1" | grep -o '"id":"[^"]*"' | head -1 | sed 's/"id":"//;s/"//'; }

# remove any prior Bench rules
for id in $(curl -sk -u "$USER:$PW" "$API/rules" | grep -o '"id":"[^"]*"\|"name":"Bench[^"]*"' | paste - - | grep Bench | grep -o '"id":"[^"]*"' | sed 's/"id":"//;s/"//'); do
  curl -sk -u "$USER:$PW" -H 'osd-xsrf: true' -X DELETE "$API/rules/$id" >/dev/null; done

RA=$(mkrule '{"name":"Bench burst-case (srcip)","enabled":true,"match":{"agentNames":["pbench-a"],"minLevel":3},"trigger":{"type":"burst","entity":"srcip","windowMinutes":30,"threshold":5},"actions":{"createCase":true,"caseSeverity":"high"}}')
RB=$(mkrule '{"name":"Bench auto-close (ruleid)","enabled":true,"match":{"agentNames":["pbench-b"],"ruleIds":["900001"]},"trigger":{"type":"per_alert"},"actions":{"createCase":false,"setStatus":"closed"}}')
RC=$(mkrule '{"name":"Bench burst-assign (user)","enabled":true,"match":{"agentNames":["pbench-c"]},"trigger":{"type":"burst","entity":"user","windowMinutes":30,"threshold":4},"actions":{"createCase":false,"setStatus":"in_progress","assignTo":"admin"}}')
RD=$(mkrule '{"name":"Bench co-occurrence (all-of)","enabled":true,"match":{"agentNames":["pbench-d-1","pbench-d-2","pbench-d-3"],"ruleIds":["900010","900011"],"ruleIdsMode":"all"},"trigger":{"type":"burst","entity":"agent","windowMinutes":30,"threshold":2},"actions":{"createCase":true,"caseSeverity":"critical"}}')
echo "rules: A=$RA B=$RB C=$RC D=$RD"

# purge prior synthetic alerts + auto-cases, (re)create tagged source index, inject corpus
curl $A -X POST "$IDX/wazuh-alert-status/_delete_by_query?refresh=true&conflicts=proceed" -H 'content-type: application/json' -d '{"query":{"prefix":{"agent.name":"pbench-"}}}' >/dev/null 2>&1
curl $A -X POST "$IDX/wazuh-alert-manager-cases/_delete_by_query?refresh=true&conflicts=proceed" -H 'content-type: application/json' -d '{"query":{"bool":{"must":[{"term":{"created_by":"correlation-rule"}},{"match_phrase_prefix":{"title":"Bench"}}]}}}' >/dev/null 2>&1
curl $A -X DELETE "$IDX/$SRCIDX" >/dev/null 2>&1
curl $A -X PUT "$IDX/$SRCIDX" -H 'content-type: application/json' -d '{"mappings":{"properties":{"@timestamp":{"type":"date"},"agent":{"properties":{"name":{"type":"keyword"},"id":{"type":"keyword"}}},"rule":{"properties":{"id":{"type":"keyword"},"level":{"type":"integer"},"description":{"type":"keyword"}}},"manager":{"properties":{"name":{"type":"keyword"}}},"data":{"properties":{"srcip":{"type":"keyword"},"srcuser":{"type":"keyword"},"paperbench":{"type":"keyword"},"pbgroup":{"type":"keyword"}}}}}}' >/dev/null 2>&1
python3 "$HERE/bench.py" gen "$RUNID" > /tmp/pb_bulk.ndjson
curl $A -X POST "$IDX/$SRCIDX/_bulk" -H 'content-type: application/x-ndjson' --data-binary @/tmp/pb_bulk.ndjson >/dev/null 2>&1
curl $A -X POST "$IDX/$SRCIDX/_refresh" >/dev/null 2>&1
echo "injected 1082 alerts; waiting for sync + automation engine..."

for i in $(seq 1 18); do
  sleep 15
  OUT=$(python3 "$HERE/bench.py" measure "$RUNID" "$RA,$RD")
  synced=$(echo "$OUT" | grep -o '"total_synced": [0-9]*' | grep -o '[0-9]*')
  cases=$(echo "$OUT" | grep -o '"rule_cases_created": [0-9]*' | grep -o '[0-9]*')
  [ "${synced:-0}" -ge 1082 ] && [ "${cases:-0}" -ge 7 ] && break
done
echo "=== RESULT (expected: cases=7 closed=20 assigned=15 linkedA=30 linkedD=4 false=0) ==="
echo "$OUT"
