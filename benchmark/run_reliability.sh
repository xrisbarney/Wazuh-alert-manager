#!/usr/bin/env bash
# Reproducible, release-neutral 100k-alert benchmark for Wazuh Alert Manager.
set -euo pipefail

: "${WAM_PW:?Set WAM_PW in the environment; never add it to this file}"
export WAM_USER="${WAM_USER:-admin}"
export WAM_INDEXER="${WAM_INDEXER:-https://localhost:9200}"
export WAM_API="${WAM_API:-https://localhost/api/wazuh_alert_manager}"
export WAM_BENCH_SOURCE_INDEX="${WAM_BENCH_SOURCE_INDEX:-wazuh-alerts-4.x-wam-benchmark}"

HERE="$(cd "$(dirname "$0")" && pwd)"
RESULTS="${WAM_BENCH_RESULTS:-$HERE/results}"
TRIAL="${WAM_BENCH_TRIAL:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT="$RESULTS/$TRIAL"
mkdir -p "$OUT"

# The dashboard status endpoint can become healthy before plugin setup and
# owned-index provisioning complete. Gate the run on this plugin's route so a
# fresh install/reset cannot race the first administrative request.
for attempt in $(seq 1 "${WAM_BENCH_READY_ATTEMPTS:-90}"); do
  if python3 "$HERE/bench.py" health > "$OUT/plugin-health.json" 2>/dev/null; then
    break
  fi
  if [ "$attempt" -eq "${WAM_BENCH_READY_ATTEMPTS:-90}" ]; then
    echo "Wazuh Alert Manager did not become ready for the benchmark" >&2
    exit 1
  fi
  sleep "${WAM_BENCH_READY_INTERVAL:-2}"
done

python3 "$HERE/bench.py" queue-config \
  --max-backlog "${WAM_BENCH_MAX_BACKLOG:-200000}" \
  --max-deferred "${WAM_BENCH_MAX_DEFERRED:-500000}" > "$OUT/queue-settings.json"
python3 "$HERE/bench.py" storage > "$OUT/storage-before.json"
python3 "$HERE/bench.py" sync-off > "$OUT/sync-disabled.json"
trap 'python3 "$HERE/bench.py" sync-on >/dev/null || true' EXIT
python3 "$HERE/bench.py" rules > "$OUT/rule-ids.json"
STARTED="$(date +%s)"
python3 "$HERE/bench.py" inject | tee "$OUT/injection.json"
python3 "$HERE/bench.py" sync-on > "$OUT/sync-enabled.json"
trap - EXIT
set +e
python3 "$HERE/bench.py" wait --rule-ids "$OUT/rule-ids.json" --timeout "${WAM_BENCH_TIMEOUT:-1800}" | tee "$OUT/result.json"
BENCH_STATUS="${PIPESTATUS[0]}"
set -e
FINISHED="$(date +%s)"
python3 "$HERE/bench.py" storage > "$OUT/storage-after.json"
python3 "$HERE/collect_environment.py" > "$OUT/environment.json"
printf '{"wall_seconds":%s,"trial":"%s"}\n' "$((FINISHED-STARTED))" "$TRIAL" > "$OUT/wall-clock.json"
sha256sum "$OUT"/*.json > "$OUT/SHA256SUMS"
if [ "$BENCH_STATUS" -eq 0 ]; then
  echo "Benchmark passed. Results: $OUT"
else
  echo "Benchmark failed or timed out; complete evidence retained: $OUT" >&2
fi
exit "$BENCH_STATUS"
