#!/usr/bin/env python3
"""Exact 100k-alert benchmark for the Wazuh Alert Manager sync/automation/case path."""

from __future__ import annotations
import argparse, base64, datetime as dt, hashlib, json, os, ssl, sys, time
import urllib.error, urllib.parse, urllib.request

USER = os.environ.get("WAM_USER", "admin")
PW = os.environ.get("WAM_PW", "")
OS = os.environ.get("WAM_INDEXER", "https://localhost:9200").rstrip("/")
API = os.environ.get("WAM_API", "https://localhost/api/wazuh_alert_manager").rstrip("/")
SRC = os.environ.get("WAM_BENCH_SOURCE_INDEX", "wazuh-alerts-4.x-wam-benchmark")
ALERTS, CASES = "wazuh-alert-status-v2-read", "wazuh-alert-manager-v2-cases-read"

EXPECTED = {
    "total_synced": 100000,
    "immediate_user_cases": 10, "immediate_user_linked": 1000,
    "burst_srcip_cases": 10, "burst_srcip_linked": 2000,
    "boolean_group_cases": 2, "boolean_group_linked": 1200,
    "immediate_agent_cases": 10, "immediate_agent_linked": 500,
    "closed_alerts": 5000, "assigned_in_progress": 2500,
    "cooccurrence_cases": 10, "cooccurrence_linked": 600,
    "false_actions_on_controls": 0,
}


def req(base, path, body=None, method="GET", content_type="application/json", timeout=180):
    data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    request = urllib.request.Request(base + path, data=data, method=method)
    request.add_header("Authorization", "Basic " + base64.b64encode(f"{USER}:{PW}".encode()).decode())
    request.add_header("Content-Type", content_type)
    if base == API:
        request.add_header("osd-xsrf", "wam-benchmark")
    context = ssl.create_default_context(); context.check_hostname = False; context.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(request, context=context, timeout=timeout) as response:
            payload = response.read()
            return json.loads(payload) if payload else {}
    except urllib.error.HTTPError as error:
        details = error.read().decode(errors="replace")
        raise RuntimeError(f"{method} {path} failed ({error.code}): {details}") from error


def osreq(path, body=None, method="GET"):
    return req(OS, path, body, method)


def apireq(path, body=None, method="GET"):
    return req(API, path, body, method)


def count(index, query):
    return int(osreq(f"/{index}/_count", {"query": query}, "POST").get("count", 0))


def term(field, value): return {"term": {field: value}}
def must(*clauses): return {"bool": {"must": list(clauses)}}
def scoped(*clauses): return must(term("source_index", SRC), *clauses)


def group(group_id, predicates):
    return {"id": group_id, "order": 0, "predicates": [
        {"id": f"{group_id}-p{i}", "order": i, "entity": entity, "operator": operator,
         **({"value": value} if operator == "equals" else {})}
        for i, (entity, operator, value) in enumerate(predicates)
    ]}


def rule(name, agents, trigger_type, groups, actions, rule_ids=None,
         rule_ids_mode="any", threshold=None, routing="separate_by_group",
         rate_limit=False):
    trigger = {
        "type": trigger_type, "entityExpression": {"version": 1, "groups": [
            {**entity_group, "order": position} for position, entity_group in enumerate(groups)
        ]},
        "routing": routing, "cooldown": {"durationMinutes": 0 if trigger_type == "per_alert" else 1},
        "rearm": ({"type": "immediate", "quietPeriodMinutes": 0} if trigger_type == "per_alert"
                  else {"type": "after_quiet_period", "quietPeriodMinutes": 1}),
    }
    if trigger_type == "burst": trigger.update({"threshold": threshold, "windowMinutes": 30})
    return {
        "name": name, "enabled": False, "priority": 100, "sortOrder": 0,
        "processingMode": "continue",
        "match": {"agentNames": agents, "agentNamesMode": "any",
                  **({"ruleIds": rule_ids, "ruleIdsMode": rule_ids_mode} if rule_ids else {})},
        "trigger": trigger, "actions": actions,
        "preconditions": {"statuses": ["open"], "assignment": "unassigned"},
        "safety": {"acknowledgeMatchAll": False, "maxActionsPerRun": 10000,
                   "maxCasesPerRun": 20,
                   **({"rateLimit": {"maxExecutions": 100000, "windowMinutes": 60}}
                      if rate_limit else {})},
    }


def definitions():
    case = lambda severity: {"createCase": True, "caseSeverity": severity, "setStatus": None, "assignTo": None}
    return [
        rule("WAM 100k A - immediate user dedup", ["wam-bench-a"], "per_alert",
             [group("a-user", [("user", "exists", None)])], case("high")),
        rule("WAM 100k B - source IP burst", ["wam-bench-b"], "burst",
             [group("b-srcip", [("srcip", "exists", None)])], case("high"), threshold=20),
        rule("WAM 100k C - Boolean entity groups", ["wam-bench-c"], "burst", [
            group("c-ssh", [("srcip", "equals", "10.30.0.10"), ("dstport", "equals", "22")]),
            group("c-backup", [("user", "equals", "svc_backup"), ("process", "equals", "rsync")]),
        ], case("critical"), threshold=5),
        rule("WAM 100k D - immediate agent dedup", [f"wam-bench-d-{i}" for i in range(10)],
             "per_alert", [group("d-agent", [("agent", "exists", None)])], case("medium")),
        rule("WAM 100k E - immediate auto-close", ["wam-bench-e"], "per_alert",
             [group("e-agent", [("agent", "exists", None)])],
             {"createCase": False, "setStatus": "closed", "assignTo": None}, rule_ids=["920005"]),
        rule("WAM 100k F - assign and progress", ["wam-bench-f"], "per_alert",
             [group("f-dstip", [("dstip", "equals", "10.50.0.10")])],
             {"createCase": False, "setStatus": "in_progress", "assignTo": "admin"}),
        rule("WAM 100k G - all-rule co-occurrence", [f"wam-bench-g-{i}" for i in range(10)],
             "burst", [group("g-agent", [("agent", "exists", None)])], case("critical"),
             rule_ids=["920010", "920011"], rule_ids_mode="all", threshold=6,
             rate_limit=True),
    ]


def list_rules():
    output, cursor = [], None
    while True:
        query = "?size=100" + ("&cursor=" + urllib.parse.quote(cursor) if cursor else "")
        result = apireq("/rules" + query); output.extend(result.get("rules", []))
        cursor = result.get("nextCursor")
        if not cursor: return output


def create_rules():
    for existing in list_rules():
        if str(existing.get("name", "")).startswith("WAM 100k "):
            query = urllib.parse.urlencode({k: existing[k] for k in ("revision", "if_seq_no", "if_primary_term")})
            apireq(f"/rules/{existing['id']}?{query}", method="DELETE")
    ids = {}
    for definition in definitions():
        created = apireq("/rules", definition, "POST")
        preview = apireq("/rules/preview", {**definition, "id": created["id"],
                         "revision": created["revision"], "lookbackHours": 1}, "POST")
        if preview.get("mode") != "historical_read_only": raise RuntimeError("Rule preview failed")
        active = apireq(f"/rules/{created['id']}", {"enabled": True,
                        **{k: created[k] for k in ("revision", "if_seq_no", "if_primary_term")}}, "PUT")
        if not active.get("enabled"): raise RuntimeError("Rule activation failed")
        ids[definition["name"].split()[2]] = created["id"]
    print(json.dumps(ids, indent=2, sort_keys=True))


def iso(base, milliseconds):
    return (base + dt.timedelta(milliseconds=milliseconds)).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def document(timestamp, agent, rule_id, level, scenario, **data):
    return {"@timestamp": timestamp,
            "agent": {"id": hashlib.sha1(agent.encode()).hexdigest()[:3], "name": agent, "ip": "192.0.2.10"},
            "manager": {"name": "wam-benchmark"},
            "rule": {"id": rule_id, "level": level,
                     "description": f"Synthetic WAM 100k scenario {scenario}",
                     "groups": ["wam_benchmark", f"scenario_{scenario.lower()}"],
                     "mitre": {"id": ["T1110"], "technique": ["Brute Force"],
                               "tactic": ["Credential Access"]}},
            "decoder": {"name": "json"}, "location": "wam-benchmark",
            "full_log": f"Synthetic benchmark event; scenario={scenario}", "data": data}


def corpus():
    base, serial = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=2), 0
    def item(scenario, agent, rule_id, level, **data):
        nonlocal serial
        serial += 1
        return f"wam-benchmark-{serial:06d}", document(iso(base, serial // 100), agent, rule_id, level, scenario, **data)
    for n in range(1000): yield item("A", "wam-bench-a", "920001", 10, srcuser=f"analyst{n%10}", srcip=f"10.10.0.{n%10+1}")
    for n in range(2000): yield item("B", "wam-bench-b", "920002", 9, srcip=f"10.20.0.{n%10+1}", dstport=22)
    for n in range(600): yield item("C", "wam-bench-c", "920003", 12, srcip="10.30.0.10", dstport=22, srcuser=f"ssh{n%20}")
    for _ in range(600): yield item("C", "wam-bench-c", "920004", 12, srcip="10.30.0.20", dstport=873, srcuser="svc_backup", process={"name": "rsync"})
    for n in range(500): yield item("D", f"wam-bench-d-{n%10}", "920006", 6, srcip=f"10.40.0.{n%10+1}")
    for n in range(5000): yield item("E", "wam-bench-e", "920005", 3, srcip=f"198.51.100.{n%200+1}")
    for n in range(2500): yield item("F", "wam-bench-f", "920007", 7, dstip="10.50.0.10", dstport=443, srcip=f"203.0.113.{n%200+1}")
    for n in range(600): yield item("G", f"wam-bench-g-{n%10}", "920010" if (n//10)%2 == 0 else "920011", 13, srcip=f"10.60.0.{n%10+1}")
    for n in range(87200): yield item("CONTROL", "wam-bench-control", "929999", 2, srcip=f"172.16.{(n//250)%250}.{n%250+1}")


def create_source():
    try: osreq(f"/{SRC}", method="DELETE")
    except RuntimeError as error:
        if "(404)" not in str(error): raise
    osreq(f"/{SRC}", {"settings": {"number_of_shards": 1, "number_of_replicas": 0, "refresh_interval": "-1"},
          "mappings": {"dynamic": True, "properties": {
              "@timestamp": {"type": "date"},
              "agent": {"properties": {"id": {"type": "keyword"}, "name": {"type": "keyword"}, "ip": {"type": "ip"}}},
              "manager": {"properties": {"name": {"type": "keyword"}}},
              "rule": {"properties": {"id": {"type": "keyword"}, "level": {"type": "integer"}, "description": {"type": "text"}, "groups": {"type": "keyword"}}},
              "data": {"properties": {"srcip": {"type": "ip"}, "dstip": {"type": "ip"}, "srcuser": {"type": "keyword"}, "dstport": {"type": "integer"}, "process": {"properties": {"name": {"type": "keyword"}}}}}
          }}}, "PUT")


def send_bulk(lines):
    result = req(OS, "/_bulk", b"\n".join(lines) + b"\n", "POST", "application/x-ndjson")
    if result.get("errors"):
        failures = [i for i in result.get("items", []) if i.get("index", {}).get("error")]
        raise RuntimeError(f"Bulk failures: {failures[:2]}")


def inject(chunk_size):
    create_source(); started = time.perf_counter(); lines = []; written = 0
    for doc_id, doc in corpus():
        lines += [json.dumps({"index": {"_index": SRC, "_id": doc_id}}, separators=(",", ":")).encode(),
                  json.dumps(doc, separators=(",", ":")).encode()]
        written += 1
        if written % chunk_size == 0: send_bulk(lines); lines = []
    if lines: send_bulk(lines)
    osreq(f"/{SRC}/_refresh", method="POST")
    elapsed = time.perf_counter() - started
    print(json.dumps({"alerts": written, "seconds": round(elapsed, 3),
                      "alerts_per_second": round(written / elapsed, 1)}, indent=2))


def case_count(rule_id): return count(CASES, {"prefix": {"correlation_key": f"{rule_id}|"}})
def linked(agent_query): return count(ALERTS, scoped(agent_query, {"exists": {"field": "case_id"}}))


def measure(ids):
    acted = {"bool": {"minimum_should_match": 1, "should": [term("status", "closed"),
             term("status", "in_progress"), {"exists": {"field": "case_id"}},
             {"exists": {"field": "assigned_to"}}]}}
    actual = {
        "total_synced": count(ALERTS, scoped()),
        "immediate_user_cases": case_count(ids["A"]),
        "immediate_user_linked": linked(term("agent.name", "wam-bench-a")),
        "burst_srcip_cases": case_count(ids["B"]),
        "burst_srcip_linked": linked(term("agent.name", "wam-bench-b")),
        "boolean_group_cases": case_count(ids["C"]),
        "boolean_group_linked": linked(term("agent.name", "wam-bench-c")),
        "immediate_agent_cases": case_count(ids["D"]),
        "immediate_agent_linked": linked({"prefix": {"agent.name": "wam-bench-d-"}}),
        "closed_alerts": count(ALERTS, scoped(term("agent.name", "wam-bench-e"), term("status", "closed"))),
        "assigned_in_progress": count(ALERTS, scoped(term("agent.name", "wam-bench-f"), term("status", "in_progress"), term("assigned_to", "admin"))),
        "cooccurrence_cases": case_count(ids["G"]),
        "cooccurrence_linked": linked({"prefix": {"agent.name": "wam-bench-g-"}}),
        "false_actions_on_controls": count(ALERTS, scoped(term("agent.name", "wam-bench-control"), acted)),
    }
    mismatches = {k: {"expected": EXPECTED[k], "actual": v} for k, v in actual.items() if v != EXPECTED[k]}
    return {"expected": EXPECTED, "actual": actual, "passed": not mismatches, "mismatches": mismatches}


def queue():
    result = apireq("/system/automation/queue")
    states = result.get("states", {}) or {}
    return {
        "active": int(states.get("pending", 0)) + int(states.get("claimed", 0)) + int(states.get("retry", 0)),
        "reportedLag": int(result.get("lag", 0)),
        "deferred": int(result.get("deferred", 0)),
        "failed": int(states.get("failed", 0)) + int(result.get("dlq", 0)),
        "pending": int(states.get("pending", 0)),
        "claimed": int(states.get("claimed", 0)),
        "retry": int(states.get("retry", 0)),
        "admissionOpen": bool(result.get("admissionOpen", False)),
    }


def configure_queue(max_backlog, max_deferred, paused=False):
    result = apireq("/system/automation/queue/settings", {
        "paused": paused,
        "maxBacklog": max_backlog,
        "maxDeferred": max_deferred,
    }, "PUT")
    print(json.dumps(result, indent=2, sort_keys=True))


def sync(enabled):
    result = apireq("/system/sync/settings", {"enabled": enabled, "intervalSeconds": 15}, "PUT")
    print(json.dumps(result, indent=2, sort_keys=True))


def wait(ids, timeout, interval):
    started = time.perf_counter(); high = {"active": 0, "deferred": 0, "failed": 0}; last = None
    while time.perf_counter() - started < timeout:
        elapsed = round(time.perf_counter() - started, 3)
        try:
            health = queue()
            for key in high: high[key] = max(high[key], health[key])
            last = measure(ids)
        except (RuntimeError, urllib.error.URLError) as error:
            print(json.dumps({"elapsed_seconds": elapsed, "transient_error": str(error)}), flush=True)
            time.sleep(interval)
            continue
        print(json.dumps({"elapsed_seconds": elapsed, "synced": last["actual"]["total_synced"], "queue": health}), flush=True)
        if last["passed"] and not any(health[k] for k in ("active", "deferred", "failed")):
            return {**last, "end_to_end_seconds": elapsed, "queue_high_water": high, "queue_final": health}
        time.sleep(interval)
    return {**(last or measure(ids)), "timed_out": True,
            "end_to_end_seconds": round(time.perf_counter()-started, 3),
            "queue_high_water": high, "queue_final": queue()}


def storage():
    output = {}
    for pattern in (SRC, "wazuh-alert-status-v2-*", "wazuh-alert-manager-v2-*"):
        try:
            stats = osreq(f"/{pattern}/_stats/store,docs").get("_all", {}).get("primaries", {})
            output[pattern] = {"documents": int(stats.get("docs", {}).get("count", 0)),
                               "bytes": int(stats.get("store", {}).get("size_in_bytes", 0))}
        except RuntimeError as error: output[pattern] = {"error": str(error)}
    return output


def document_bounds():
    response = osreq(f"/{CASES}/_search", {
        "size": 1000,
        "track_total_hits": True,
        "_source": ["alert_ids", "evidence_count", "history", "correlation"],
        "query": {"match_all": {}},
    }, "POST")
    hits = response.get("hits", {}).get("hits", [])
    def length(value): return len(value) if isinstance(value, list) else 0
    return {
        "case_count": int(response.get("hits", {}).get("total", {}).get("value", 0)),
        "max_alert_id_preview": max((length(h.get("_source", {}).get("alert_ids")) for h in hits), default=0),
        "max_history_entries": max((length(h.get("_source", {}).get("history")) for h in hits), default=0),
        "max_evidence_count": max((int(h.get("_source", {}).get("evidence_count", 0)) for h in hits), default=0),
        "sum_evidence_count": sum(int(h.get("_source", {}).get("evidence_count", 0)) for h in hits),
    }


def load_ids(value):
    if os.path.isfile(value):
        with open(value, encoding="utf-8") as handle: return json.load(handle)
    return json.loads(value)


def main():
    parser = argparse.ArgumentParser(); commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("rules")
    inject_parser = commands.add_parser("inject"); inject_parser.add_argument("--chunk-size", type=int, default=2000)
    measure_parser = commands.add_parser("measure"); measure_parser.add_argument("--rule-ids", required=True)
    wait_parser = commands.add_parser("wait"); wait_parser.add_argument("--rule-ids", required=True)
    wait_parser.add_argument("--timeout", type=int, default=1800); wait_parser.add_argument("--interval", type=int, default=15)
    commands.add_parser("bounds"); commands.add_parser("health"); commands.add_parser("queue"); commands.add_parser("storage")
    queue_config = commands.add_parser("queue-config")
    queue_config.add_argument("--max-backlog", type=int, default=200000)
    queue_config.add_argument("--max-deferred", type=int, default=500000)
    queue_config.add_argument("--paused", action="store_true")
    commands.add_parser("sync-on"); commands.add_parser("sync-off")
    args = parser.parse_args()
    if not PW: parser.error("Set WAM_PW; this kit never stores credentials")
    if args.command == "rules": create_rules()
    elif args.command == "inject": inject(args.chunk_size)
    elif args.command == "measure": print(json.dumps(measure(load_ids(args.rule_ids)), indent=2, sort_keys=True))
    elif args.command == "wait":
        result = wait(load_ids(args.rule_ids), args.timeout, args.interval)
        print(json.dumps(result, indent=2, sort_keys=True)); return 0 if result.get("passed") and not result.get("timed_out") else 1
    elif args.command == "bounds": print(json.dumps(document_bounds(), indent=2, sort_keys=True))
    elif args.command == "health": print(json.dumps(apireq("/system/health"), indent=2, sort_keys=True))
    elif args.command == "queue": print(json.dumps(queue(), indent=2, sort_keys=True))
    elif args.command == "queue-config": configure_queue(args.max_backlog, args.max_deferred, args.paused)
    elif args.command == "storage": print(json.dumps(storage(), indent=2, sort_keys=True))
    elif args.command == "sync-on": sync(True)
    elif args.command == "sync-off": sync(False)
    return 0


if __name__ == "__main__": sys.exit(main())
