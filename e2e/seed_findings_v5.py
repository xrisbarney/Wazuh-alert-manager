#!/usr/bin/env python3
"""Seed test-owned Wazuh 5.0-shaped findings (plus their underlying events).

Writes ONLY to two plugin-test data streams, `wazuh-findings-v5-wam-e2e` and
`wazuh-events-v5-wam-e2e`, created from test-owned index templates. Their
backing indices (`.ds-wazuh-findings-v5-wam-e2e-00000N`) satisfy the plugin's
approved 5.0 source matcher, so sync, hydration and the second hop to the
event can be exercised without touching a real Wazuh category stream.

Document shape follows a live Wazuh 5.0.0-rc2 finding
(runtime-evidence/phase1-5.0-rc2/findings-sample-rc2.json): identity under
`wazuh.agent.*`, rule context under `wazuh.rule.*` with a LABEL in
`wazuh.rule.level`, ECS `source.*`/`user.*`/`process.*`, provenance in
`event.index`/`event.doc_id`, and a nanosecond `@timestamp`.

Usage (never store credentials in this file):
  WAM_PW=... WAM_INDEXER=https://192.168.56.20:9200 python3 e2e/seed_findings_v5.py [--count 8] [--severity low]
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from benchmark import bench  # noqa: E402

FINDINGS_STREAM = "wazuh-findings-v5-wam-e2e"
EVENTS_STREAM = "wazuh-events-v5-wam-e2e"
TEMPLATE_PREFIX = "wam-e2e-"

COMMON_MAPPINGS = bench.V5_TEST_MAPPINGS


def ensure_stream(name: str) -> None:
    """Create the test-owned template and data stream if they do not exist."""
    bench.ensure_v5_stream(name)


def write_index(stream: str) -> str:
    """The physical backing index a data stream currently writes to."""
    info = bench.osreq(f"/_data_stream/{stream}")
    indices = info["data_streams"][0]["indices"]
    return indices[-1]["index_name"]


def nanos(base: dt.datetime, offset: int) -> str:
    stamp = base + dt.timedelta(milliseconds=offset)
    return stamp.strftime("%Y-%m-%dT%H:%M:%S.%f") + f"{offset % 1000:03d}Z"


def bulk_create(stream: str, docs: list[dict]) -> list[str]:
    lines: list[bytes] = []
    for doc in docs:
        lines.append(json.dumps({"create": {"_index": stream}}, separators=(",", ":")).encode())
        lines.append(json.dumps(doc, separators=(",", ":")).encode())
    result = bench.req(bench.OS, "/_bulk?refresh=true", b"\n".join(lines) + b"\n", "POST", "application/x-ndjson")
    if result.get("errors"):
        failures = [i for i in result.get("items", []) if i.get("create", {}).get("error")]
        raise RuntimeError(f"Bulk failures: {failures[:2]}")
    return [item["create"]["_id"] for item in result["items"]]


def event_doc(stamp: str, agent: str, address: str, user: str, port: int, original: str) -> dict:
    return {
        "@timestamp": stamp,
        "message": original,
        "event": {"kind": "event", "category": ["authentication"], "type": ["start"], "original": original},
        "host": {"hostname": agent},
        "source": {"ip": address, "port": port},
        "user": {"name": user},
        "process": {"name": "sshd", "pid": 4242},
        "wazuh": {
            "agent": {"id": "901", "name": agent, "groups": ["default"], "version": "v5.0.0", "host": {"hostname": agent, "ip": "192.0.2.10"}},
            "cluster": {"node": "node01", "name": "wazuh"},
            "integration": {"name": "system-auth", "category": "wam-e2e"},
            "protocol": {"location": "journald"},
            "space": {"name": "standard"},
        },
    }


def finding_doc(event: dict, event_index: str, event_id: str, severity: str, run: str, serial: int) -> dict:
    doc = json.loads(json.dumps(event))
    doc["event"]["index"] = event_index
    doc["event"]["doc_id"] = event_id
    doc["wazuh"]["rule"] = {
        "id": f"wam-e2e-{run}-rule",
        "title": f"Failed authentication attempt - {event['user']['name']}",
        "level": severity,
        "tags": [severity, "wam_e2e", "attack.credential_access", "attack.t1110"],
        "mitre": {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]},
        "status": "stable",
    }
    doc["message"] = f"[wam-e2e {run}#{serial}] {event['event']['original']}"
    return doc


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--count", type=int, default=8, help="findings to seed (default 8)")
    parser.add_argument("--severity", default="low", help="wazuh.rule.level label (default low)")
    args = parser.parse_args()
    if not os.environ.get("WAM_PW"):
        raise SystemExit("Set WAM_PW; credentials are never stored in this script")

    ensure_stream(EVENTS_STREAM)
    ensure_stream(FINDINGS_STREAM)
    event_index = write_index(EVENTS_STREAM)

    run = f"{time.time_ns()}"
    base = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=2)
    addresses = ["203.0.113.77"] * 2 + ["203.0.113.88"] * 3 + ["203.0.113.89"] * 3
    addresses = (addresses * ((args.count // len(addresses)) + 1))[: args.count]

    events = []
    for offset, address in enumerate(addresses, 1):
        user = f"wam-ui-{offset % 3}"
        original = f"Failed password for invalid user {user} from {address} port {40000 + offset} ssh2"
        events.append(event_doc(nanos(base, offset), "wam-e2e-agent", address, user, 40000 + offset, original))
    event_ids = bulk_create(EVENTS_STREAM, events)

    findings = [
        finding_doc(event, event_index, event_id, args.severity, run, serial)
        for serial, (event, event_id) in enumerate(zip(events, event_ids), 1)
    ]
    finding_ids = bulk_create(FINDINGS_STREAM, findings)

    print(json.dumps({
        "seeded": len(finding_ids),
        "findings_stream": FINDINGS_STREAM,
        "findings_index": write_index(FINDINGS_STREAM),
        "events_index": event_index,
        "severity": args.severity,
        "run": run,
    }))


if __name__ == "__main__":
    main()
