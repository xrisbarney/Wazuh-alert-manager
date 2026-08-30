#!/usr/bin/env python3
"""Seed fresh, test-owned native-format alerts for the headed UI bench."""

from __future__ import annotations

import datetime as dt
import json
import os
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from benchmark import bench


INDEX = "wazuh-alerts-4.x-wam-e2e"


def main() -> None:
    if not os.environ.get("WAM_PW"):
        raise SystemExit("Set WAM_PW; credentials are never stored in this script")
    bench.SRC = INDEX
    try:
        bench.osreq(f"/{INDEX}", {
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": {"dynamic": True},
        }, "PUT")
    except RuntimeError as error:
        if "resource_already_exists_exception" not in str(error):
            raise

    run = f"{time.time_ns()}"
    now = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=2)
    addresses = ["203.0.113.77"] * 2 + ["203.0.113.88"] * 3 + ["203.0.113.89"] * 3
    lines = []
    for offset, address in enumerate(addresses, 1):
        doc_id = f"wam-e2e-{run}-{offset}"
        document = bench.document(
            bench.iso(now, offset), "wam-e2e-agent", "930001", 10, "UI",
            srcip=address, dstport=22, srcuser="wam-ui",
        )
        lines.extend([
            json.dumps({"index": {"_index": INDEX, "_id": doc_id}}, separators=(",", ":")).encode(),
            json.dumps(document, separators=(",", ":")).encode(),
        ])
    bench.send_bulk(lines)
    bench.osreq(f"/{INDEX}/_refresh", method="POST")
    print(json.dumps({"seeded": len(addresses), "index": INDEX, "run": run}))


if __name__ == "__main__":
    main()
