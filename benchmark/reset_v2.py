#!/usr/bin/env python3
"""Delete only verified Wazuh Alert Manager benchmark and optional legacy data."""

import argparse
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

USER = os.environ.get("WAM_USER", "admin")
PASSWORD = os.environ.get("WAM_PW", "")
BASE = os.environ.get("WAM_INDEXER", "https://localhost:9200").rstrip("/")
SOURCE = os.environ.get("WAM_BENCH_SOURCE_INDEX", "wazuh-alerts-4.x-wam-benchmark")
ALLOWED_PREFIXES = ("wazuh-alert-status-v2-", "wazuh-alert-manager-v2-")
LEGACY_V1_INDICES = {
    "wazuh-alert-status",
    "wazuh-alert-manager-comments",
    "wazuh-alert-manager-cases",
    "wazuh-alert-manager-rules",
    "wazuh-alert-manager-meta",
}


def request(path, method="GET"):
    req = urllib.request.Request(BASE + path, method=method)
    token = base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
    req.add_header("Authorization", f"Basic {token}")
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, context=context, timeout=120) as response:
            payload = response.read()
            return json.loads(payload) if payload else {}
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return {}
        raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--yes", action="store_true", help="confirm the destructive reset")
    parser.add_argument(
        "--include-legacy-v1",
        action="store_true",
        help="also delete the five exact legacy v1 plugin indices",
    )
    args = parser.parse_args()
    if not args.yes or not PASSWORD:
        parser.error("Set WAM_PW and pass --yes")

    indices = request("/_cat/indices?format=json&h=index")
    names = sorted({entry["index"] for entry in indices})
    targets = [name for name in names if name.startswith(ALLOWED_PREFIXES)]
    if SOURCE in names:
        targets.append(SOURCE)
    if args.include_legacy_v1:
        targets.extend(sorted(LEGACY_V1_INDICES.intersection(names)))
    for target in targets:
        if not (
            target == SOURCE
            or target.startswith(ALLOWED_PREFIXES)
            or (args.include_legacy_v1 and target in LEGACY_V1_INDICES)
        ):
            raise RuntimeError(f"Refusing unowned target: {target}")
        if "*" in target or target in ("wazuh-alerts-*", "wazuh-alerts-4.x-*"):
            raise RuntimeError(f"Refusing wildcard/native target: {target}")

    print(json.dumps({"deleting": targets}, indent=2))
    for target in targets:
        request("/" + target, "DELETE")
    print(json.dumps({"deleted": targets, "recoverable": False}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
