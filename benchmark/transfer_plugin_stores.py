#!/usr/bin/env python3
"""Copy the plugin-owned stores from one indexer to another (lab tooling).

Used for the v3 platform-transition scenario: bring a populated Wazuh 4.x
plugin dataset (cases, evidence, activity, alert projections, rules, meta) to
a Wazuh 5.0 indexer, install the 5.0 build, and verify old cases and evidence
stay usable while new findings are admitted without replaying the 4.x cursor.

Only `wazuh-alert-status-v2-*` and `wazuh-alert-manager-v2-*` indices are ever
read or written. Native Wazuh storage on either side is never touched. The
target indices are created with the SOURCE index's mappings (dynamic: false
preserved) and the same read/write aliases, so the plugin recognizes them on
first start and runs its own additive mapping upgrade.

Usage (never store credentials in this file):
  WAM_SRC=https://192.168.56.21:9200 WAM_SRC_USER=admin WAM_SRC_PW=... \
  WAM_DST=https://192.168.56.20:9200 WAM_DST_USER=admin WAM_DST_PW=... \
  python3 benchmark/transfer_plugin_stores.py [--dry-run] [--max-docs N]
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

ALLOWED_PREFIXES = ("wazuh-alert-status-v2-", "wazuh-alert-manager-v2-")


class Cluster:
    def __init__(self, base: str, user: str, password: str) -> None:
        if not base or not password:
            raise SystemExit("Set WAM_SRC/WAM_DST, WAM_SRC_USER/WAM_DST_USER and WAM_SRC_PW/WAM_DST_PW")
        self.base = base.rstrip("/")
        self.auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def req(self, path: str, body=None, method: str = "GET", content_type: str = "application/json"):
        data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
        request = urllib.request.Request(self.base + path, data=data, method=method)
        request.add_header("Authorization", self.auth)
        request.add_header("Content-Type", content_type)
        try:
            with urllib.request.urlopen(request, context=self.ctx, timeout=300) as response:
                payload = response.read()
                return json.loads(payload) if payload else {}
        except urllib.error.HTTPError as error:
            details = error.read().decode(errors="replace")
            raise RuntimeError(f"{method} {path} failed ({error.code}): {details[:400]}") from error


def owned(name: str) -> bool:
    return name.startswith(ALLOWED_PREFIXES) and "*" not in name


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dry-run", action="store_true", help="list what would be copied")
    parser.add_argument("--max-docs", type=int, default=0, help="cap documents per index (0 = all)")
    parser.add_argument("--batch", type=int, default=1000)
    args = parser.parse_args()

    src = Cluster(os.environ.get("WAM_SRC", ""), os.environ.get("WAM_SRC_USER", "admin"), os.environ.get("WAM_SRC_PW", ""))
    dst = Cluster(os.environ.get("WAM_DST", ""), os.environ.get("WAM_DST_USER", "admin"), os.environ.get("WAM_DST_PW", ""))

    indices = sorted(
        entry["index"] for entry in src.req("/_cat/indices/wazuh-alert-status-v2-*,wazuh-alert-manager-v2-*?format=json&h=index")
        if owned(entry["index"])
    )
    if not indices:
        raise SystemExit("No plugin-owned indices found on the source")
    aliases = src.req("/_alias/wazuh-alert-status-v2-*,wazuh-alert-manager-v2-*")

    existing = {entry["index"] for entry in dst.req("/_cat/indices/wazuh-alert-status-v2-*,wazuh-alert-manager-v2-*?format=json&h=index")}
    if existing:
        raise SystemExit(f"Target already has plugin indices ({sorted(existing)[:3]}...); refusing to merge. Clean it first (benchmark/reset_v2.py).")

    plan = []
    for index in indices:
        count = int(src.req(f"/{index}/_count")["count"])
        plan.append((index, count, sorted(aliases.get(index, {}).get("aliases", {}).items())))
    print(json.dumps({"plan": [{"index": i, "docs": c, "aliases": [a for a, _ in al]} for i, c, al in plan]}, indent=2))
    if args.dry_run:
        return 0

    total = 0
    for index, count, alias_items in plan:
        if not owned(index):
            raise RuntimeError(f"Refusing unowned index {index}")
        meta = src.req(f"/{index}")[index]
        mappings = meta["mappings"]
        settings = {"number_of_shards": 1, "number_of_replicas": 0}
        blocks = meta.get("settings", {}).get("index", {}).get("blocks", {})
        dst.req(f"/{index}", {"settings": settings, "mappings": mappings}, "PUT")
        copied = 0
        res = src.req(f"/{index}/_search?scroll=2m", {"size": args.batch, "sort": ["_doc"], "seq_no_primary_term": False}, "POST")
        scroll = res.get("_scroll_id")
        while True:
            hits = res.get("hits", {}).get("hits", [])
            if not hits:
                break
            lines = []
            for hit in hits:
                if args.max_docs and copied >= args.max_docs:
                    break
                lines.append(json.dumps({"index": {"_index": index, "_id": hit["_id"]}}, separators=(",", ":")).encode())
                lines.append(json.dumps(hit["_source"], separators=(",", ":")).encode())
                copied += 1
            if lines:
                result = dst.req("/_bulk", b"\n".join(lines) + b"\n", "POST", "application/x-ndjson")
                if result.get("errors"):
                    failures = [i for i in result["items"] if i.get("index", {}).get("error")]
                    raise RuntimeError(f"Bulk failures on {index}: {failures[:2]}")
            if args.max_docs and copied >= args.max_docs:
                break
            res = src.req("/_search/scroll", {"scroll": "2m", "scroll_id": scroll}, "POST")
        if scroll:
            try:
                src.req("/_search/scroll", {"scroll_id": [scroll]}, "DELETE")
            except RuntimeError:
                pass
        dst.req(f"/{index}/_refresh", method="POST")
        if alias_items:
            actions = []
            for alias, config in alias_items:
                action = {"index": index, "alias": alias}
                if config.get("is_write_index") is not None:
                    action["is_write_index"] = bool(config["is_write_index"])
                actions.append({"add": action})
            dst.req("/_aliases", {"actions": actions}, "POST")
        if blocks.get("write") in ("true", True):
            # Retired/archived generations stay write-blocked on the target too.
            dst.req(f"/{index}/_settings", {"index.blocks.write": True}, "PUT")
        total += copied
        print(json.dumps({"index": index, "copied": copied, "of": count, "aliases": [a for a, _ in alias_items]}))
    print(json.dumps({"total_copied": total, "indices": len(plan)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
