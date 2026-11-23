#!/usr/bin/env python3
"""Remove the e2e-seeded (synthetic) alerts, cases, rules and their side
records from a dev stack so only the lab and manual data remain.

Dry run by default (prints what would be deleted); ``--apply`` deletes.

What goes (the records every mutating bench under ``e2e/`` creates):

* projected alerts of the seeder's agent ``wam-e2e-agent`` in every
  ``wazuh-alert-status-v2-*`` generation, and the seeder's own native-format
  index ``wazuh-alerts-4.x-wam-e2e`` (4.x) / the plugin-owned test data
  streams ``wazuh-findings-v5-wam-e2e`` and ``wazuh-events-v5-wam-e2e``
  written by ``e2e/seed_findings_v5.py`` (5.0) together with the test-owned
  index templates ``wam-e2e-<stream>`` that ``benchmark/bench.py`` creates
  for them;
* cases whose title starts with ``WAM e2e``, ``=WAM e2e`` or ``E2E ``;
* automation rules named ``E2E ...`` / ``WAM e2e...`` and their revision docs;
* the side records of those alerts, cases and rules: evidence links, activity
  (comments + alert/case audit + rule audit events), attachments, notification
  outbox entries and automation queue entries;
* the ``automation-preview:`` documents of the meta index.

Before the cases go, every non-synthetic alert the benches linked to one of
them (``full_ui.spec.ts`` links the first alerts of the live queue, whichever
agent they belong to) gets its ``case_id`` cleared, the same reset the unlink
path performs, so no real-agent alert is left owning a deleted case. Alerts
whose ``case_id`` already points at a missing case get the same reset.

Retired (write-blocked) generations are unblocked for the deletes and
blocked again afterwards, also when a delete fails. Nothing else is touched:
``Lab:`` cases, manually created cases, the real agent / manager alerts,
task lists, enrichment sources, settings and the lab enrichment cache stay.

Credentials are never stored here. They come from the repository's ignored
``.env.e2e.local`` (``WAM_SEED_URL`` / ``WAM_SEED_USERNAME`` /
``WAM_SEED_PASSWORD``, the variables ``e2e/helpers.ts#seedAlerts`` hands to
``seed_alerts.py``; ``WAM_E2E_USERNAME`` / ``WAM_E2E_PASSWORD`` are the
fallback, as there) or from the same variables in the environment, which win
over the file.

    python -I -X utf8 e2e/cleanup_synthetic.py            # dry run
    python -I -X utf8 e2e/cleanup_synthetic.py --apply    # delete

On the Wazuh 5.0 stack the credentials come from ``scripts/dev/env-5.0.sh``
(``source`` it first; its exported ``WAM_SEED_*`` win over ``.env.e2e.local``).
"""

from __future__ import annotations

import argparse
import base64
import datetime
import json
import os
import pathlib
import ssl
import sys
import time
import urllib.error
import urllib.request

SYNTHETIC_AGENT = "wam-e2e-agent"
SYNTHETIC_CASE_TITLE_PREFIXES = ["WAM e2e", "=WAM e2e", "E2E "]
SYNTHETIC_RULE_NAME_PREFIXES = ["E2E ", "WAM e2e"]
SYNTHETIC_NATIVE_INDICES = ["wazuh-alerts-4.x-wam-e2e"]
# Wazuh 5.0 line: `e2e/seed_findings_v5.py` writes only these two plugin-owned
# test data streams (`wazuh-*-v5-wam-*`), never a real native index.
SYNTHETIC_NATIVE_DATA_STREAMS = ["wazuh-findings-v5-wam-e2e", "wazuh-events-v5-wam-e2e"]
# `benchmark/bench.py#ensure_v5_stream` creates one index template per test stream.
V5_TEST_TEMPLATE_PREFIX = "wam-e2e-"
PREVIEW_META_PREFIX = "automation-preview:"
PAGE_SIZE = 10000

STATUS_PATTERN = "wazuh-alert-status-v2-*"
CASES_PATTERN = "wazuh-alert-manager-v2-cases-*"
# Case existence must also see the pre-alias singleton: on a stack where
# `migrateCaseAliases()` has not run, every case still lives there and alerts
# pointing into it are NOT orphans.
CASES_SINGLETON = "wazuh-alert-manager-v2-cases"
CASES_READ = f"{CASES_SINGLETON},{CASES_PATTERN}"
EVIDENCE_PATTERN = "wazuh-alert-manager-v2-evidence-*"
ACTIVITY_PATTERN = "wazuh-alert-manager-v2-activity-*"
ATTACHMENTS_INDEX = "wazuh-alert-manager-v2-attachments"
NOTIFICATIONS_INDEX = "wazuh-alert-manager-v2-notifications"
AUTOMATION_QUEUE_INDEX = "wazuh-alert-manager-v2-automation-queue"
RULES_INDEX = "wazuh-alert-manager-v2-rules"
META_INDEX = "wazuh-alert-manager-v2-meta"


def read_env_file(path: pathlib.Path) -> dict[str, str]:
    """KEY=VALUE lines of a dotenv file (comments and blanks skipped, quotes stripped)."""
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def credentials() -> tuple[str, str, str]:
    env_file = read_env_file(pathlib.Path(__file__).resolve().parents[1] / ".env.e2e.local")

    def pick(*names: str, default: str | None = None) -> str | None:
        for name in names:
            if os.environ.get(name):
                return os.environ[name]
        for name in names:
            if env_file.get(name):
                return env_file[name]
        return default

    url = (pick("WAM_SEED_URL", default="https://localhost:9200") or "").rstrip("/")
    user = pick("WAM_SEED_USERNAME", "WAM_E2E_USERNAME", default="admin") or "admin"
    password = pick("WAM_SEED_PASSWORD", "WAM_E2E_PASSWORD")
    if not password:
        raise SystemExit("Set WAM_SEED_PASSWORD (or WAM_E2E_PASSWORD) in .env.e2e.local or the environment; "
                         "credentials are never stored in this script")
    return url, user, password


class Indexer:
    def __init__(self, base: str, user: str, password: str) -> None:
        self.base = base
        self.auth = base64.b64encode(f"{user}:{password}".encode()).decode()
        # Dev stacks use self-signed certificates (same as helpers.ts#indexerRequest).
        self.ctx = ssl._create_unverified_context()

    def request(self, method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            self.base + path, data=data, method=method,
            headers={"Authorization": "Basic " + self.auth, "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=120) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read() or b"{}")

    def search_ids(self, index: str, query: dict, source: list[str] | None = None) -> list[tuple[str, str, dict]]:
        """(index, id, source) of every hit (one page of `index.max_result_window`; the sets here are small)."""
        body: dict = {"size": PAGE_SIZE, "query": query, "_source": source or False, "track_total_hits": True}
        status, data = self.request("POST", f"/{index}/_search?ignore_unavailable=true", body)
        if status == 404:
            return []
        if status != 200:
            raise RuntimeError(f"search {index} failed: {status} {data}")
        total = int(data["hits"]["total"]["value"])
        if total > PAGE_SIZE:
            raise RuntimeError(f"search {index} matched {total} documents, more than one page ({PAGE_SIZE}); narrow the query")
        return [(hit["_index"], hit["_id"], hit.get("_source") or {}) for hit in data["hits"]["hits"]]

    def count(self, index: str, query: dict) -> int:
        status, data = self.request("POST", f"/{index}/_count?ignore_unavailable=true", {"query": query})
        if status == 404:
            return 0
        if status != 200:
            raise RuntimeError(f"count {index} failed: {status} {data}")
        return int(data.get("count", 0))

    def update_by_query(self, index: str, query: dict, script: dict) -> int:
        status, data = self.request(
            "POST", f"/{index}/_update_by_query?conflicts=proceed&refresh=true&ignore_unavailable=true",
            {"query": query, "script": script},
        )
        if status == 404:
            return 0
        if status != 200 or data.get("failures"):
            raise RuntimeError(f"update_by_query {index} failed: {status} {data}")
        return int(data.get("updated", 0))

    def delete_by_query(self, index: str, query: dict) -> int:
        status, data = self.request(
            "POST", f"/{index}/_delete_by_query?conflicts=proceed&refresh=true&ignore_unavailable=true", {"query": query}
        )
        if status == 404:
            return 0
        if status != 200 or data.get("failures"):
            raise RuntimeError(f"delete_by_query {index} failed: {status} {data}")
        return int(data.get("deleted", 0))

    def write_blocked_indices(self, patterns: list[str]) -> list[str]:
        """Concrete indices under the patterns whose `index.blocks.write` is true (retired generations)."""
        status, data = self.request(
            "GET", f"/{','.join(patterns)}/_settings/index.blocks.write?flat_settings=true&ignore_unavailable=true"
        )
        if status == 404:
            return []
        if status != 200:
            raise RuntimeError(f"settings read failed: {status} {data}")
        return sorted(
            name for name, body in data.items()
            if str((body.get("settings") or {}).get("index.blocks.write", "")).lower() == "true"
        )

    def set_write_block(self, index: str, blocked: bool) -> int:
        status, data = self.request("PUT", f"/{index}/_settings", {"index.blocks.write": blocked})
        if status != 200:
            raise RuntimeError(f"write block {index}={blocked} failed: {status} {data}")
        return status

    def index_exists(self, index: str) -> bool:
        status, _ = self.request("HEAD", f"/{index}")
        return status == 200

    def delete_index(self, index: str) -> int:
        status, data = self.request("DELETE", f"/{index}")
        if status not in (200, 404):
            raise RuntimeError(f"delete index {index} failed: {status} {data}")
        return status

    def data_stream_exists(self, stream: str) -> bool:
        status, _ = self.request("GET", f"/_data_stream/{stream}")
        return status == 200

    def index_template_exists(self, name: str) -> bool:
        status, _ = self.request("GET", f"/_index_template/{name}")
        return status == 200

    def delete_index_template(self, name: str) -> int:
        status, data = self.request("DELETE", f"/_index_template/{name}")
        if status not in (200, 404):
            raise RuntimeError(f"delete index template {name} failed: {status} {data}")
        return status

    def delete_data_stream(self, stream: str) -> int:
        """Delete a data stream and its backing `.ds-*` indices (5.0 seeder output)."""
        status, data = self.request("DELETE", f"/_data_stream/{stream}")
        if status not in (200, 404):
            raise RuntimeError(f"delete data stream {stream} failed: {status} {data}")
        return status


def terms(field: str, values: list[str]) -> dict:
    return {"terms": {field: values}}


def any_of(*clauses: dict) -> dict:
    return {"bool": {"should": list(clauses), "minimum_should_match": 1}}


def main() -> int:
    parser = argparse.ArgumentParser(description="Remove the e2e-seeded synthetic data from a dev stack.")
    parser.add_argument("--apply", action="store_true", help="delete (default: dry run that only counts)")
    args = parser.parse_args()
    apply = args.apply

    base, user, password = credentials()
    es = Indexer(base, user, password)
    print(f"{'APPLY' if apply else 'DRY RUN'} against {base} as {user}")

    # 0. The seeder's own sources go FIRST, before any id is read: the sync job
    #    runs every 30-60 s, so a tick between the id snapshot and the source
    #    delete would re-project synthetic records (status rows whose side
    #    records were already deleted, or side records keyed on a stale id
    #    list). Once the sources are gone no further projection can occur.
    for index in SYNTHETIC_NATIVE_INDICES:
        if not es.index_exists(index):
            print(f"native index {index}: absent")
        elif apply:
            print(f"delete index {index}: {es.delete_index(index)}")
        else:
            print(f"would delete index {index}")

    for stream in SYNTHETIC_NATIVE_DATA_STREAMS:
        if not es.data_stream_exists(stream):
            print(f"native data stream {stream}: absent")
        elif apply:
            print(f"delete data stream {stream}: {es.delete_data_stream(stream)}")
        else:
            print(f"would delete data stream {stream}")
        # The test-owned template outlives the stream; drop it too.
        template = f"{V5_TEST_TEMPLATE_PREFIX}{stream}"
        if not es.index_template_exists(template):
            print(f"test index template {template}: absent")
        elif apply:
            print(f"delete index template {template}: {es.delete_index_template(template)}")
        else:
            print(f"would delete index template {template}")

    # 1. Synthetic alerts: the projected rows of the seeder's agent (and their alert_uid aliases).
    status_rows = es.search_ids(STATUS_PATTERN, {"term": {"agent.name": SYNTHETIC_AGENT}}, ["alert_uid"])
    alert_ids = sorted({row[1] for row in status_rows} | {row[2]["alert_uid"] for row in status_rows if row[2].get("alert_uid")})
    print(f"synthetic projected alerts: {len(status_rows)} (ids {len(alert_ids)})")

    # 2. Cases: every title prefix the benches create.
    case_query = any_of(*[{"prefix": {"title.keyword": prefix}} for prefix in SYNTHETIC_CASE_TITLE_PREFIXES])
    cases = es.search_ids(CASES_PATTERN, case_query, ["title"])
    case_ids = sorted({row[1] for row in cases})
    kept_cases = es.search_ids(CASES_PATTERN, {"bool": {"must_not": case_query}}, ["title"])
    print(f"cases to delete: {len(case_ids)}; cases kept: {sorted(row[2].get('title', '') for row in kept_cases)}")

    # 3. Rules: named e2e rules plus their revision docs.
    rule_query = any_of(*[{"prefix": {"name.keyword": prefix}} for prefix in SYNTHETIC_RULE_NAME_PREFIXES])
    rules = es.search_ids(RULES_INDEX, rule_query, ["name"])
    rule_ids = sorted({row[1] for row in rules})
    kept_rules = es.search_ids(
        RULES_INDEX,
        {"bool": {"must_not": [{"ids": {"values": rule_ids}}, {"term": {"document_type": "rule_revision"}}]}},
        ["name"],
    )
    print(f"rules to delete: {len(rule_ids)}; rules kept: {sorted(row[2].get('name', '') for row in kept_rules)}")

    # 4. Automation preview documents of the meta index.
    preview_ids = [row[1] for row in es.search_ids(META_INDEX, {"match_all": {}}) if row[1].startswith(PREVIEW_META_PREFIX)]
    print(f"automation preview meta docs: {len(preview_ids)}")

    # 5. Non-synthetic alerts the benches linked to a synthetic case: their case_id is
    #    reset (as the unlink path does) before the case is deleted. Alerts whose
    #    case_id points at a case that no longer exists (left by an earlier run
    #    before this step existed) get the same reset.
    cases_resolvable = es.index_exists(CASES_SINGLETON) or es.index_exists(CASES_PATTERN)
    existing_case_ids = {row[1] for row in es.search_ids(CASES_READ, {"match_all": {}})} if cases_resolvable else set()
    linked_rows = es.search_ids(
        STATUS_PATTERN,
        {"bool": {"filter": [{"exists": {"field": "case_id"}}], "must_not": [{"term": {"agent.name": SYNTHETIC_AGENT}}]}},
        ["case_id"],
    )
    # A stack whose case indices do not resolve at all (pre-migration, or a
    # mis-targeted URL) must clear nothing: every case_id would look orphaned.
    orphan_alert_ids = sorted(
        row[1] for row in linked_rows
        if row[2].get("case_id") and row[2]["case_id"] not in existing_case_ids
    ) if cases_resolvable else []
    if not cases_resolvable:
        print(f"case indices ({CASES_READ}) resolve to nothing: skipping the orphan case_id reset")
    linked_real_query = {
        "bool": {
            "filter": [any_of(terms("case_id", case_ids), {"ids": {"values": orphan_alert_ids}})],
            "must_not": [{"term": {"agent.name": SYNTHETIC_AGENT}}],
        }
    }
    unlink_script = {
        "lang": "painless",
        "source": "ctx._source.case_id = null; ctx._source.updated_at = params.now",
        "params": {"now": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")},
    }
    print(f"real-agent alerts linked to synthetic cases (case_id to clear): {es.count(STATUS_PATTERN, linked_real_query)}"
          f" (of which case already missing: {len(orphan_alert_ids)})")

    targets = alert_ids + case_ids + rule_ids
    plan: list[tuple[str, dict]] = [
        (STATUS_PATTERN, {"term": {"agent.name": SYNTHETIC_AGENT}}),
        (CASES_PATTERN, {"ids": {"values": case_ids}}),
        (EVIDENCE_PATTERN, any_of(terms("case_id", case_ids), terms("alert_id", alert_ids))),
        (ACTIVITY_PATTERN, any_of(terms("case_id", case_ids), terms("alert_id", alert_ids), terms("target_id", targets))),
        (ATTACHMENTS_INDEX, terms("case_id", case_ids)),
        (NOTIFICATIONS_INDEX, terms("target_id", targets)),
        (AUTOMATION_QUEUE_INDEX, terms("alert_uid", alert_ids)),
        (RULES_INDEX, any_of({"ids": {"values": rule_ids}}, terms("rule_id", rule_ids))),
        (META_INDEX, {"ids": {"values": preview_ids}}),
    ]

    # Retired generations are write-blocked; lift the block for the deletes and put it back.
    retired = es.write_blocked_indices([STATUS_PATTERN, CASES_PATTERN, EVIDENCE_PATTERN, ACTIVITY_PATTERN])
    print(f"retired (write-blocked) generations: {retired or 'none'}")
    failed = False
    if apply:
        for index in retired:
            print(f"  unblock {index}: {es.set_write_block(index, False)}")
    try:
        if apply:
            print(f"cleared case_id on {STATUS_PATTERN}: {es.update_by_query(STATUS_PATTERN, linked_real_query, unlink_script)}")
        else:
            print(f"would clear case_id on {STATUS_PATTERN}: {es.count(STATUS_PATTERN, linked_real_query)}")
        for index, query in plan:
            if apply:
                print(f"deleted {index}: {es.delete_by_query(index, query)}")
            else:
                print(f"would delete {index}: {es.count(index, query)}")
        if apply:
            # Verify our own result instead of relying on a separate dry run: a
            # sync tick already in flight when the source went away can still
            # upsert its in-memory hits after the delete above.
            synthetic = {"term": {"agent.name": SYNTHETIC_AGENT}}
            residue = es.count(STATUS_PATTERN, synthetic)
            if residue:
                print(f"re-projected synthetic alerts after the delete: {residue}; retrying once in 20 s")
                time.sleep(20)
                print(f"deleted {STATUS_PATTERN} (retry): {es.delete_by_query(STATUS_PATTERN, synthetic)}")
                residue = es.count(STATUS_PATTERN, synthetic)
                if residue:
                    failed = True
                    print(f"ERROR {residue} synthetic projected alerts still in {STATUS_PATTERN}", file=sys.stderr)
            print(f"synthetic projected alerts remaining: {residue}")
    except RuntimeError as error:
        failed = True
        print(f"ERROR {error}", file=sys.stderr)
    finally:
        if apply:
            for index in retired:
                try:
                    print(f"  re-block {index}: {es.set_write_block(index, True)}")
                except RuntimeError as error:
                    failed = True
                    print(f"ERROR {error}", file=sys.stderr)

    if apply and not failed:
        remaining = es.search_ids(CASES_READ, {"match_all": {}}, ["title"]) if cases_resolvable else []
        print(f"cases remaining: {sorted(row[2].get('title', '') for row in remaining)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
