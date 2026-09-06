# Version 2.0.2 scope

This page records the scope and known boundaries of version 2.0.2. It is not a future-release roadmap.

## Shipped scope

- A bounded projection of selected Wazuh alert fields in plugin-owned storage; native `wazuh-alerts-*` indices remain read-only.
- Numeric rollover generations for alert projections, activity, cases, and evidence, all behind read/write aliases.
- Reviewed retirement, insert-only restore, archived-case reopen, holds, retention guards, and separately confirmed purge.
- Resumable migration from legacy plugin indices without deleting the migration sources.
- Evidence-first case membership with exact counts, paginated case alert lists, and a 1,000-ID compatibility preview.
- Immediate and correlated-burst automation, Boolean entity groups, deterministic deduplication, case caps, saved ruleset snapshots, a durable queue, leased worker lanes, retries, executions, and dead-letter handling.
- Exact live-data reporting without alert sampling.
- Alert and case workflow, comments, audit activity, attack-path and MITRE views, deterministic related-alert suggestions, and optional guarded AI analysis.
- Exact-version build archives for the supported Wazuh 4.12, 4.13, and 4.14 dashboard releases.

## Current boundaries

- Reports are operational views of live, unarchived data, not immutable compliance snapshots.
- Automation is prospective. Enabling a rule does not apply it retroactively to historical alerts.
- Active Response commands to Wazuh agents are not included.
- Full archived alert payloads depend on the referenced retained physical generation. A case evidence stub remains after an authorized purge, but the purged payload cannot be reconstructed by the plugin.
- The interactive attack graph is intentionally bounded and reports truncation when its safety ceiling is reached.
- Plugin installation is required on every OpenSearch Dashboards replica that may serve the application; agents and manager-only or indexer-only nodes do not receive the dashboard plugin.
