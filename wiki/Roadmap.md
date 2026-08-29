# Roadmap

## Version 2.0 baseline

Version 2 replaces the legacy single heavy index with plugin-owned numeric
generations behind read/write aliases. Rollover covers operational alerts,
activity, cases, and evidence relationships. Retirement and purge remain
separate, reviewed actions; native `wazuh-alerts-*` stays read-only.

The release also includes resumable legacy migration, bounded evidence snapshots,
case and evidence rollover, archived-case reopen, hold-aware archive purge,
exact aggregation-based reports, durable automation queues, Boolean entity
triggers, and explicit graph truncation at the safety ceiling.

## After 2.0

- Add asynchronous, saved report jobs and immutable signed exports for compliance
  users who need a frozen record rather than the live/unarchived operational view.
- Add graph expansion and server-side neighborhood queries for investigations
  larger than the bounded interactive graph.
- Add lifecycle scheduling windows, dry-run diffs, notification hooks, and backup
  attestations before purge.
- Add configurable SLA policies with versioned policy history. Version 2 uses the
  documented fixed policy and exact write-time reporting fields.
- Add case templates, evidence export packages, richer collaboration, and external
  ticketing/webhook actions with encrypted secret storage.
- Continue validating every release against the actual Wazuh 4.12, 4.13, and 4.14
  dashboard source trees and browser smoke suites.
