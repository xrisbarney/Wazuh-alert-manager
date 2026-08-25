# v1.5.1

A small patch release on top of [v1.5.0](RELEASE_NOTES_v1.5.0_DRAFT.md): it fixes a
correctness race in single-tick burst correlation and ships a reliability
benchmark / reproducibility kit. It contains everything in v1.5.0 (alert
lifecycle, cases, automation rules, precedent & suggested alerts, reporting).

## Fixed

- **Single-tick burst correlation no longer misses.** When an entire alert burst
  arrived within one sync interval, the automation engine could evaluate it
  *before* those alerts were search-refreshed in `wazuh-alert-status`, so the
  count raced the ~1 s refresh and a burst could be silently missed (and, because
  the alerts leave the next tick's window, never re-evaluated). The sync now
  refreshes the status index before running rule evaluation, making single-tick
  burst detection deterministic. (`server/lib/sync_job.ts`)

## Added

- **Reliability benchmark / reproducibility kit** (`benchmark/`). Injects a
  tagged 1,082-alert synthetic corpus with known-correct outcomes through the
  real sync → automation path and measures the engine's actions, including false
  actions on benign filler alerts. See `benchmark/README.md`.

## Verification

- Regression smoke: **16/16 passing** on Wazuh 4.14.
- Reliability run: **1,082 / 1,082 alerts handled correctly, 0 false actions on
  1,000 benign fillers** (cases opened, alerts auto-closed, auto-assigned, and
  co-occurrence all reproduced their ground truth exactly).

## Downloads (match the asset to your Wazuh version)

| Wazuh | OpenSearch Dashboards | Asset |
|-------|-----------------------|-------|
| 4.12  | 2.19.1 | `wazuhAlertManager-1.5.1-wazuh4.12.zip` |
| 4.13  | 2.19.2 | `wazuhAlertManager-1.5.1-wazuh4.13.zip` |
| 4.14  | 2.19.5 | `wazuhAlertManager-1.5.1-wazuh4.14.zip` |

Server code is identical across the three builds; only the target-version stamp
differs. Install/upgrade steps are unchanged — see the
[wiki](https://github.com/xrisbarney/Wazuh-alert-manager/wiki/Installation).
