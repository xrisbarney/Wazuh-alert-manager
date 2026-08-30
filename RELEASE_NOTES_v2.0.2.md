# Wazuh Alert Manager 2.0.2

Version 2.0.2 is the scale and reliability patch for the v2 workbench.

## Reliability and scale

- Processes durable automation admissions in bounded batches with parallel,
  rule-affine execution lanes, fenced claims, retries and restart recovery.
- Coalesces matching alerts into their deduplicated case route before writing,
  preventing avoidable case-update contention during dense bursts.
- Uses exact queue, alert and reporting totals; no 2,000/10,000-hit sampling.
- Keeps case documents bounded while the paginated evidence family remains the
  exact source of linked-alert truth. Cases store an exact `evidence_count` and
  a bounded preview rather than growing without limit.
- Holds plugin startup readiness until owned index families are provisioned.

## Cases and UI

- Adds pagination to linked alerts in the case flyout.
- Fixes case visibility and optimistic-concurrency races after automated or
  manual creation.
- Preserves deterministic case claims across generation rollover.

## Benchmark result

The release was gated by clean 100,000-alert trials on Wazuh 4.14. Exact
ground-truth checks cover immediate rules, entity bursts, Boolean groups,
co-occurrence, status/assignment actions and 87,200 negative controls. The
published evidence records projection/drain timing, queue high-water marks,
storage, environment metadata and checksums. This single-node synthetic result
is reproducibility evidence, not a universal production-capacity claim.

## Compatibility

Release assets are built independently for Wazuh 4.12, 4.13 and 4.14
(OpenSearch Dashboards 2.19.1, 2.19.2 and 2.19.5). Native Wazuh alert indices
remain read-only. Existing v1/v2 plugin data is migrated or retained safely.
