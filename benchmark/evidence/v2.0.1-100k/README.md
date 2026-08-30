# v2.0.1 100k evidence

This directory preserves the sanitized, machine-readable outcome of the clean
30 August 2026 scale run. It contains no credentials, host addresses, cookies
or private key material.

The result is a **failed automation-drain benchmark** and must not be presented
as a positive 100k automation-capacity claim. Projection reached 100,000, but
98,616 queue items were pending at the deadline. Partial rule outcomes show
work completed before timeout; they do not establish complete correctness.

The exact queue aggregation used `track_total_hits: true`. This was necessary
because the released v2.0.1 health endpoint reported only 10,000 for a 100,000
item queue. The benchmark branch adds a focused regression-tested correction
for that observability bug and the equivalent Alerts-table total cap; worker
batching remains future work. The run also showed that rule-list `Last fired`
telemetry remains `Never` even after durable executions complete. That separate
summary-projection gap is documented but not silently attributed as fixed.

The run used a direct synthetic source index, so agent transmission and Wazuh
manager decoding are outside scope. See `../../README.md` for the scenario
matrix, safety boundary and reproduction procedure.
