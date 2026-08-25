# Reporting

The **Reporting** app (second entry in the nav group) summarises alert and case activity over a time range you choose with the date picker. It has an **Overview** tab plus per-analyst tabs.

## Overview

- **KPI tiles** — Total alerts, Open / In progress / Closed, Mean time to assign, Mean time to resolve, and SLA compliance. Time-based tiles carry an info tooltip explaining exactly how they're measured.
- **Period-over-period deltas** — each KPI shows a **▲/▼ %** vs the immediately preceding equal-length window. Colour encodes *better/worse*, not just direction (a rising resolve time is red; a rising SLA % is green). Hover for the prior value.
- **Alert volume per day** — an area trend.
- **Status over time** — a **stacked** daily chart of Open / In progress / Closed, so you can see disposition shift across the window.
- **Alerts by status** and **Cases by severity** — donut charts with a count-legend (dot · label · count · %) and a centre total.
- **SLA breakdown by severity** — resolved / within-SLA / breached / compliance %, against the severity-based targets.
- **Cases** — created count, status split, and mean time to close.

### Accuracy notes

- **Total alerts** and the **status breakdown** are exact (aggregations over the full match, not a sample).
- **Time-based metrics** (MTTR / MTTA / SLA) are computed over a bounded sample of the period; when the sample is truncated, the UI says so. Narrow the time range for exact figures on very high-volume periods.

## SLA targets

| Severity | Wazuh level | Target |
|----------|-------------|--------|
| Critical | 12+ | 1 hour |
| High | 7–11 | 4 hours |
| Medium | 4–6 | 24 hours |
| Low | 0–3 | 3 days |

SLA compliance is the share of *resolved* alerts closed within their severity's target.

## Per-analyst tabs

- **Workload** — open / in-progress / closed / total per assignee.
- **Performance** — resolved count and mean time to resolve per analyst (sample-based, like the overall figure).
- **Cases by analyst** — case status split and mean time to close per owner (includes an In-progress column).
- **Leaderboard** — analysts ranked by throughput.
