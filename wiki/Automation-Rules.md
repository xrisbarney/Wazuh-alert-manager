# Automation Rules

Automation rules act on alerts **as they arrive**. A rule has three parts:

1. **Match** — which alerts it applies to.
2. **Trigger** — *when* it fires.
3. **Actions** — *what* it does.

Manage rules under **Workbench → Settings → Automation rules**.

---

## 1. Match conditions

All specified conditions must hold (logical **AND**). Leave a field blank to skip it.

| Condition | Meaning |
|-----------|---------|
| **Rule groups** | Wazuh rule groups (e.g. `authentication_failed`, `pam`). |
| **Rule IDs** | Specific Wazuh rule IDs (e.g. `5710`, `5716`). |
| **Agents** | Restrict to specific agents/hosts. |
| **Min level** | Minimum Wazuh rule level. |

### Any-of vs All-of

Rule groups, Rule IDs, and Agents each have an **Any of / All of** toggle:

- **Any of** (default) — a matching alert has *any* listed value. This is **volume**.
- **All of** — the grouping entity must have seen **every** listed value within the window. This is **co-occurrence**.

> **Example.** `Rule IDs = 5510, 5516`, mode **All of**, grouped by host → the rule only fires when **both** 5510 **and** 5516 have occurred on the same host in the window. With **Any of**, either one contributes to the count.

Co-occurrence is evaluated exactly (via aggregation), across sync intervals, so `5510` in one tick and `5516` in the next still count as long as they fall inside the window.

---

## 2. Trigger

| Trigger | Fires… | Actions apply to… |
|---------|--------|-------------------|
| **Every matching alert** (per-alert) | on each matching alert at ingest | that alert |
| **A burst on one entity** | once **≥ threshold** matching alerts land on one entity within the **window** | the alerts in that burst |

**Burst** settings:

- **Group alerts by** — the entity that ties a burst together: Agent (host), Source IP, Destination IP, Source user, Destination user, or Process.
- **Threshold** — how many alerts are needed.
- **Window (minutes)** — the sliding window they must fall within.

> For an **All-of** rule that only needs "one of each", set the threshold to the number of required values (minimum 2). The threshold is a volume floor; coverage is checked separately.

---

## 3. Actions

Pick **at least one**. Any action works with either trigger (except *Create case*, which requires a burst).

| Action | Effect |
|--------|--------|
| **Set status** | Move matching alerts to **Open / In progress / Closed**. Setting **Closed** is your **auto-close** for routine noise. |
| **Assign to** | Route matching alerts (and any case opened) to an analyst. This is your **auto-assign**. Leave blank for no assignment. |
| **Open a case** *(burst only)* | Escalate the burst into a case at the chosen **severity**. |

### How create-case behaves

- Cases are **de-duplicated per rule + entity**: while a case for that rule and entity is still open, new matching alerts **extend it** rather than spawning duplicates.
- Case creation is **rate-limited** per evaluation pass, so a noisy source can't flood you.
- If **Assign to** is set, the created case is assigned to that analyst too.
- Every automated action is recorded in the alert/case **history** with a `rule:<id>` provenance entry.

---

## Dry run

Every rule has a **Dry run (last 24h)** button that shows what it *would* have done, before you enable it:

- **Per-alert** trigger → "*N matching alerts would be acted on*".
- **Burst** trigger → matching alerts, which entities would fire, and how many would open a case.

Dry run is read-only and never writes anything.

> The dry run is approximate — it counts matches over the lookback rather than a strict sliding window. Live evaluation uses the exact window you configured.

---

## Worked examples

**Auto-close a known-noisy rule**
Match `Rule IDs = 5502` → Trigger *Every matching alert* → Action *Set status = Closed*.

**Brute-force escalation**
Match `Rule groups = authentication_failed` → Trigger *Burst*, group by **Source IP**, threshold **10**, window **5 min** → Action *Open a High case* + *Assign to* an on-call analyst.

**Co-occurrence case**
Match `Rule IDs = 5510, 5516` (**All of**) → Trigger *Burst*, group by **Agent**, threshold **2**, window **30 min** → Action *Open a Critical case*.

---

## Safety & evaluation

- Rules are evaluated inside the background sync tick under a **leader lock**, so there is a single writer and no double-creation across replicas.
- Candidate work is bounded by each tick's batch, not the whole index.
- See [[Architecture]] for how evaluation fits into the sync job, and [[Security Model]] for why entity fields are treated carefully.
