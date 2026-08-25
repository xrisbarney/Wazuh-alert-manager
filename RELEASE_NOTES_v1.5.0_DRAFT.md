# v1.5.0 — draft release notes (overnight build)

> Working draft assembled during the autonomous build. **Nothing is committed** — all changes are uncommitted in the working tree for you to review, adjust, and commit yourself.

## Theme: correctness and trust before features

This release deliberately leads with the foundations. Five design reviews converged on the same finding — the plugin's capabilities were ahead of its correctness — and three defects were actively losing or leaking data. Those are fixed first; visible polish follows.

## Fixed — data-integrity / security (the important ones)

- **Sync no longer silently loses alerts.** The background sync searched an unsorted `batchSize` (default 10k) and advanced its watermark unconditionally, so any window with >10k matching alerts kept an arbitrary subset and lost the rest forever. It now sorts ascending and advances the watermark only to the last alert actually copied. (`server/lib/sync_job.ts`)
- **Plugin-owned fields are protected on resync.** The scripted copy loop was key-agnostic and could let a same-named Wazuh field clobber an analyst's `status`/`case_id`/`assigned_to`/history on the next resync. A protected-field guard now prevents that.
- **AI analysis no longer sends raw documents off-network.** Previously the entire alert `_source` (and every linked alert's `_source` plus up to 200 comment bodies) went to the LLM provider. Now an allowlist **projection boundary** (`server/lib/egress/projection.ts`) is the only thing that can leave the network — raw `_source` is a compile error there. Comment bodies are never sent (only a count); `full_log` is truncated.
- **Identity is no longer spoofable for attribution.** Removed the `x-forwarded-user` request-header fallback from user resolution; identity now comes only from the OpenSearch Security plugin (`server/lib/identity.ts`), with an explicit `anonymous` state when it can't be established.
- **Reporting metrics are honest.** Status counts and totals now come from an aggregation over the full match (they reconcile exactly); MTTR/MTTA/SLA remain sample-based and are labelled as such. Fixed an MTTA miscount where a status-only bulk change was counted as an assignment.

## Fixed — upgrades / robustness

- **Mapping changes now reach upgraded installs.** `provision.ts` previously never applied new mappings to an existing index. An idempotent `ensureMappingAdditions()` + `MAPPING_VERSION` now migrates them; incompatible changes fail safe (logged, non-fatal).
- **Long/opportunistic fields are aggregatable.** Added `dynamic_templates` mapping `data.*`, `syscheck.*`, `rule.mitre.*` strings to `keyword` at 1024 chars (were silently dropping at 256).
- **Bounded inputs.** `maxSize` caps on case alert-id arrays; graph route tolerates scalar MITRE fields (was 500-ing on some decoders).

## Improved — look & feel / smoothness

- **One design system** (`public/design.ts`): severity bands standardised on 12/7/4 (were contradicting across three files); lifecycle status given a cool colour ramp so EUI `danger` is reserved for genuinely high severity instead of being spent on every `open` row; one shared time formatter.
- **Severity badges** show label + level (colour is never the sole signal).
- **Reports gets charts** (`@elastic/charts`, no new dependency): alert-volume-per-day trend, status bar, case-severity bar — plus the honest denominators kept.
- **Cases table** is now sortable (the sort affordance was previously dead) with client pagination and severity badges.
- **Dark-mode fix**: removed a hardcoded panel colour in the bulk-actions bar.
- **Fewer wasted fetches**: the alerts view no longer double-fetches on Apply or dead-ends on a time-range change; the case flyout trusts the authoritative update response instead of reloading over it.
- **Checkbox bug fixed**: selecting an alert's checkbox no longer opens the detail flyout, so multi-select actually works. A row click still opens the flyout; clicking the checkbox, actions, or any control on the row does not.
- **Metric tooltips**: Reports' mean-time-to-assign / resolve / SLA tiles now carry info tooltips explaining exactly how each is measured (and that time-based metrics are sample-based).

## New — SOC workbench features

- **Automation rules** (Settings → Automation rules). A rule matches alerts (rule groups / rule IDs / agents / min level), fires on a **trigger**, and takes one or more **actions**:
  - **Triggers:** *every matching alert* (per-alert) or *a burst on one entity* (group by agent, source/destination IP, source/destination user, or process; fire once ≥ N land on one entity within a window).
  - **Actions:** open a case (burst only, de-duplicated per rule+entity and rate-limited), set status (**auto-close** routine noise, or move to In progress), and/or assign to an analyst (**auto-assign**). Status/assign work on either trigger.
  - **Any-of / All-of** per match section — *All of* means the entity must have seen **every** listed value within the window (co-occurrence, e.g. rule 5510 **and** 5516 on one host), verified exactly via aggregation; applies to groups, IDs, and agents.
  - **Dry run** on every rule shows what it would have done over the last 24h before you enable it.
  - Server: `server/routes/rules.ts`, `server/lib/correlation*.ts`; evaluated under the sync leader-lock (single writer). Provenance is recorded on every auto-action.
- **Precedent lookup.** The alert flyout opens with a "seen before" callout — how the same rule has been handled on the same host (open/in-progress/closed counts + how many escalated to a case), flagging likely-routine noise. Deterministic, no LLM. (`/alerts/{id}/precedent`)
- **Suggested related alerts.** The Related Alerts tab now ranks other alerts that share a host, source IP, user, or rule within ±24h, with the shared-entity reasons and one-click **Link**. (`/alerts/{id}/suggested`)
- **Attack-path graph.** Case attack-path tab renders a dependency-free entity graph (hosts / accounts / techniques, co-occurrence edges) with robust pan/zoom; kill-chain table included.
- **Reporting** is multi-tab (Overview + per-analyst Workload / Performance / Cases-by-analyst / Leaderboard), with **donut** status/severity breakdowns, a count-legend, and **period-over-period ▲/▼ deltas** on the KPI tiles (colour = better/worse).
- **Navigation** is a collapsible group: **Workbench** (Alerts / Cases / Settings) and **Reporting**; the plugin title sits in the breadcrumb bar like the Wazuh modules.
- **In-progress** is a first-class status for both alerts and cases; default views show Open + In progress.

## Known conditions (read before deploying widely)

- On installs whose `wazuh-alert-status` index predates the explicit `assigned_to` keyword mapping, that field stays `text` (the migration fail-safes rather than forcing an incompatible change). A reindex is the only full fix. Fresh installs are unaffected.
- Corpus-wide features (future) require document-level security to be applied to `wazuh-alert-status` directly — restrictions on `wazuh-alerts-*` do not carry through the sync copy.

## Deliberately NOT in this release (staged for review)

**Active Response** (pushing commands back to agents) is intentionally not shipped — it warrants a dedicated security review of the command path and authorization model.

## Verification

Every change was built (TypeScript compile) and run through a 16-check regression smoke suite after each step, on a live Wazuh 4.14 install (16/16 throughout). The automation-rule model additionally passes an 11-case create/validate/dry-run matrix (per-alert & burst triggers, any/all coverage incl. agents, and the three rejection cases). Cross-version zips for 4.12 (OSD 2.19.1), 4.13 (2.19.2), and 4.14 (2.19.5) are rebuilt from the same source and refreshed in `Downloads/` — the server code is byte-identical across the three; only the target-version stamp differs.
