// Write-time operational reporting fields so MTTA/MTTR/SLA and per-analyst
// resolution figures are exact for the live, unarchived cohort without walking
// unbounded history arrays or sampling. Updated idempotently wherever an alert
// is assigned, closed, or reopened (manual bulk-update, automation, backfill).

import { BAND_LEVEL_RANGES, effectiveLevel, severityBandOf, SeverityBand } from '../../common/severity';
import { ALERT_STATUSES, SLA_BANDS, SLA_DUE_SOON_MINUTES, SLA_STATES } from '../../common/constants';
import type { AlertReporting, SlaBand, SlaPolicy, SlaState, SlaTarget } from '../../common/types';

export const REPORTING_FIELD_VERSION = 1;

export interface ReportingSlaTier {
  minLevel: number;
  label: string;
  targetMinutes: number;
}

// Shared, single source of truth for the severity SLA policy. Reports and the
// write-time projection both consume this so they can never disagree.
export const REPORTING_SLA_POLICY: ReportingSlaTier[] = [
  { minLevel: 12, label: 'Critical', targetMinutes: 60 },
  { minLevel: 7, label: 'High', targetMinutes: 240 },
  { minLevel: 4, label: 'Medium', targetMinutes: 1440 },
  { minLevel: 0, label: 'Low', targetMinutes: 4320 },
];

/**
 * Built-in per-band targets (step 3.1): the resolve targets of
 * `REPORTING_SLA_POLICY` with an assign target of 25% of the resolve target,
 * floored at 15 minutes. `DEFAULT_SLA_POLICY` (server/lib/sla/policy.ts) is
 * built from this table; the due-date helpers below fall back to it when no
 * stored policy is passed.
 */
export const DEFAULT_SLA_TARGETS: Readonly<Record<SlaBand, SlaTarget>> = Object.freeze(
  SLA_BANDS.reduce((acc, band) => {
    const tier = REPORTING_SLA_POLICY.find((t) => t.minLevel === BAND_LEVEL_RANGES[band]!.min)!;
    acc[band] = { resolveMinutes: tier.targetMinutes, assignMinutes: Math.max(15, Math.round(tier.targetMinutes * 0.25)) };
    return acc;
  }, {} as Record<SlaBand, SlaTarget>)
);

/** Display label of a band inside the stored `reporting.sla_tier` field (unchanged since v2). */
export const SLA_BAND_LABELS: Record<SlaBand, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

/**
 * The tier list (`minLevel` descending) of a stored SLA policy (step 3.1), in
 * the same shape as `REPORTING_SLA_POLICY` so every existing consumer
 * (reports, Markdown summaries, write-time projection) can take a configured
 * policy without changing shape. Band floors come from common/severity.ts.
 */
export function policyToTiers(policy: SlaPolicy): ReportingSlaTier[] {
  return SLA_BANDS.map((band) => ({
    minLevel: BAND_LEVEL_RANGES[band]!.min,
    label: SLA_BAND_LABELS[band],
    targetMinutes: policy.targets[band].resolveMinutes,
  }));
}

/**
 * SLA tier of a numeric level. Without a policy the built-in
 * `REPORTING_SLA_POLICY` applies; callers that have loaded the stored policy
 * (`getSlaPolicy` in server/lib/sla/policy.ts) pass it so the configured
 * targets are the single source of truth.
 */
export function slaForLevel(level: number, policy?: SlaPolicy | null): ReportingSlaTier {
  const tiers = policy ? policyToTiers(policy) : REPORTING_SLA_POLICY;
  return tiers.find((tier) => level >= tier.minLevel) || tiers[tiers.length - 1];
}

export type AlertReportingFields = AlertReporting;

// ---------------------------------------------------------------------------
// Due timestamps (step 3.2)
// ---------------------------------------------------------------------------

export interface AlertDueFields {
  /** `@timestamp` + the band's resolve target; null when the record has no severity. */
  sla_due_at: string | null;
  /** `@timestamp` + the band's first-assignment target; null when the record has no severity. */
  assign_due_at: string | null;
}

/** Map any severity band onto an SLA band: `informational` (5.0 label only) counts as `low`. */
export function slaBandOfSeverity(band: SeverityBand | SlaBand | null | undefined): SlaBand | null {
  if (band == null) return null;
  return band === 'critical' || band === 'high' || band === 'medium' ? band : 'low';
}

/** The policy's target of a band, falling back to the built-in table band by band. */
export function slaTargetOf(policy: SlaPolicy | null | undefined, band: SlaBand): SlaTarget {
  const target = policy?.targets?.[band];
  const defaults = DEFAULT_SLA_TARGETS[band];
  return {
    resolveMinutes: typeof target?.resolveMinutes === 'number' ? target.resolveMinutes : defaults.resolveMinutes,
    assignMinutes: typeof target?.assignMinutes === 'number' ? target.assignMinutes : defaults.assignMinutes,
  };
}

function plusMinutes(baseMs: number, minutes: number): string {
  return new Date(baseMs + minutes * 60000).toISOString();
}

/**
 * Due timestamps of a canonical alert record at first projection: both
 * adapters call this through the projection so a 4.x numeric level and a
 * 5.0 label-only finding resolve to the same band model
 * (`severityBandOf` / `effectiveLevel` in common/severity.ts). Without a
 * numeric level or a recognised label both fields are null (never guessed).
 * `now` is the base only when the record carries no parsable `@timestamp`.
 */
export function computeDueFields(
  source: any,
  policy?: SlaPolicy | null,
  now: string = new Date().toISOString()
): AlertDueFields {
  const band = slaBandOfSeverity(severityBandOf(source));
  if (!band) return { sla_due_at: null, assign_due_at: null };
  const parsed = Date.parse(source?.['@timestamp'] || '');
  const baseMs = Number.isFinite(parsed) ? parsed : Date.parse(now);
  if (!Number.isFinite(baseMs)) return { sla_due_at: null, assign_due_at: null };
  const target = slaTargetOf(policy, band);
  return {
    sla_due_at: plusMinutes(baseMs, target.resolveMinutes),
    assign_due_at: plusMinutes(baseMs, target.assignMinutes),
  };
}

/**
 * Due date of a case: `created_at` + the resolve target of its severity. Case
 * severities map 1:1 onto the SLA bands. Null when the severity is unknown
 * or `created_at` does not parse.
 */
export function computeCaseDueAt(severity: unknown, createdAt: unknown, policy?: SlaPolicy | null): string | null {
  const band = (SLA_BANDS as readonly string[]).includes(String(severity)) ? (severity as SlaBand) : null;
  if (!band) return null;
  const baseMs = Date.parse(typeof createdAt === 'string' ? createdAt : '');
  if (!Number.isFinite(baseMs)) return null;
  return plusMinutes(baseMs, slaTargetOf(policy, band).resolveMinutes);
}

/** Alert/case statuses whose due date still counts (a closed record is never breached). */
export const SLA_ACTIVE_STATUSES: readonly string[] = ALERT_STATUSES.filter((status) => status !== 'closed');

export function isSlaState(value: unknown): value is SlaState {
  return typeof value === 'string' && (SLA_STATES as readonly string[]).includes(value);
}

/**
 * OpenSearch filter clause for an `slaState` list filter over `dueField`
 * (`reporting.sla_due_at` on alerts, `sla_due_at` on cases):
 *   breached  = due date in the past AND status open|in_progress
 *   due_soon  = due within SLA_DUE_SOON_MINUTES and not breached (same statuses)
 *   on_track  = the rest that has a due date (same statuses)
 */
export function slaStateClause(state: SlaState, dueField: string, now: string = new Date().toISOString()): any {
  const nowMs = Date.parse(now);
  const soon = new Date(nowMs + SLA_DUE_SOON_MINUTES * 60000).toISOString();
  const status = { terms: { status: [...SLA_ACTIVE_STATUSES] } };
  if (state === 'breached') return { bool: { filter: [{ range: { [dueField]: { lt: now } } }, status] } };
  if (state === 'due_soon') return { bool: { filter: [{ range: { [dueField]: { gte: now, lte: soon } } }, status] } };
  return { bool: { filter: [{ range: { [dueField]: { gt: soon } } }, status] } };
}

export interface ReportingChange {
  status?: string | null;
  assignedTo?: string | null;
}

function minutesBetween(occurredMs: number, atMs: number): number | null {
  if (!Number.isFinite(occurredMs)) return null;
  const diff = (atMs - occurredMs) / 60000;
  return diff >= 0 ? diff : null;
}

function levelOf(source: any): number {
  // 4.x: numeric rule.level. 5.0: the lowest level of the label's band so a
  // label-only finding never claims a stricter SLA tier (common/severity.ts).
  return effectiveLevel(source) ?? 0;
}

/**
 * Compute the complete next `reporting` object for an alert after a status or
 * assignment change. Reads the existing reporting object and the alert's own
 * `@timestamp`/`assigned_to`/`rule.level` so the result is idempotent and never
 * clobbers an unrelated concurrent sub-field (the caller merges sub-fields, or
 * the writer uses optimistic concurrency). Returns null when nothing changes.
 * `policy` is the stored SLA policy (step 3.1); omitted = built-in defaults.
 * The due timestamps (`sla_due_at` / `assign_due_at`, step 3.2) are never part
 * of the result: every caller merges the result key by key
 * (`REPORTING_MERGE_SCRIPT`), so leaving them out keeps the stored values,
 * including a recompute by the due-date backfill that landed after `source`
 * was read.
 */
export function buildReportingUpdate(
  source: any,
  changes: ReportingChange,
  now: string = new Date().toISOString(),
  policy?: SlaPolicy | null
): AlertReportingFields | null {
  const { sla_due_at: _dueAt, assign_due_at: _assignDueAt, ...existing } = (source?.reporting as AlertReportingFields) || {};
  const occurredMs = Date.parse(source?.['@timestamp'] || '');
  const nowMs = Date.parse(now);
  const next: AlertReportingFields = { ...existing };
  let changed = false;

  if (changes.assignedTo) {
    if (next.first_assigned_at == null && next.assign_minutes == null) {
      next.first_assigned_at = now;
      next.assign_minutes = minutesBetween(occurredMs, nowMs);
      changed = true;
    }
  }

  if (changes.status != null) {
    if (changes.status === 'closed') {
      const resolveMinutes = minutesBetween(occurredMs, nowMs);
      const tier = slaForLevel(levelOf(source), policy);
      next.closed_at = now;
      next.resolve_minutes = resolveMinutes;
      next.assignee_at_close = changes.assignedTo != null ? changes.assignedTo : (source?.assigned_to ?? null);
      next.sla_tier = tier.label;
      next.sla_met = resolveMinutes != null ? resolveMinutes <= tier.targetMinutes : null;
      changed = true;
    } else {
      if (
        next.closed_at != null ||
        next.resolve_minutes != null ||
        next.assignee_at_close != null ||
        next.sla_tier != null ||
        next.sla_met != null
      ) {
        changed = true;
      }
      next.closed_at = null;
      next.resolve_minutes = null;
      next.assignee_at_close = null;
      next.sla_tier = null;
      next.sla_met = null;
    }
  }

  if (!changed) return null;
  next.reporting_version = REPORTING_FIELD_VERSION;
  return next;
}

// Painless fragment for the sync upsert: seeds the due timestamps of a freshly
// projected record (`params.doc.reporting`) only when the stored document has
// none, so an overlap replay or a later policy change never rewrites them
// during normal sync; a policy change runs server/lib/sla/due_backfill.ts.
export const REPORTING_DUE_SEED_SCRIPT = `
  if (params.doc.reporting != null) {
    if (ctx._source.reporting == null) { ctx._source.reporting = [:]; }
    if (ctx._source.reporting.sla_due_at == null && params.doc.reporting.sla_due_at != null) {
      ctx._source.reporting.sla_due_at = params.doc.reporting.sla_due_at;
    }
    if (ctx._source.reporting.assign_due_at == null && params.doc.reporting.assign_due_at != null) {
      ctx._source.reporting.assign_due_at = params.doc.reporting.assign_due_at;
    }
  }
`;

// Painless fragment that merges reporting sub-fields into ctx._source.reporting
// without replacing the whole object, so a concurrent close cannot erase a
// concurrently recorded first assignment. Callers bind `params.reporting`.
export const REPORTING_MERGE_SCRIPT = `
  if (ctx._source.reporting == null) { ctx._source.reporting = [:]; }
  if (params.reporting != null) {
    for (entry in params.reporting.entrySet()) {
      ctx._source.reporting[entry.getKey()] = entry.getValue();
    }
  }
`;
