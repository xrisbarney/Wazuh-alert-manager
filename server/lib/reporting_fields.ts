// Write-time operational reporting fields so MTTA/MTTR/SLA and per-analyst
// resolution figures are exact for the live, unarchived cohort without walking
// unbounded history arrays or sampling. Updated idempotently wherever an alert
// is assigned, closed, or reopened (manual bulk-update, automation, backfill).

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

export function slaForLevel(level: number): ReportingSlaTier {
  return (
    REPORTING_SLA_POLICY.find((tier) => level >= tier.minLevel) ||
    REPORTING_SLA_POLICY[REPORTING_SLA_POLICY.length - 1]
  );
}

export interface AlertReportingFields {
  first_assigned_at?: string | null;
  assign_minutes?: number | null;
  closed_at?: string | null;
  resolve_minutes?: number | null;
  assignee_at_close?: string | null;
  sla_tier?: string | null;
  sla_met?: boolean | null;
  reporting_version?: number;
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
  const level = source?.rule?.level;
  return level != null ? Number(level) : 0;
}

/**
 * Compute the complete next `reporting` object for an alert after a status or
 * assignment change. Reads the existing reporting object and the alert's own
 * `@timestamp`/`assigned_to`/`rule.level` so the result is idempotent and never
 * clobbers an unrelated concurrent sub-field (the caller merges sub-fields, or
 * the writer uses optimistic concurrency). Returns null when nothing changes.
 */
export function buildReportingUpdate(
  source: any,
  changes: ReportingChange,
  now: string = new Date().toISOString()
): AlertReportingFields | null {
  const existing: AlertReportingFields = (source?.reporting as AlertReportingFields) || {};
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
      const tier = slaForLevel(levelOf(source));
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
