import {
  buildReportingUpdate,
  computeCaseDueAt,
  computeDueFields,
  DEFAULT_SLA_TARGETS,
  REPORTING_DUE_SEED_SCRIPT,
  slaForLevel,
  slaStateClause,
  REPORTING_SLA_POLICY,
} from './reporting_fields';
import { deriveAlertReporting } from './report_metrics';

const source = (overrides: any = {}) => ({
  '@timestamp': '2026-08-28T10:00:00.000Z',
  status: 'open',
  assigned_to: null,
  rule: { level: 8 },
  history: [],
  ...overrides,
});

describe('reporting write-time fields', () => {
  test('records the first assignment only once', () => {
    const first = buildReportingUpdate(source(), { assignedTo: 'alice' }, '2026-08-28T10:10:00.000Z');
    expect(first?.first_assigned_at).toBe('2026-08-28T10:10:00.000Z');
    expect(first?.assign_minutes).toBe(10);

    // A later reassignment must not overwrite the first-assignment time; the
    // reporting object is unchanged so the update is a no-op (null).
    const second = buildReportingUpdate(
      source({ reporting: first, assigned_to: 'alice' }),
      { assignedTo: 'bob' },
      '2026-08-28T10:20:00.000Z'
    );
    expect(second).toBeNull();
  });

  test('records resolution and SLA on close', () => {
    const reporting = buildReportingUpdate(
      source({ reporting: { first_assigned_at: '2026-08-28T10:10:00.000Z', assign_minutes: 10 } }),
      { status: 'closed', assignedTo: 'alice' },
      '2026-08-28T14:00:00.000Z'
    );
    expect(reporting?.resolve_minutes).toBe(240);
    expect(reporting?.assignee_at_close).toBe('alice');
    expect(reporting?.sla_tier).toBe('High');
    expect(reporting?.sla_met).toBe(true);
    expect(reporting?.closed_at).toBe('2026-08-28T14:00:00.000Z');
  });

  test('uses the existing assignee at close when no new assignment arrives', () => {
    const reporting = buildReportingUpdate(
      source({ assigned_to: 'alice' }),
      { status: 'closed' },
      '2026-08-28T14:00:00.000Z'
    );
    expect(reporting?.assignee_at_close).toBe('alice');
  });

  test('clears resolution fields on reopen', () => {
    const reporting = buildReportingUpdate(
      source({
        status: 'closed',
        reporting: { closed_at: '2026-08-28T14:00:00.000Z', resolve_minutes: 240, sla_tier: 'High', sla_met: true },
      }),
      { status: 'open' },
      '2026-08-28T15:00:00.000Z'
    );
    expect(reporting?.closed_at).toBeNull();
    expect(reporting?.resolve_minutes).toBeNull();
    expect(reporting?.sla_tier).toBeNull();
    expect(reporting?.sla_met).toBeNull();
  });

  test('returns null when nothing changes', () => {
    expect(buildReportingUpdate(source(), {})).toBeNull();
  });
});

describe('SLA policy', () => {
  test('selects the correct tier for each severity level', () => {
    expect(slaForLevel(12).label).toBe('Critical');
    expect(slaForLevel(7).label).toBe('High');
    expect(slaForLevel(4).label).toBe('Medium');
    expect(slaForLevel(0).label).toBe('Low');
  });

  test('exposes a monotonic policy', () => {
    expect(REPORTING_SLA_POLICY[0].minLevel).toBe(12);
    expect(REPORTING_SLA_POLICY[REPORTING_SLA_POLICY.length - 1].minLevel).toBe(0);
  });
});

describe('deriveAlertReporting backfill', () => {
  test('materializes timing from embedded history', () => {
    const reporting = deriveAlertReporting(
      source({
        status: 'closed',
        assigned_to: 'alice',
        history: [
          { timestamp: '2026-08-28T10:10:00.000Z', action: 'assignment_change', to: 'alice' },
          { timestamp: '2026-08-28T14:00:00.000Z', action: 'status_change', to: 'closed' },
        ],
      })
    );
    expect(reporting.first_assigned_at).toBe('2026-08-28T10:10:00.000Z');
    expect(reporting.assign_minutes).toBe(10);
    expect(reporting.closed_at).toBe('2026-08-28T14:00:00.000Z');
    expect(reporting.resolve_minutes).toBe(240);
    expect(reporting.assignee_at_close).toBe('alice');
    expect(reporting.sla_tier).toBe('High');
    expect(reporting.reporting_version).toBe(1);
  });

  test('leaves timing empty for a never-touched open alert', () => {
    const reporting = deriveAlertReporting(source());
    expect(reporting.first_assigned_at).toBeNull();
    expect(reporting.closed_at).toBeNull();
    expect(reporting.sla_tier).toBeNull();
  });
});

describe('due timestamps (step 3.2)', () => {
  const policy = {
    targets: {
      critical: { resolveMinutes: 30, assignMinutes: 5 },
      high: { resolveMinutes: 120, assignMinutes: 20 },
      medium: { resolveMinutes: 600, assignMinutes: 60 },
      low: { resolveMinutes: 2880, assignMinutes: 240 },
    },
    escalations: [],
  };
  const ts = '2026-11-21T10:00:00.000Z';
  const plus = (minutes: number) => new Date(Date.parse(ts) + minutes * 60000).toISOString();

  test('computeDueFields for every band from a 4.x numeric level', () => {
    expect(computeDueFields({ '@timestamp': ts, rule: { level: 12 } }, policy)).toEqual({ sla_due_at: plus(30), assign_due_at: plus(5) });
    expect(computeDueFields({ '@timestamp': ts, rule: { level: 15 } }, policy)).toEqual({ sla_due_at: plus(30), assign_due_at: plus(5) });
    expect(computeDueFields({ '@timestamp': ts, rule: { level: 7 } }, policy)).toEqual({ sla_due_at: plus(120), assign_due_at: plus(20) });
    expect(computeDueFields({ '@timestamp': ts, rule: { level: 11 } }, policy)).toEqual({ sla_due_at: plus(120), assign_due_at: plus(20) });
    expect(computeDueFields({ '@timestamp': ts, rule: { level: 4 } }, policy)).toEqual({ sla_due_at: plus(600), assign_due_at: plus(60) });
    expect(computeDueFields({ '@timestamp': ts, rule: { level: 3 } }, policy)).toEqual({ sla_due_at: plus(2880), assign_due_at: plus(240) });
    expect(computeDueFields({ '@timestamp': ts, rule: { level: 0 } }, policy)).toEqual({ sla_due_at: plus(2880), assign_due_at: plus(240) });
  });

  test('computeDueFields for a 5.0 label-only record goes through the band model (informational = low)', () => {
    const labelOnly = (label: string) => ({ '@timestamp': ts, rule: { id: 'r', level: null }, severity_label: label });
    expect(computeDueFields(labelOnly('critical'), policy)).toEqual({ sla_due_at: plus(30), assign_due_at: plus(5) });
    expect(computeDueFields(labelOnly('high'), policy).sla_due_at).toBe(plus(120));
    expect(computeDueFields(labelOnly('Medium'), policy).sla_due_at).toBe(plus(600));
    expect(computeDueFields(labelOnly('low'), policy).sla_due_at).toBe(plus(2880));
    expect(computeDueFields(labelOnly('informational'), policy)).toEqual({ sla_due_at: plus(2880), assign_due_at: plus(240) });
  });

  test('computeDueFields is null without a level and without a recognised label, and without a timestamp base', () => {
    expect(computeDueFields({ '@timestamp': ts }, policy)).toEqual({ sla_due_at: null, assign_due_at: null });
    expect(computeDueFields({ '@timestamp': ts, rule: { id: 'r', level: null }, severity_label: 'bogus' }, policy)).toEqual({ sla_due_at: null, assign_due_at: null });
    expect(computeDueFields({ '@timestamp': ts, rule: { id: 'r', level: null }, severity_label: null }, policy)).toEqual({ sla_due_at: null, assign_due_at: null });
    // No parsable @timestamp: `now` is the base.
    expect(computeDueFields({ rule: { level: 12 } }, policy, ts)).toEqual({ sla_due_at: plus(30), assign_due_at: plus(5) });
    expect(computeDueFields({ rule: { level: 12 } }, policy, 'nope')).toEqual({ sla_due_at: null, assign_due_at: null });
  });

  test('without a policy the built-in targets apply (and they equal the REPORTING_SLA_POLICY resolve targets)', () => {
    expect(DEFAULT_SLA_TARGETS).toEqual({
      critical: { resolveMinutes: 60, assignMinutes: 15 },
      high: { resolveMinutes: 240, assignMinutes: 60 },
      medium: { resolveMinutes: 1440, assignMinutes: 360 },
      low: { resolveMinutes: 4320, assignMinutes: 1080 },
    });
    expect(computeDueFields({ '@timestamp': ts, rule: { level: 8 } })).toEqual({ sla_due_at: plus(240), assign_due_at: plus(60) });
    expect(computeDueFields({ '@timestamp': ts, rule: { level: 8 } }, null)).toEqual({ sla_due_at: plus(240), assign_due_at: plus(60) });
  });

  test('computeCaseDueAt maps case severities 1:1 onto the bands', () => {
    expect(computeCaseDueAt('critical', ts, policy)).toBe(plus(30));
    expect(computeCaseDueAt('high', ts, policy)).toBe(plus(120));
    expect(computeCaseDueAt('medium', ts, policy)).toBe(plus(600));
    expect(computeCaseDueAt('low', ts, policy)).toBe(plus(2880));
    expect(computeCaseDueAt('low', ts)).toBe(plus(4320));
    expect(computeCaseDueAt('urgent', ts, policy)).toBeNull();
    expect(computeCaseDueAt('high', null, policy)).toBeNull();
  });

  test('slaStateClause builds the breached / due_soon / on_track bool clauses over the active statuses', () => {
    const now = ts;
    const soon = plus(60);
    expect(slaStateClause('breached', 'reporting.sla_due_at', now)).toEqual({
      bool: { filter: [{ range: { 'reporting.sla_due_at': { lt: now } } }, { terms: { status: ['open', 'in_progress'] } }] },
    });
    expect(slaStateClause('due_soon', 'sla_due_at', now)).toEqual({
      bool: { filter: [{ range: { sla_due_at: { gte: now, lte: soon } } }, { terms: { status: ['open', 'in_progress'] } }] },
    });
    expect(slaStateClause('on_track', 'sla_due_at', now)).toEqual({
      bool: { filter: [{ range: { sla_due_at: { gt: soon } } }, { terms: { status: ['open', 'in_progress'] } }] },
    });
  });

  test('the upsert seed fragment only sets the due fields when the stored document has none', () => {
    expect(REPORTING_DUE_SEED_SCRIPT).toContain('if (ctx._source.reporting.sla_due_at == null && params.doc.reporting.sla_due_at != null)');
    expect(REPORTING_DUE_SEED_SCRIPT).toContain('if (ctx._source.reporting.assign_due_at == null && params.doc.reporting.assign_due_at != null)');
    expect(REPORTING_DUE_SEED_SCRIPT).not.toMatch(/ctx\._source\.reporting = params/);
  });

  test('buildReportingUpdate never carries the due fields, so a key-by-key merge leaves the stored ones alone', () => {
    const base = source({ reporting: { sla_due_at: plus(240), assign_due_at: plus(60) } });
    const closed = buildReportingUpdate(base, { status: 'closed' }, '2026-08-28T10:10:00.000Z')!;
    expect(closed).toMatchObject({ sla_met: true });
    expect(closed).not.toHaveProperty('sla_due_at');
    expect(closed).not.toHaveProperty('assign_due_at');
    const reopened = buildReportingUpdate(
      source({ reporting: { ...closed, sla_due_at: plus(240), assign_due_at: plus(60) } }),
      { status: 'open' },
      '2026-08-28T10:20:00.000Z'
    )!;
    expect(reopened).toMatchObject({ closed_at: null });
    expect(reopened).not.toHaveProperty('sla_due_at');
    expect(reopened).not.toHaveProperty('assign_due_at');
    const assigned = buildReportingUpdate(base, { assignedTo: 'alice' }, '2026-08-28T10:05:00.000Z')!;
    expect(assigned.first_assigned_at).toBe('2026-08-28T10:05:00.000Z');
    expect(Object.keys(assigned)).not.toEqual(expect.arrayContaining(['sla_due_at', 'assign_due_at']));
  });
});
