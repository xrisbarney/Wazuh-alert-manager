import { buildReportingUpdate, slaForLevel, REPORTING_SLA_POLICY } from './reporting_fields';
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
