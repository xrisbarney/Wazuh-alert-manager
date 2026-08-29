import { CorrelationRule } from '../../common';
import { planAutomation } from './automation_planner';
import { simulateAutomationPreview } from './automation_preview';

const now = new Date('2026-08-28T12:00:00.000Z');
const rule = (patch: any = {}): CorrelationRule => ({
  id: 'candidate',
  name: 'candidate',
  enabled: false,
  revision: 3,
  match: { ruleIds: ['100'] },
  trigger: { type: 'burst', entity: 'agent', threshold: 3, windowMinutes: 5 },
  actions: { createCase: true, caseSeverity: 'high', setStatus: 'closed', assignTo: 'robot' },
  preconditions: { statuses: ['open'], assignment: 'unassigned' },
  safety: { acknowledgeMatchAll: false },
  ...patch,
} as CorrelationRule);
const alert = (id: string, minute: number, source: any = {}) => ({
  id,
  source: {
    '@timestamp': `2026-08-28T11:${String(minute).padStart(2, '0')}:00.000Z`,
    status: 'open',
    assigned_to: null,
    agent: { name: 'host-a' },
    rule: { id: '100', groups: ['auth'], level: 8 },
    ...source,
  },
});

describe('exact automation preview', () => {
  test('uses a sliding burst window rather than the whole lookback and reports missing entities', () => {
    const result = simulateAutomationPreview(
      rule(),
      [alert('a', 40), alert('b', 50), alert('c', 55), alert('missing', 56, { agent: {} })],
      [],
      new Set(),
      { now, lookbackHours: 1 }
    );
    expect(result.triggeringEntities).toEqual([]);
    expect(result.casesCreated).toBe(0);
    expect(result.missingEntities).toBe(1);
  });

  test('matches planner conflict, order, precondition, and stop behavior exactly', () => {
    const candidate = rule({ trigger: { type: 'per_alert' }, actions: { createCase: false, setStatus: 'closed' }, priority: 20 });
    const winner = rule({ id: 'winner', enabled: true, trigger: { type: 'per_alert' }, actions: { createCase: false, setStatus: 'in_progress' }, priority: 10 });
    const alerts = [alert('z', 59)];
    const expected = planAutomation(alerts, [{ ...winner, enabled: true }, { ...candidate, enabled: true }]);
    const result = simulateAutomationPreview(candidate, alerts, [winner], new Set(), { now, lookbackHours: 1 });
    expect(result.conflicts).toEqual(expected[0].conflicts.map((conflict) => ({ alertId: 'z', ...conflict })));
    expect(result.statusChanges).toBe(0);
  });

  test('applies action/case caps and existing-case dedup without writes', () => {
    const candidate = rule({ safety: { acknowledgeMatchAll: false, maxActionsPerRun: 1, maxCasesPerRun: 1 } });
    const alerts = [alert('a', 55), alert('b', 56), alert('c', 57), alert('d', 58, { agent: { name: 'host-b' } }), alert('e', 59, { agent: { name: 'host-b' } }), alert('f', 59, { agent: { name: 'host-b' } })];
    const result = simulateAutomationPreview(candidate, alerts, [], new Set(['candidate|host-a']), { now, lookbackHours: 1 });
    expect(result.casesExtended).toBe(1);
    expect(result.casesCreated).toBe(1);
    expect(result.statusChanges + result.assignments).toBe(1);
  });

  test('has activation and durable rate-limit parity with live event-time evaluation', () => {
    const candidate = rule({
      trigger: { type: 'per_alert' }, actions: { createCase: false, setStatus: 'closed' },
      safety: { acknowledgeMatchAll: false, rateLimit: { maxExecutions: 1, windowMinutes: 60 } },
    });
    const first = alert('first', 58, { ingested_at: '2026-08-28T11:58:30.000Z' });
    const second = alert('second', 59, { ingested_at: '2026-08-28T11:59:30.000Z' });
    const result = simulateAutomationPreview(candidate, [first, second], [], new Set(), {
      now, lookbackHours: 1, effectiveFrom: '2026-08-28T11:59:00.000Z',
      rateLimitReservations: { candidate: [{ id: 'existing', timestamp: '2026-08-28T11:30:00.000Z' }] },
    });
    expect(result.matchingAlerts).toBe(1);
    expect(result.statusChanges).toBe(0);
    expect(result.rateLimited).toBe(true);
  });
});
