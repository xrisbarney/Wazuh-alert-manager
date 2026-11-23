import { NOTIFICATIONS_INDEX, NOTIFICATION_REPORT_MARKDOWN_MAX_BYTES } from '../../../common';
import type { ReportRun, ReportSchedule } from '../../../common';
import { registerActivityEmitter } from '../activity';
import {
  caseEventForActivity,
  caseOutboxId,
  createNotificationEmitter,
  describeEscalationActions,
  getNotificationEmitter,
  registerNotificationEmitter,
  reportOutboxId,
  reportRunLink,
  resolveNotificationChannels,
  severityRaised,
  slaOutboxId,
} from './emitters';
import { NOTIFICATION_TRUNCATION_NOTE, setNotificationRuntime } from './render';
import { invalidateNotificationSettingsCache, primeNotificationSettingsCache } from './settings';

const CASE_INDEX = 'wazuh-alert-manager-v2-cases-000001';

const slack: any = { id: 'slack', name: 'Slack', kind: 'indexer_channel', enabled: true, indexerChannel: { configId: 'cfg-1' }, events: ['case.created', 'case.assigned', 'case.severity_raised', 'case.closed', 'sla.breached', 'sla.escalated', 'report.scheduled'] };
const hook: any = { id: 'hook', name: 'Hook', kind: 'webhook', enabled: true, webhook: { url: 'https://receiver.example.com/wam', secretConfigured: false, headers: {}, allowInsecure: false }, events: ['case.created'] };
const off: any = { id: 'off', name: 'Off', kind: 'webhook', enabled: false, webhook: { url: 'https://receiver.example.com/off', secretConfigured: false, headers: {}, allowInsecure: false }, events: ['case.created', 'sla.escalated'] };
const settings = { enabled: true, channels: [slack, hook, off] };

function mockLogger() {
  return { debug: jest.fn(), info: jest.fn(), warn: jest.fn(), error: jest.fn() };
}

/** Outbox + case read mock: `index` with `op_type: create` answers 409 on a repeated id. */
function mockClient(cases: Record<string, any> = {}) {
  const outbox = new Map<string, any>();
  return {
    outbox,
    index: jest.fn(async ({ index, id, op_type, body }: any) => {
      expect(index).toBe(NOTIFICATIONS_INDEX);
      expect(op_type).toBe('create');
      if (outbox.has(id)) throw Object.assign(new Error('conflict'), { meta: { statusCode: 409 } });
      outbox.set(id, body);
      return { body: { result: 'created' } };
    }),
    bulk: jest.fn(async ({ body }: any) => {
      const items: any[] = [];
      for (let i = 0; i < body.length; i += 2) {
        const op = body[i].create;
        expect(op._index).toBe(NOTIFICATIONS_INDEX);
        if (outbox.has(op._id)) items.push({ create: { status: 409, error: { type: 'version_conflict_engine_exception', reason: 'exists' } } });
        else {
          outbox.set(op._id, body[i + 1]);
          items.push({ create: { status: 201, result: 'created' } });
        }
      }
      return { body: { errors: items.some((item) => item.create.error), items } };
    }),
    search: jest.fn(async () => ({
      body: { hits: { hits: Object.entries(cases).map(([id, source]) => ({ _id: id, _index: CASE_INDEX, _source: source })) } },
    })),
  };
}

const caseDoc = (overrides: any = {}) => ({
  id: 'case-1',
  case_uid: 'case-1',
  title: 'Suspicious login',
  description: 'raw description that must never leave the process',
  severity: 'high',
  status: 'open',
  assigned_to: null,
  created_by: 'alice',
  created_at: '2026-11-21T10:00:00.000Z',
  updated_by: 'alice',
  updated_at: '2026-11-21T10:00:00.000Z',
  closed_at: null,
  evidence_count: 2,
  history: [{ action: 'case_created' }],
  ...overrides,
});

beforeEach(() => {
  invalidateNotificationSettingsCache();
  primeNotificationSettingsCache(settings as any);
  setNotificationRuntime({ notifications: { dashboardUrl: 'https://soc.example.com' } } as any);
});
afterEach(() => {
  invalidateNotificationSettingsCache();
  setNotificationRuntime(null);
  registerNotificationEmitter(null);
  registerActivityEmitter(null);
});

describe('pure helpers', () => {
  test('caseEventForActivity: the real action names of cases.ts and the automation routing', () => {
    expect(caseEventForActivity({ action: 'case_created', from: null, to: null })).toEqual({ event: 'case.created', from: null, to: null });
    expect(caseEventForActivity({ action: 'case_auto_created_evidence', from: null, to: null })).toEqual({ event: 'case.created', from: null, to: null });
    expect(caseEventForActivity({ action: 'case_auto_extended', from: null, to: null })).toBeNull();
    expect(caseEventForActivity({ action: 'assignment_change', from: null, to: 'bob' })).toEqual({ event: 'case.assigned', from: null, to: 'bob' });
    expect(caseEventForActivity({ action: 'assignment_change', from: 'bob', to: 'bob' })).toBeNull();
    expect(caseEventForActivity({ action: 'assignment_change', from: 'bob', to: null })).toBeNull();
    expect(caseEventForActivity({ action: 'status_change', from: 'open', to: 'closed' })).toEqual({ event: 'case.closed', from: 'open', to: 'closed' });
    expect(caseEventForActivity({ action: 'status_change', from: 'open', to: 'in_progress' })).toBeNull();
    expect(caseEventForActivity({ action: 'case_closed', from: null, to: 'complete' })).toEqual({ event: 'case.closed', from: null, to: 'closed' });
    expect(caseEventForActivity({ action: 'case_close_partial', from: null, to: 'partial' })).toBeNull();
    expect(caseEventForActivity({ action: 'case_updated', from: 'open', to: 'open' })).toBeNull();
    expect(caseEventForActivity({ action: 'comment_added', from: null, to: null })).toBeNull();
    expect(caseEventForActivity({ action: 'case_created', from: null, to: null, target_type: 'alert' })).toBeNull();
  });

  test('severityRaised only for a higher known band', () => {
    expect(severityRaised('medium', 'high')).toBe(true);
    expect(severityRaised('low', 'critical')).toBe(true);
    expect(severityRaised('high', 'medium')).toBe(false);
    expect(severityRaised('high', 'high')).toBe(false);
    expect(severityRaised(null, 'high')).toBe(false);
    expect(severityRaised('weird', 'high')).toBe(false);
    expect(severityRaised('low', undefined)).toBe(false);
  });

  test('outbox ids are deterministic per event, record, key and channel', () => {
    expect(caseOutboxId('case.created', 'case-1', '2026-11-21T10:00:00.000Z', 'slack')).toBe('case:case.created:case-1:2026-11-21T10:00:00.000Z:slack');
    expect(caseOutboxId('case.assigned', 'case-1', '', 'slack')).toBe('case:case.assigned:case-1:na:slack');
    expect(slaOutboxId('sla.escalated', 'case', 'c-1', 'first-response', 'hook')).toBe('sla:sla.escalated:case:c-1:first-response:hook');
    expect(slaOutboxId('sla.breached', 'alert', 'a-1', '2026-11-21T09:00:00.000Z', 'slack')).toBe('sla:sla.breached:alert:a-1:2026-11-21T09:00:00.000Z:slack');
    expect(reportOutboxId('daily-8', '2026-11-21T08:00:00.000Z', 'slack')).toBe('report:daily-8:2026-11-21T08:00:00.000Z:slack');
  });

  test('resolveNotificationChannels: binding, explicit bypass, unknown / disabled ids, global switch', () => {
    expect(resolveNotificationChannels(settings as any, 'case.created').channels.map((c) => c.id)).toEqual(['slack', 'hook']);
    expect(resolveNotificationChannels(settings as any, 'sla.escalated').channels.map((c) => c.id)).toEqual(['slack']);
    const explicit = resolveNotificationChannels(settings as any, 'sla.escalated', ['hook', 'off', 'ghost', 'hook', ' ']);
    expect(explicit).toEqual({ enabled: true, channels: [hook], unknown: ['ghost'], disabled: ['off'] });
    expect(resolveNotificationChannels(settings as any, 'case.created', []).channels.map((c) => c.id)).toEqual(['slack', 'hook']);
    expect(resolveNotificationChannels({ enabled: false, channels: [slack] } as any, 'case.created', ['slack'])).toEqual({ enabled: false, channels: [], unknown: [], disabled: [] });
    expect(resolveNotificationChannels(null, 'case.created').channels).toEqual([]);
  });

  test('reportRunLink and describeEscalationActions', () => {
    expect(reportRunLink('daily-8')).toBe('https://soc.example.com/api/wazuh_alert_manager/reports/schedules/daily-8/last-run.md');
    expect(reportRunLink('daily-8', null)).toBe('/api/wazuh_alert_manager/reports/schedules/daily-8/last-run.md');
    expect(describeEscalationActions({ assignTo: 'bob', raiseSeverity: { from: 'high', to: 'critical' }, comment: true })).toBe('assigned to bob; severity raised high -> critical; comment added');
    expect(describeEscalationActions({ raiseSeverity: null })).toBeNull();
    expect(describeEscalationActions(null)).toBeNull();
  });

  test('registerNotificationEmitter / getNotificationEmitter', () => {
    expect(getNotificationEmitter()).toBeNull();
    const emitter = createNotificationEmitter(() => mockClient(), mockLogger());
    registerNotificationEmitter(emitter);
    expect(getNotificationEmitter()).toBe(emitter);
    registerNotificationEmitter(null);
    expect(getNotificationEmitter()).toBeNull();
  });
});

describe('emitCaseEvent', () => {
  test('fans a bound event out to every enabled bound channel under a deterministic id with a projected payload', async () => {
    const client = mockClient();
    const logger = mockLogger();
    const emitter = createNotificationEmitter(() => client, logger);
    const now = new Date('2026-11-21T10:00:01.000Z');
    const result = await emitter.emitCaseEvent('case.created', caseDoc(), { actor: 'alice', now });
    expect(result).toEqual({
      event: 'case.created',
      enqueued: ['case:case.created:case-1:2026-11-21T10:00:00.000Z:slack', 'case:case.created:case-1:2026-11-21T10:00:00.000Z:hook'],
      duplicates: [],
      skipped: [],
      channels: 2,
      error: null,
    });
    const doc = client.outbox.get('case:case.created:case-1:2026-11-21T10:00:00.000Z:slack');
    expect(doc).toEqual(expect.objectContaining({
      event: 'case.created', channel_id: 'slack', channel_kind: 'indexer_channel', status: 'pending',
      target_type: 'case', target_id: 'case-1', subject: '[Wazuh Alert Manager] Case created: Suspicious login', created_at: now.toISOString(),
    }));
    expect(doc.payload).toEqual(expect.objectContaining({
      event: 'case.created', occurred_at: now.toISOString(), actor: 'alice',
      case: expect.objectContaining({ id: 'case-1', title: 'Suspicious login', severity: 'high', alert_count: 2, link: 'https://soc.example.com/app/wazuh-alert-manager?tab=cases&case=case-1' }),
    }));
    expect(JSON.stringify(doc.payload)).not.toContain('raw description');
    expect(doc.payload.case).not.toHaveProperty('history');
    expect(client.outbox.get('case:case.created:case-1:2026-11-21T10:00:00.000Z:hook').channel_kind).toBe('webhook');
    expect(logger.error).not.toHaveBeenCalled();

    // Replay (a retried write, a second replica): silent duplicates, nothing new.
    const again = await emitter.emitCaseEvent('case.created', caseDoc(), { actor: 'alice', now });
    expect(again.enqueued).toEqual([]);
    expect(again.duplicates).toHaveLength(2);
    expect(client.outbox.size).toBe(2);
  });

  test('case.assigned keys on the activity id and carries from / to; case.closed keys on closed_at', async () => {
    const client = mockClient();
    const emitter = createNotificationEmitter(() => client, mockLogger());
    const assigned = await emitter.emitCaseEvent('case.assigned', caseDoc({ assigned_to: 'bob' }), { actor: 'alice', changes: { from: null, to: 'bob' }, activityId: 'evt-1' });
    expect(assigned.enqueued).toEqual(['case:case.assigned:case-1:evt-1:slack']);
    expect(client.outbox.get('case:case.assigned:case-1:evt-1:slack').payload).toEqual(expect.objectContaining({ from: null, to: 'bob', actor: 'alice' }));
    const closed = await emitter.emitCaseEvent('case.closed', caseDoc({ status: 'closed', closed_at: '2026-11-21T11:00:00.000Z', disposition: 'true_positive' }), { actor: 'alice', changes: { from: 'open', to: 'closed' } });
    expect(closed.enqueued).toEqual(['case:case.closed:case-1:2026-11-21T11:00:00.000Z:slack']);
    expect(client.outbox.get(closed.enqueued[0]).payload.case).toEqual(expect.objectContaining({ status: 'closed', disposition: 'true_positive' }));
  });

  test('case.severity_raised only when the new band is higher', async () => {
    const client = mockClient();
    const emitter = createNotificationEmitter(() => client, mockLogger());
    const lowered = await emitter.emitCaseEvent('case.severity_raised', caseDoc({ severity: 'low' }), { changes: { from: 'high', to: 'low' } });
    expect(lowered).toEqual(expect.objectContaining({ enqueued: [], skipped: ['case.severity_raised'], channels: 0 }));
    const same = await emitter.emitCaseEvent('case.severity_raised', caseDoc(), { changes: { from: 'high', to: 'high' } });
    expect(same.enqueued).toEqual([]);
    const raised = await emitter.emitCaseEvent('case.severity_raised', caseDoc({ severity: 'critical', updated_at: '2026-11-21T10:05:00.000Z' }), { actor: 'alice', changes: { from: 'high', to: 'critical' } });
    expect(raised.enqueued).toEqual(['case:case.severity_raised:case-1:2026-11-21T10:05:00.000Z:slack']);
    expect(client.outbox.get(raised.enqueued[0]).payload).toEqual(expect.objectContaining({ from: 'high', to: 'critical', case: expect.objectContaining({ severity: 'critical' }) }));
    expect(client.outbox.size).toBe(1);
  });

  test('explicit notify ids bypass the binding but must exist and be enabled; a custom key is honoured', async () => {
    const client = mockClient();
    const logger = mockLogger();
    const emitter = createNotificationEmitter(() => client, logger);
    const result = await emitter.emitCaseEvent('case.assigned', caseDoc({ assigned_to: 'bob' }), { changes: { from: null, to: 'bob' }, notify: ['hook', 'off', 'ghost'], key: 'sla-escalation:r1:case-1:assignment' });
    expect(result.enqueued).toEqual(['case:case.assigned:case-1:sla-escalation:r1:case-1:assignment:hook']);
    expect(result.skipped).toEqual(['ghost', 'off']);
    expect(result.channels).toBe(1);
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('unknown channel id(s) ghost; disabled channel id(s) off skipped'));
  });

  test('nothing is enqueued when notifications are globally disabled or no channel is bound', async () => {
    primeNotificationSettingsCache({ enabled: false, channels: [slack] } as any);
    const client = mockClient();
    const emitter = createNotificationEmitter(() => client, mockLogger());
    expect(await emitter.emitCaseEvent('case.created', caseDoc())).toEqual(expect.objectContaining({ enqueued: [], channels: 0, error: null }));
    primeNotificationSettingsCache({ enabled: true, channels: [hook] } as any);
    expect((await emitter.emitCaseEvent('case.closed', caseDoc({ status: 'closed', closed_at: 'x' }))).channels).toBe(0);
    expect(client.index).not.toHaveBeenCalled();
  });

  test('every failure is logged and swallowed: outbox write, settings client, missing id', async () => {
    const logger = mockLogger();
    const broken = { ...mockClient(), index: jest.fn(async () => { throw new Error('indexer down'); }) };
    const emitter = createNotificationEmitter(() => broken, logger);
    const result = await emitter.emitCaseEvent('case.created', caseDoc());
    expect(result.error).toBe('indexer down');
    expect(result.enqueued).toEqual([]);
    expect(logger.error).toHaveBeenCalledTimes(2); // one per channel
    expect(logger.error.mock.calls[0][0]).toContain('could not enqueue case.created for case case-1 to channel slack: indexer down');

    const noClient = createNotificationEmitter(() => { throw new Error('no client'); }, logger);
    const failed = await noClient.emitCaseEvent('case.created', caseDoc());
    expect(failed.error).toBe('no client');

    const skipped = await emitter.emitCaseEvent('case.created', { title: 'no id' } as any);
    expect(skipped.skipped).toEqual(['case.created']);
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('without a case id'));
  });
});

describe('emitSlaEvent', () => {
  const alertSource = {
    rule: { id: '5710', description: 'sshd: Attempt to login using a non-existent user', level: 5 },
    agent: { id: '001', name: 'web-1' },
    status: 'open',
    assigned_to: null,
    '@timestamp': '2026-11-21T08:00:00.000Z',
    reporting: { sla_due_at: '2026-11-21T09:00:00.000Z' },
    full_log: 'raw log line that must not leave the process',
    data: { srcip: '203.0.113.5' },
  };

  test('sla.breached goes to the bound channels with a projected alert, keyed on the due date', async () => {
    const client = mockClient();
    const emitter = createNotificationEmitter(() => client, mockLogger());
    const result = await emitter.emitSlaEvent('sla.breached', { target: 'alert', record: { id: 'a-1', source: alertSource }, dueAt: '2026-11-21T09:00:00.000Z', message: 'SLA due 2026-11-21T09:00:00.000Z passed', now: new Date('2026-11-21T09:00:30.000Z') });
    expect(result.enqueued).toEqual(['sla:sla.breached:alert:a-1:2026-11-21T09:00:00.000Z:slack']);
    const doc = client.outbox.get(result.enqueued[0]);
    expect(doc).toEqual(expect.objectContaining({ target_type: 'alert', target_id: 'a-1', subject: '[Wazuh Alert Manager] SLA breached: sshd: Attempt to login using a non-existent user' }));
    expect(doc.payload).toEqual(expect.objectContaining({
      event: 'sla.breached', actor: 'system:sla', message: 'SLA due 2026-11-21T09:00:00.000Z passed', case: null,
      alert: expect.objectContaining({ id: 'a-1', rule: { id: '5710', description: alertSource.rule.description }, agent: { id: '001', name: 'web-1' }, sla_due_at: '2026-11-21T09:00:00.000Z', severity: expect.objectContaining({ band: 'medium', level: 5 }) }),
    }));
    expect(JSON.stringify(doc.payload)).not.toContain('raw log line');
    expect(JSON.stringify(doc.payload)).not.toContain('203.0.113.5');
    // Replay of the same record and due date: duplicate.
    const again = await emitter.emitSlaEvent('sla.breached', { target: 'alert', record: { id: 'a-1', source: alertSource }, dueAt: '2026-11-21T09:00:00.000Z' });
    expect(again).toEqual(expect.objectContaining({ enqueued: [], duplicates: ['sla:sla.breached:alert:a-1:2026-11-21T09:00:00.000Z:slack'] }));
  });

  test('sla.escalated: the escalation notify ids win over the binding (hook is not bound to the event); without them the bound channels apply', async () => {
    const client = mockClient();
    const logger = mockLogger();
    const emitter = createNotificationEmitter(() => client, logger);
    const escalation = { id: 'first-response', name: 'First response' };
    const explicit = await emitter.emitSlaEvent('sla.escalated', {
      target: 'case', record: { id: 'c-1', source: caseDoc({ id: undefined, assigned_to: 'bob', status: 'in_progress' }) }, escalation, notify: ['hook', 'ghost'], message: 'assigned to bob',
    });
    expect(explicit.enqueued).toEqual(['sla:sla.escalated:case:c-1:first-response:hook']);
    expect(explicit.skipped).toEqual(['ghost']);
    const doc = client.outbox.get(explicit.enqueued[0]);
    expect(doc).toEqual(expect.objectContaining({ target_type: 'case', target_id: 'c-1', channel_kind: 'webhook' }));
    expect(doc.payload).toEqual(expect.objectContaining({
      event: 'sla.escalated', actor: 'system:sla', escalation, message: 'assigned to bob',
      case: expect.objectContaining({ id: 'c-1', assigned_to: 'bob', status: 'in_progress' }),
    }));
    expect(doc.payload.alert).toBeUndefined();

    const bound = await emitter.emitSlaEvent('sla.escalated', { target: 'alert', record: { id: 'a-1', source: alertSource }, escalation, notify: [] });
    expect(bound.enqueued).toEqual(['sla:sla.escalated:alert:a-1:first-response:slack']);
    const empty = await emitter.emitSlaEvent('sla.escalated', { target: 'alert', record: { id: 'a-2', source: alertSource }, escalation, notify: null });
    expect(empty.enqueued).toEqual(['sla:sla.escalated:alert:a-2:first-response:slack']);
  });

  test('a notify list that resolves to nothing enqueues nothing (and never falls back to the binding)', async () => {
    const client = mockClient();
    const logger = mockLogger();
    const emitter = createNotificationEmitter(() => client, logger);
    const result = await emitter.emitSlaEvent('sla.escalated', { target: 'alert', record: { id: 'a-1', source: alertSource }, escalation: { id: 'r', name: 'R' }, notify: ['off'] });
    expect(result).toEqual(expect.objectContaining({ enqueued: [], skipped: ['off'], channels: 0, error: null }));
    expect(client.index).not.toHaveBeenCalled();
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('disabled channel id(s) off skipped'));
  });

  test('a failing outbox is logged, never thrown', async () => {
    const logger = mockLogger();
    const broken = { ...mockClient(), index: jest.fn(async () => { throw new Error('boom'); }) };
    const emitter = createNotificationEmitter(() => broken, logger);
    const result = await emitter.emitSlaEvent('sla.breached', { target: 'case', record: { id: 'c-1', source: caseDoc() } });
    expect(result.error).toBe('boom');
    expect(logger.error).toHaveBeenCalledTimes(1);
    expect((await emitter.emitSlaEvent('sla.breached', { target: 'case', record: { id: '', source: {} } })).skipped).toEqual(['sla.breached']);
  });

  test('emitSlaEvents writes a whole batch through one bulk of create ops: same ids and payloads as the single form, duplicates on replay', async () => {
    const client = mockClient();
    const emitter = createNotificationEmitter(() => client, mockLogger());
    const batch = [
      { target: 'alert' as const, record: { id: 'a-1', source: alertSource }, dueAt: '2026-11-21T09:00:00.000Z', message: 'SLA due 2026-11-21T09:00:00.000Z passed', now: new Date('2026-11-21T09:00:30.000Z') },
      { target: 'alert' as const, record: { id: 'a-2', source: alertSource }, dueAt: '2026-11-21T09:00:00.000Z', now: new Date('2026-11-21T09:00:30.000Z') },
      { target: 'alert' as const, record: { id: '', source: alertSource } },
    ];
    const result = await emitter.emitSlaEvents('sla.breached', batch);
    expect(result).toEqual({
      event: 'sla.breached',
      enqueued: ['sla:sla.breached:alert:a-1:2026-11-21T09:00:00.000Z:slack', 'sla:sla.breached:alert:a-2:2026-11-21T09:00:00.000Z:slack'],
      duplicates: [], skipped: ['sla.breached'], channels: 2, error: null,
    });
    expect(client.bulk).toHaveBeenCalledTimes(1);
    expect(client.index).not.toHaveBeenCalled();
    const doc = client.outbox.get(result.enqueued[0]);
    expect(doc).toEqual(expect.objectContaining({ id: result.enqueued[0], event: 'sla.breached', status: 'pending', channel_id: 'slack', channel_kind: 'indexer_channel', target_type: 'alert', target_id: 'a-1', subject: '[Wazuh Alert Manager] SLA breached: sshd: Attempt to login using a non-existent user', created_at: '2026-11-21T09:00:30.000Z' }));
    expect(doc.payload).toEqual(expect.objectContaining({ event: 'sla.breached', actor: 'system:sla', message: 'SLA due 2026-11-21T09:00:00.000Z passed', alert: expect.objectContaining({ id: 'a-1' }) }));
    expect(JSON.stringify(doc.payload)).not.toContain('raw log line');

    const again = await emitter.emitSlaEvents('sla.breached', batch.slice(0, 2));
    expect(again).toEqual(expect.objectContaining({ enqueued: [], duplicates: result.enqueued, channels: 2, error: null }));
    expect(await emitter.emitSlaEvents('sla.breached', [])).toEqual({ event: 'sla.breached', enqueued: [], duplicates: [], skipped: [], channels: 0, error: null });
    expect(client.bulk).toHaveBeenCalledTimes(2);
  });

  test('emitSlaEvents: explicit notify ids per entry, an item failure and a bulk failure are logged, never thrown', async () => {
    const logger = mockLogger();
    const client = mockClient();
    const emitter = createNotificationEmitter(() => client, logger);
    const escalation = { id: 'r', name: 'R' };
    const explicit = await emitter.emitSlaEvents('sla.escalated', [
      { target: 'alert', record: { id: 'a-1', source: alertSource }, escalation, notify: ['hook', 'ghost'] },
      { target: 'alert', record: { id: 'a-2', source: alertSource }, escalation, notify: ['off'] },
      { target: 'alert', record: { id: 'a-3', source: alertSource }, escalation },
    ]);
    expect(explicit).toEqual(expect.objectContaining({ enqueued: ['sla:sla.escalated:alert:a-1:r:hook', 'sla:sla.escalated:alert:a-3:r:slack'], skipped: ['ghost', 'off'], channels: 2, error: null }));
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('ghost unknown or disabled channel id(s) skipped'));

    const partial = {
      ...mockClient(),
      bulk: jest.fn(async ({ body }: any) => ({ body: { items: body.filter((_: any, i: number) => i % 2 === 0).map((op: any, i: number) => (i === 0 ? { create: { status: 429, error: { type: 'es_rejected_execution_exception', reason: 'queue full' } } } : { create: { status: 201 } })) } })),
    };
    const rejected = await createNotificationEmitter(() => partial, logger).emitSlaEvents('sla.breached', [
      { target: 'case', record: { id: 'c-1', source: caseDoc() }, dueAt: 'd' },
      { target: 'case', record: { id: 'c-2', source: caseDoc() }, dueAt: 'd' },
    ]);
    expect(rejected).toEqual(expect.objectContaining({ enqueued: ['sla:sla.breached:case:c-2:d:slack'], duplicates: [], error: 'queue full' }));
    expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('1 sla.breached entry not enqueued, first: sla:sla.breached:case:c-1:d:slack: queue full'));

    const broken = { ...mockClient(), bulk: jest.fn(async () => { throw new Error('boom'); }) };
    const failed = await createNotificationEmitter(() => broken, logger).emitSlaEvents('sla.breached', [{ target: 'case', record: { id: 'c-1', source: caseDoc() } }]);
    expect(failed).toEqual(expect.objectContaining({ enqueued: [], channels: 1, error: 'boom' }));
    expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('could not enqueue 1 sla.breached entry: boom'));
  });
});

describe('emitReportEvent', () => {
  const schedule: ReportSchedule = { id: 'daily-8', name: 'Daily 08:00', cadence: 'daily', dayOfWeek: 1, hourUtc: 8, rangeDays: 1, channelIds: ['slack', 'hook', 'ghost'], enabled: true };
  const run = (markdown: string): ReportRun => ({
    schedule_id: 'daily-8', slot: '2026-11-21T08:00:00.000Z', generated_at: '2026-11-21T08:00:05.000Z', range_from: '2026-11-20T08:00:00.000Z', range_to: '2026-11-21T08:00:00.000Z',
    triggered_by: 'scheduler', markdown, error: null, failed_slot: null, failed_at: null, attempts: 0,
  });

  test('goes to the schedule channelIds (hook is not bound to report.scheduled), unknown ids skipped, Markdown as the message, keyed per slot', async () => {
    const client = mockClient();
    const logger = mockLogger();
    const emitter = createNotificationEmitter(() => client, logger);
    const result = await emitter.emitReportEvent(schedule, run('# Daily 08:00\n\nAlerts in range: **3**.'), { now: new Date('2026-11-21T08:00:05.000Z') });
    expect(result.enqueued).toEqual(['report:daily-8:2026-11-21T08:00:00.000Z:slack', 'report:daily-8:2026-11-21T08:00:00.000Z:hook']);
    expect(result.skipped).toEqual(['ghost']);
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('report.scheduled for report daily-8: unknown channel id(s) ghost skipped'));
    const doc = client.outbox.get(result.enqueued[0]);
    expect(doc).toEqual(expect.objectContaining({ target_type: 'report', target_id: 'daily-8', subject: '[Wazuh Alert Manager] Scheduled report: Daily 08:00' }));
    expect(doc.payload).toEqual(expect.objectContaining({
      event: 'report.scheduled', actor: 'scheduler', case: null,
      report: { id: 'daily-8', name: 'Daily 08:00', slot: '2026-11-21T08:00:00.000Z', link: 'https://soc.example.com/api/wazuh_alert_manager/reports/schedules/daily-8/last-run.md', markdown: '# Daily 08:00\n\nAlerts in range: **3**.' },
    }));
    // The same slot again (Run now after the scheduler): duplicate, not a second delivery.
    const again = await emitter.emitReportEvent(schedule, { ...run('changed'), triggered_by: 'admin' });
    expect(again.enqueued).toEqual([]);
    expect(again.duplicates).toHaveLength(2);
  });

  test('the Markdown is cut at NOTIFICATION_REPORT_MARKDOWN_MAX_BYTES on a UTF-8 boundary', async () => {
    const client = mockClient();
    const emitter = createNotificationEmitter(() => client, mockLogger());
    const big = 'é'.repeat(NOTIFICATION_REPORT_MARKDOWN_MAX_BYTES); // 2 bytes each
    const result = await emitter.emitReportEvent({ ...schedule, channelIds: ['slack'] }, run(big));
    const markdown: string = client.outbox.get(result.enqueued[0]).payload.report.markdown;
    expect(Buffer.byteLength(markdown, 'utf8')).toBeLessThanOrEqual(NOTIFICATION_REPORT_MARKDOWN_MAX_BYTES);
    expect(markdown.endsWith(NOTIFICATION_TRUNCATION_NOTE)).toBe(true);
    expect(markdown).not.toContain('�');
  });

  test('no channelIds, no slot, or a failing outbox: nothing thrown', async () => {
    const client = mockClient();
    const logger = mockLogger();
    const emitter = createNotificationEmitter(() => client, logger);
    expect(await emitter.emitReportEvent({ ...schedule, channelIds: [] }, run('x'))).toEqual(expect.objectContaining({ enqueued: [], channels: 0, error: null }));
    expect((await emitter.emitReportEvent(schedule, { ...run('x'), slot: '' })).skipped).toEqual(['report.scheduled']);
    expect(client.index).not.toHaveBeenCalled();
    const broken = { ...mockClient(), index: jest.fn(async () => { throw new Error('boom'); }) };
    const failing = createNotificationEmitter(() => broken, logger);
    expect((await failing.emitReportEvent(schedule, run('x'))).error).toBe('boom');
  });
});

describe('activityHook', () => {
  const event = (overrides: any = {}) => ({
    event_uid: 'evt-1', event_type: 'audit', target_type: 'case', target_id: 'case-1', alert_id: null, case_id: 'case-1',
    timestamp: '2026-11-21T10:00:00.000Z', created_at: '2026-11-21T10:00:00.000Z', user: 'alice', author: 'alice',
    action: 'case_created', from: null, to: null, source: 'user', operation_id: null, rule_revision: null, ...overrides,
  });

  test('maps the activity event, loads the case once and emits with the actor and the activity time', async () => {
    const client = mockClient({ 'case-1': caseDoc({ id: undefined }) });
    const emitter = createNotificationEmitter(() => client, mockLogger());
    await emitter.activityHook(event());
    expect(client.search).toHaveBeenCalledTimes(1);
    expect(client.outbox.has('case:case.created:case-1:2026-11-21T10:00:00.000Z:slack')).toBe(true);
    expect(client.outbox.get('case:case.created:case-1:2026-11-21T10:00:00.000Z:hook').payload).toEqual(expect.objectContaining({ actor: 'alice', occurred_at: '2026-11-21T10:00:00.000Z' }));

    await emitter.activityHook(event({ event_uid: 'evt-2', action: 'assignment_change', from: null, to: 'bob' }));
    expect(client.outbox.has('case:case.assigned:case-1:evt-2:slack')).toBe(true);
    expect(client.outbox.get('case:case.assigned:case-1:evt-2:slack').payload).toEqual(expect.objectContaining({ from: null, to: 'bob' }));
  });

  test('unmapped actions never read the case; case_closed on a case that is not closed emits nothing; a missing case is logged', async () => {
    const client = mockClient({ 'case-1': caseDoc({ id: undefined }) });
    const logger = mockLogger();
    const emitter = createNotificationEmitter(() => client, logger);
    await emitter.activityHook(event({ action: 'comment_added' }));
    await emitter.activityHook(event({ action: 'case_updated', from: 'open', to: 'open' }));
    expect(client.search).not.toHaveBeenCalled();
    await emitter.activityHook(event({ action: 'case_closed', to: 'complete' }));
    expect(client.outbox.size).toBe(0);
    // A re-close of an already closed case (POST /close marks it) never notifies again.
    const closed = mockClient({ 'case-1': caseDoc({ id: undefined, status: 'closed', closed_at: '2026-11-21T11:00:00.000Z' }) });
    const reClose = createNotificationEmitter(() => closed, logger);
    await reClose.activityHook(event({ action: 'case_closed', to: 'complete', details: { disposition: 'benign', closure_reason: null, already_closed: true } }));
    expect(closed.search).not.toHaveBeenCalled();
    expect(closed.outbox.size).toBe(0);
    expect(caseEventForActivity({ action: 'case_closed', from: null, to: 'complete', details: { already_closed: true } })).toBeNull();
    expect(caseEventForActivity({ action: 'case_closed', from: null, to: 'complete', details: { disposition: 'benign' } })).toEqual({ event: 'case.closed', from: null, to: 'closed' });
    const missing = createNotificationEmitter(() => mockClient({}), logger);
    await missing.activityHook(event());
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('case.created for case case-1 skipped, the case could not be read'));
  });

  test('case_closed emits case.closed keyed on closed_at; a hook failure is swallowed', async () => {
    const client = mockClient({ 'case-1': caseDoc({ id: undefined, status: 'closed', closed_at: '2026-11-21T11:00:00.000Z' }) });
    const emitter = createNotificationEmitter(() => client, mockLogger());
    await emitter.activityHook(event({ action: 'case_closed', to: 'complete', timestamp: '2026-11-21T11:00:00.000Z' }));
    expect(client.outbox.has('case:case.closed:case-1:2026-11-21T11:00:00.000Z:slack')).toBe(true);
    const logger = mockLogger();
    const broken = createNotificationEmitter(() => { throw new Error('no client'); }, logger);
    await expect(broken.activityHook(event())).resolves.toBeUndefined();
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('could not be read: no client'));
  });
});
