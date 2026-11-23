import { NOTIFICATIONS_INDEX } from '../../../common';
import { enqueueRuleNotifications, ruleActionPayload, ruleNotifyOutboxId, RuleNotificationTask } from './rule_action';
import { invalidateNotificationSettingsCache, primeNotificationSettingsCache } from './settings';

const settings = {
  enabled: true,
  channels: [
    { id: 'slack', name: 'SOC Slack', kind: 'indexer_channel', enabled: true, events: ['case.created'] },
    { id: 'hook', name: 'SOAR hook', kind: 'webhook', enabled: true, events: [] },
    { id: 'off', name: 'Retired', kind: 'webhook', enabled: false, events: ['rule.action'] },
  ],
} as any;

const alertSource = {
  '@timestamp': '2026-11-21T10:00:00.000Z',
  status: 'in_progress',
  assigned_to: 'tier-1',
  rule: { id: '5710', description: 'sshd: brute force', level: 10, groups: ['authentication_failed'] },
  agent: { id: '001', name: 'web-01' },
  data: { srcip: '10.0.0.9' },
  full_log: 'raw line',
  history: [{ action: 'x' }],
};

const task = (patch: Partial<RuleNotificationTask> = {}): RuleNotificationTask => ({
  ruleId: 'rule-1',
  ruleName: 'Brute force',
  alertId: 'a1',
  source: alertSource,
  channelIds: ['slack', 'hook'],
  actions: { status: 'in_progress', assignee: 'tier-1', caseId: 'case-9' },
  now: new Date('2026-11-21T10:00:05.000Z'),
  ...patch,
});

const logger = { warn: jest.fn(), debug: jest.fn() };

/** An outbox whose `bulk` answers 201 per new id, 409 per repeated id, or whatever `itemStatus` says. */
function outboxClient(itemStatus: (doc: any) => { status: number; error?: any } | null = () => null) {
  const written = new Set<string>();
  return {
    bulk: jest.fn(async (request: any) => {
      const items: any[] = [];
      for (let position = 0; position < request.body.length; position += 2) {
        const action = request.body[position].create;
        const doc = request.body[position + 1];
        expect(action._index).toBe(NOTIFICATIONS_INDEX);
        expect(action._id).toBe(doc.id);
        const forced = itemStatus(doc);
        if (forced) items.push({ create: { _id: doc.id, ...forced } });
        else if (written.has(doc.id)) items.push({ create: { _id: doc.id, status: 409, error: { type: 'version_conflict_engine_exception' } } });
        else {
          written.add(doc.id);
          items.push({ create: { _id: doc.id, status: 201 } });
        }
      }
      return { body: { errors: items.some((item) => item.create.error), items } };
    }),
  };
}

/** The outbox docs written, in order, across every bulk. */
const writtenDocs = (client: any) =>
  client.bulk.mock.calls.flatMap((call: any[]) => call[0].body.filter((_: any, index: number) => index % 2 === 1));

describe('rule action notify (step 1.4)', () => {
  beforeEach(() => jest.clearAllMocks());
  afterEach(() => invalidateNotificationSettingsCache());

  test('ruleNotifyOutboxId is notify:{ruleId}:{alertId} plus the channel, bounded and never empty', () => {
    expect(ruleNotifyOutboxId('rule-1', 'a1', 'slack')).toBe('notify:rule-1:a1:slack');
    expect(ruleNotifyOutboxId('', ' ', 'slack')).toBe('notify:na:na:slack');
    expect(ruleNotifyOutboxId('r'.repeat(200), 'a1', 'slack')).toBe(`notify:${'r'.repeat(128)}:a1:slack`);
  });

  test('ruleActionPayload is the allowlisted alert projection with the rule and the applied actions, never the raw source', () => {
    const payload = ruleActionPayload(task());
    expect(payload).toMatchObject({
      event: 'rule.action',
      occurred_at: '2026-11-21T10:00:05.000Z',
      case: null,
      actor: 'correlation-rule',
      rule: { id: 'rule-1', name: 'Brute force' },
      actions: { status: 'in_progress', assignee: 'tier-1', caseId: 'case-9' },
      alert: {
        id: 'a1',
        title: 'sshd: brute force',
        status: 'in_progress',
        assigned_to: 'tier-1',
        severity: { band: 'high', level: 10 },
        agent: { id: '001', name: 'web-01' },
        rule: { id: '5710' },
      },
    });
    expect((payload.alert as any).data).toBeUndefined();
    expect((payload.alert as any).full_log).toBeUndefined();
    expect((payload.alert as any).history).toBeUndefined();
    expect(ruleActionPayload(task({ actions: {} })).actions).toEqual({});
    expect(ruleActionPayload(task({ actions: { status: null, assignee: null, caseId: null } })).actions).toEqual({});
  });

  test('writes one entry per enabled channel under the idempotent id in one bulk, counts unknown, disabled and duplicate targets as skipped', async () => {
    const client = outboxClient();
    const first = await enqueueRuleNotifications(client, [task({ channelIds: ['slack', 'hook', 'off', 'ghost'] })], logger, { settings });
    expect(first).toEqual({ enqueued: 2, skipped: 2, rulesEnqueued: ['rule-1'], failures: [] });
    expect(client.bulk).toHaveBeenCalledTimes(1);
    const docs = writtenDocs(client);
    expect(docs.map((doc: any) => doc.id)).toEqual(['notify:rule-1:a1:slack', 'notify:rule-1:a1:hook']);
    expect(docs[0]).toMatchObject({
      event: 'rule.action',
      channel_id: 'slack',
      channel_kind: 'indexer_channel',
      target_type: 'alert',
      target_id: 'a1',
      status: 'pending',
      subject: '[Wazuh Alert Manager] Automation rule fired: sshd: brute force',
      created_at: '2026-11-21T10:00:05.000Z',
    });
    expect(docs[0].payload.rule).toEqual({ id: 'rule-1', name: 'Brute force' });
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('ghost, off'));

    const replay = await enqueueRuleNotifications(client, [task({ channelIds: ['slack', 'hook', 'off', 'ghost'] })], logger, { settings });
    expect(replay).toEqual({ enqueued: 0, skipped: 4, rulesEnqueued: [], failures: [] });
  });

  test('writes in chunks, re-asserts the lease before every bulk after the first, and names only the rules that wrote an entry', async () => {
    const client = outboxClient();
    const beforeChunk = jest.fn(async () => undefined);
    const tasks = [
      task({ ruleId: 'rule-1', alertId: 'a1' }),
      task({ ruleId: 'rule-1', alertId: 'a2' }),
      task({ ruleId: 'rule-2', alertId: 'a1', channelIds: ['ghost'] }),
      task({ ruleId: 'rule-3', alertId: 'a1', channelIds: ['hook'] }),
    ];
    const result = await enqueueRuleNotifications(client, tasks, logger, { settings, beforeChunk, chunkSize: 2 });
    expect(result).toEqual({ enqueued: 5, skipped: 1, rulesEnqueued: ['rule-1', 'rule-3'], failures: [] });
    expect(client.bulk).toHaveBeenCalledTimes(3);
    expect(client.bulk.mock.calls.map((call) => call[0].body.length / 2)).toEqual([2, 2, 1]);
    expect(beforeChunk).toHaveBeenCalledTimes(2);

    beforeChunk.mockRejectedValueOnce(Object.assign(new Error('Automation execution ownership was lost'), { ownershipLost: true }));
    await expect(enqueueRuleNotifications(outboxClient(), tasks, logger, { settings, beforeChunk, chunkSize: 2 }))
      .rejects.toMatchObject({ ownershipLost: true });
  });

  test('reads the cached settings when none are given and skips everything while notifications are disabled', async () => {
    primeNotificationSettingsCache({ ...settings, enabled: false });
    const client = outboxClient();
    const result = await enqueueRuleNotifications(client, [task(), task({ alertId: 'a2', channelIds: ['slack', 'slack'] })], logger);
    expect(result).toEqual({ enqueued: 0, skipped: 3, rulesEnqueued: [], failures: [] });
    expect(client.bulk).not.toHaveBeenCalled();
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('disabled in Settings > Notifications'));
  });

  test('a failed settings read rejects instead of skipping the targets as disabled (the evaluator retries; a skip would be final)', async () => {
    invalidateNotificationSettingsCache();
    const client = { ...outboxClient(), get: jest.fn(async () => { throw new Error('meta index unavailable'); }) };
    await expect(enqueueRuleNotifications(client, [task()], logger)).rejects.toThrow('meta index unavailable');
    expect(client.bulk).not.toHaveBeenCalled();
    expect(logger.warn).not.toHaveBeenCalledWith(expect.stringContaining('disabled in Settings > Notifications'));
  });

  test('a bulk item failure other than a duplicate is reported per target and the other targets are still written', async () => {
    const client = outboxClient((doc) => (doc.channel_id === 'slack' ? { status: 503, error: { reason: 'outbox unavailable' } } : null));
    const result = await enqueueRuleNotifications(client, [task()], logger, { settings });
    expect(result).toEqual({
      enqueued: 1,
      skipped: 0,
      rulesEnqueued: ['rule-1'],
      failures: [{ ruleId: 'rule-1', alertId: 'a1', channelId: 'slack', message: 'outbox unavailable' }],
    });
  });

  test('a transport failure of a bulk rejects', async () => {
    const client = { bulk: jest.fn(async () => { throw new Error('connection reset'); }) };
    await expect(enqueueRuleNotifications(client, [task()], logger, { settings })).rejects.toThrow('connection reset');
  });

  test('an empty task list writes and reads nothing', async () => {
    const client = outboxClient();
    await expect(enqueueRuleNotifications(client, [], logger)).resolves.toEqual({ enqueued: 0, skipped: 0, rulesEnqueued: [], failures: [] });
    expect(client.bulk).not.toHaveBeenCalled();
  });
});
