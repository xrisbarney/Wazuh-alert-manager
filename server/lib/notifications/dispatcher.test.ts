import { META_INDEX, NOTIFICATIONS_INDEX, NOTIFICATION_DISPATCHER_LEASE_ID, NOTIFICATION_DISPATCHER_STATUS_DOC_ID, NOTIFICATION_FORBIDDEN_HINT } from '../../../common/constants';
import type { NotificationSettings } from '../../../common/types';
import { leaseDocId } from '../lease';
import {
  dispatchOne,
  getNotificationDispatcherRuntime,
  isIdleStatusWriteSkippable,
  notificationDispatcherLeaseTtlMs,
  readNotificationDispatcherStatus,
  setNotificationDispatcherRuntime,
  startNotificationDispatcher,
  tickNotificationDispatcher,
} from './dispatcher';
import { ClaimedNotification } from './outbox';

const NOW = new Date('2026-11-21T10:00:00.000Z');

const settings: NotificationSettings = {
  enabled: true,
  channels: [
    { id: 'slack', name: 'Slack', kind: 'indexer_channel', enabled: true, events: ['case.created'], indexer_channel: { configId: 'cfg-1' } },
    { id: 'hook', name: 'Hook', kind: 'webhook', enabled: true, events: ['case.created'], webhook: { url: 'https://hooks.example.com/x', contentType: 'application/json' } },
    { id: 'off', name: 'Off', kind: 'webhook', enabled: false, events: ['case.created'], webhook: { url: 'https://hooks.example.com/y', contentType: 'application/json' } },
    { id: 'blocked', name: 'Blocked', kind: 'webhook', enabled: false, invalid: 'host not allowlisted', events: ['case.created'], webhook: { url: 'https://10.0.0.1/y', contentType: 'application/json' } },
  ],
};

const payload = { event: 'case.created', occurred_at: NOW.toISOString(), source: 'wazuh-alert-manager', case: { id: 'c1', title: 'Phishing', case_uid: 'WAM-1' } };

function claimedOf(channelId: string, extra: Partial<ClaimedNotification['source']> = {}): ClaimedNotification {
  const channel = settings.channels.find((c) => c.id === channelId);
  return {
    id: `n-${channelId}`,
    seqNo: 1,
    primaryTerm: 1,
    source: {
      id: `n-${channelId}`,
      event: 'case.created',
      channel_id: channelId,
      channel_kind: channel?.kind || 'webhook',
      status: 'sending',
      subject: '[Wazuh Alert Manager] Case created: Phishing',
      payload,
      target_type: 'case',
      target_id: 'c1',
      attempts: 0,
      created_at: NOW.toISOString(),
      next_attempt_at: NOW.toISOString(),
      sent_at: null,
      updated_at: NOW.toISOString(),
      claimed_by: 'h1',
      claimed_at: NOW.toISOString(),
      last_error: null,
      last_status_code: null,
      delivery: null,
      dedupe_key: null,
      ...extra,
    },
  };
}

function ok(statusCode = 200) {
  return { ok: true, statusCode, error: null, deliveryId: 'd1', durationMs: 12 };
}

function fail(error: string, statusCode: number | null = 500) {
  return { ok: false, statusCode, error, deliveryId: 'd2', durationMs: 30 };
}

/** In-memory client: outbox docs keyed by id, meta docs (lease + status) keyed by id, due search answers `due`. */
function fakeClient(due: ClaimedNotification[] = [], options: { leaseHeldBy?: string } = {}) {
  const meta: Record<string, any> = {};
  if (options.leaseHeldBy) {
    meta[leaseDocId(NOTIFICATION_DISPATCHER_LEASE_ID)] = {
      _seq_no: 1,
      _primary_term: 1,
      _source: { document_type: 'lease', lease_id: NOTIFICATION_DISPATCHER_LEASE_ID, holder_id: options.leaseHeldBy, expires_at: new Date(NOW.getTime() + 60_000).toISOString() },
    };
  }
  const outbox: Record<string, any> = {};
  for (const entry of due) outbox[entry.id] = { ...entry.source, status: 'pending', claimed_by: null, claimed_at: null };
  const client: any = {
    get: jest.fn(async ({ index, id }: any) => {
      if (index === META_INDEX && meta[id]) return { body: { _id: id, found: true, ...meta[id] } };
      throw Object.assign(new Error('not found'), { meta: { statusCode: 404 } });
    }),
    create: jest.fn(async ({ index, id, body }: any) => {
      if (index === META_INDEX) {
        if (meta[id]) throw Object.assign(new Error('exists'), { meta: { statusCode: 409 } });
        meta[id] = { _seq_no: 0, _primary_term: 1, _source: body };
      }
      return {};
    }),
    index: jest.fn(async ({ index, id, body }: any) => {
      if (index === META_INDEX) meta[id] = { _seq_no: 0, _primary_term: 1, _source: body };
      return {};
    }),
    update: jest.fn(async ({ index, id, body }: any) => {
      if (index === META_INDEX) {
        if (body?.doc) meta[id] = { ...(meta[id] || { _seq_no: 0, _primary_term: 1 }), _source: { ...(meta[id]?._source || {}), ...body.doc } };
        return {};
      }
      if (index === NOTIFICATIONS_INDEX) {
        if (body?.script) {
          outbox[id] = { ...outbox[id], status: 'sending', claimed_by: body.script.params.holder, claimed_at: body.script.params.now };
        } else if (body?.doc) {
          outbox[id] = { ...outbox[id], ...body.doc };
        }
        return { body: { _seq_no: 2, _primary_term: 1 } };
      }
      return {};
    }),
    search: jest.fn(async ({ index }: any) => {
      if (index === NOTIFICATIONS_INDEX) {
        return { body: { hits: { hits: due.map((entry) => ({ _id: entry.id, _seq_no: 1, _primary_term: 1, _source: outbox[entry.id] })) } } };
      }
      return { body: { hits: { hits: [] } } };
    }),
    delete: jest.fn(async ({ index, id }: any) => {
      if (index === META_INDEX) delete meta[id];
      return {};
    }),
    outbox,
    meta,
  };
  return client;
}

const logger: any = { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() };

describe('dispatchOne', () => {
  test('indexer channel: sent through sendIndexerChannel with the rendered text and the outbox as monitor input', async () => {
    const client = fakeClient();
    const sendIndexerChannel = jest.fn(async () => ok(200));
    const sendWebhook = jest.fn();
    const claimed = claimedOf('slack');
    const res = await dispatchOne(client, claimed, settings, { sendIndexerChannel: sendIndexerChannel as any, sendWebhook, now: NOW });
    expect(res).toEqual({ outcome: 'sent', error: null });
    expect(sendWebhook).not.toHaveBeenCalled();
    const [c, configId, message, opts] = sendIndexerChannel.mock.calls[0] as any[];
    expect(c).toBe(client);
    expect(configId).toBe('cfg-1');
    expect(message.subject).toBe('[Wazuh Alert Manager] Case created: Phishing');
    expect(message.message).toContain('Case: WAM-1 Phishing');
    expect(opts).toEqual({ inputIndex: NOTIFICATIONS_INDEX });
    const doc = client.update.mock.calls[0][0].body.doc;
    expect(doc).toMatchObject({ status: 'sent', attempts: 1, last_status_code: 200, delivery: { transport: 'indexer_channel', deliveryId: 'd1', statusCode: 200, durationMs: 12 } });
  });

  test('webhook: secret resolved then sent; a failure records the backoff', async () => {
    const client = fakeClient();
    const resolveWebhookSecret = jest.fn(async () => 'shh');
    const sendWebhook = jest.fn(async () => fail('Receiver answered HTTP 502', 502));
    const claimed = claimedOf('hook', { attempts: 1 });
    const res = await dispatchOne(client, claimed, settings, { resolveWebhookSecret, sendWebhook: sendWebhook as any, now: NOW });
    expect(res).toEqual({ outcome: 'failed', error: 'Receiver answered HTTP 502' });
    expect(sendWebhook.mock.calls[0].slice(1, 4)).toEqual([settings.channels[1], 'shh', payload]);
    const doc = client.update.mock.calls[0][0].body.doc;
    expect(doc).toMatchObject({ status: 'failed', attempts: 2, next_attempt_at: '2026-11-21T10:02:00.000Z', last_status_code: 502, delivery: { transport: 'webhook', statusCode: 502 } });
  });

  test('a 403 from either transport is recorded with the role hint; the fifth failure is dead', async () => {
    const client = fakeClient();
    const sendIndexerChannel = jest.fn(async () => fail(`no permissions for [cluster:admin/opendistro/alerting/monitor/execute]`, 403));
    const res = await dispatchOne(client, claimedOf('slack', { attempts: 4 }), settings, { sendIndexerChannel: sendIndexerChannel as any, now: NOW });
    expect(res.outcome).toBe('dead');
    expect(res.error).toContain(`(hint: ${NOTIFICATION_FORBIDDEN_HINT})`);
    expect(client.update.mock.calls[0][0].body.doc).toMatchObject({ status: 'dead', attempts: 5, next_attempt_at: null, last_status_code: 403 });
  });

  test('a missing encryption key (typed 409 from resolveWebhookSecret) fails the entry with a one-hour retry, no send', async () => {
    const client = fakeClient();
    const error: any = new Error('Cannot use the webhook secret of channel "hook": the WAZUH_ALERT_MANAGER_ENCRYPTION_KEY environment variable is not set for the wazuh-dashboard service.');
    error.statusCode = 409;
    const resolveWebhookSecret = jest.fn(async () => { throw error; });
    const sendWebhook = jest.fn();
    const res = await dispatchOne(client, claimedOf('hook'), settings, { resolveWebhookSecret, sendWebhook, now: NOW });
    expect(res.outcome).toBe('failed');
    expect(res.error).toBe(error.message);
    expect(sendWebhook).not.toHaveBeenCalled();
    expect(client.update.mock.calls[0][0].body.doc).toMatchObject({ status: 'failed', attempts: 1, next_attempt_at: '2026-11-21T11:00:00.000Z', last_status_code: null });
  });

  test('any other error from the secret lookup (a transient meta read failure) is rethrown: no attempt consumed, claim left for the stale reclaim', async () => {
    const client = fakeClient();
    const resolveWebhookSecret = jest.fn(async () => { throw Object.assign(new Error('meta index unreachable'), { meta: { statusCode: 503 } }); });
    const sendWebhook = jest.fn();
    await expect(dispatchOne(client, claimedOf('hook'), settings, { resolveWebhookSecret, sendWebhook, now: NOW })).rejects.toThrow('meta index unreachable');
    expect(sendWebhook).not.toHaveBeenCalled();
    expect(client.update).not.toHaveBeenCalled();
  });

  test('the real sendIndexerChannel 403 text carries the role hint exactly once after markFailed', async () => {
    const client = fakeClient();
    client.transport = {
      request: jest.fn(async () => {
        throw Object.assign(new Error('security_exception'), { meta: { statusCode: 403, body: { error: { reason: 'no permissions for [cluster:admin/opendistro/alerting/monitor/execute]' } } } });
      }),
    };
    const res = await dispatchOne(client, claimedOf('slack'), settings, { now: NOW });
    expect(res.outcome).toBe('failed');
    expect(res.error!.split('wazuh_alert_manager_notify').length - 1).toBe(1);
    expect(res.error).toContain(`(hint: ${NOTIFICATION_FORBIDDEN_HINT})`);
    expect(client.update.mock.calls[0][0].body.doc).toMatchObject({ status: 'failed', attempts: 1, last_status_code: 403, last_error: res.error });
  });

  test('a missing, disabled or policy-blocked channel dead-letters the entry with the reason', async () => {
    const client = fakeClient();
    const sendWebhook = jest.fn();
    const sendIndexerChannel = jest.fn();
    const deps = { sendWebhook, sendIndexerChannel, now: NOW } as any;
    expect(await dispatchOne(client, claimedOf('gone', { channel_id: 'gone' }), settings, deps)).toEqual({ outcome: 'dead', error: 'Channel "gone" no longer exists in the notification settings.' });
    expect(await dispatchOne(client, claimedOf('off'), settings, deps)).toEqual({ outcome: 'dead', error: 'Channel "off" is disabled.' });
    expect(await dispatchOne(client, claimedOf('blocked'), settings, deps)).toEqual({ outcome: 'dead', error: 'Channel "blocked" is blocked by the egress policy: host not allowlisted' });
    expect(sendWebhook).not.toHaveBeenCalled();
    expect(sendIndexerChannel).not.toHaveBeenCalled();
    for (const [req] of client.update.mock.calls) expect(req.body.doc).toMatchObject({ status: 'dead', attempts: 1 });
  });

  test('a claim lost to a stale-reclaim (409 on the mark) is reported as lost', async () => {
    const client = fakeClient();
    client.update = jest.fn(async () => { throw Object.assign(new Error('conflict'), { meta: { statusCode: 409 } }); });
    const sendIndexerChannel = jest.fn(async () => ok());
    expect(await dispatchOne(client, claimedOf('slack'), settings, { sendIndexerChannel: sendIndexerChannel as any })).toEqual({ outcome: 'lost', error: null });
  });
});

describe('tickNotificationDispatcher', () => {
  test('acquires the lease, claims due entries, delivers through both transports and writes the status doc', async () => {
    const client = fakeClient([claimedOf('slack'), claimedOf('hook'), claimedOf('off')]);
    const sendIndexerChannel = jest.fn(async () => ok());
    const sendWebhook = jest.fn(async () => fail('timeout', null));
    const resolveWebhookSecret = jest.fn(async () => '');
    const result = await tickNotificationDispatcher(client, {
      holder: 'h1',
      ttlMs: 30_000,
      now: NOW,
      logger,
      settings,
      deps: { sendIndexerChannel: sendIndexerChannel as any, sendWebhook: sendWebhook as any, resolveWebhookSecret },
    });
    expect(result).toMatchObject({ acquired: true, claimed: 3, sent: 1, failed: 1, dead: 1, lost: 0 });
    expect(result.errors).toEqual([
      'n-hook (case.created -> hook): timeout',
      'n-off (case.created -> off): Channel "off" is disabled.',
    ]);
    expect(client.outbox['n-slack']).toMatchObject({ status: 'sent', attempts: 1, claimed_by: null });
    expect(client.outbox['n-hook']).toMatchObject({ status: 'failed', attempts: 1, next_attempt_at: '2026-11-21T10:00:30.000Z', last_error: 'timeout' });
    expect(client.outbox['n-off']).toMatchObject({ status: 'dead' });
    expect(client.meta[leaseDocId(NOTIFICATION_DISPATCHER_LEASE_ID)]._source).toMatchObject({ document_type: 'lease', holder_id: 'h1' });
    const status = await readNotificationDispatcherStatus(client);
    expect(status).toEqual({
      last_tick_at: NOW.toISOString(),
      holder: 'h1',
      claimed: 3,
      sent: 1,
      failed: 1,
      dead: 1,
      errors: [
        { at: NOW.toISOString(), message: 'n-hook (case.created -> hook): timeout' },
        { at: NOW.toISOString(), message: 'n-off (case.created -> off): Channel "off" is disabled.' },
      ],
    });
    expect(client.index.mock.calls.find(([r]: any[]) => r.id === NOTIFICATION_DISPATCHER_STATUS_DOC_ID)[0].index).toBe(META_INDEX);
  });

  test('a lease held by another replica makes the tick a no-op (nothing claimed, no status write)', async () => {
    const client = fakeClient([claimedOf('slack')], { leaseHeldBy: 'other' });
    const sendIndexerChannel = jest.fn();
    const result = await tickNotificationDispatcher(client, { holder: 'h1', ttlMs: 30_000, now: NOW, logger, settings, deps: { sendIndexerChannel } });
    expect(result).toMatchObject({ acquired: false, claimed: 0 });
    expect(sendIndexerChannel).not.toHaveBeenCalled();
    expect(client.search).not.toHaveBeenCalled();
    expect(client.index).not.toHaveBeenCalled();
  });

  test('globally disabled notifications: nothing is claimed, entries stay pending, the status doc still records the tick', async () => {
    const client = fakeClient([claimedOf('slack')]);
    const result = await tickNotificationDispatcher(client, { holder: 'h1', ttlMs: 30_000, now: NOW, logger, settings: { ...settings, enabled: false } });
    expect(result).toMatchObject({ acquired: true, claimed: 0, sent: 0 });
    expect(client.search).not.toHaveBeenCalled();
    expect(client.outbox['n-slack'].status).toBe('pending');
    expect((await readNotificationDispatcherStatus(client))?.claimed).toBe(0);
  });

  test('the lease is renewed every five entries; once lost, the remaining claims go back to pending and the status doc is left alone', async () => {
    const due = Array.from({ length: 7 }, (_, i) => claimedOf('slack', { id: `n-${i}` }));
    for (const entry of due) entry.id = entry.source.id;
    const client = fakeClient(due);
    client.meta[NOTIFICATION_DISPATCHER_STATUS_DOC_ID] = {
      _source: { document_type: 'notification_dispatcher_status', last_tick_at: 'x', holder: 'h2', claimed: 1, sent: 1, failed: 0, dead: 0, errors: [] },
    };
    let sends = 0;
    const sendIndexerChannel = jest.fn(async () => {
      sends += 1;
      // The fifth delivery takes long enough for another replica to take the lease.
      if (sends === 5) {
        client.meta[leaseDocId(NOTIFICATION_DISPATCHER_LEASE_ID)] = {
          _seq_no: 9,
          _primary_term: 1,
          _source: { document_type: 'lease', lease_id: NOTIFICATION_DISPATCHER_LEASE_ID, holder_id: 'h2', expires_at: new Date(NOW.getTime() + 60_000).toISOString() },
        };
      }
      return ok();
    });
    const result = await tickNotificationDispatcher(client, { holder: 'h1', ttlMs: 30_000, now: NOW, logger, settings, deps: { sendIndexerChannel: sendIndexerChannel as any } });
    expect(result).toMatchObject({ acquired: true, claimed: 7, sent: 5, leaseLost: true, released: 2 });
    expect(result.errors).toEqual(['batch stopped after 5 of 7: lease lost to another replica (2 claims released)']);
    expect(sendIndexerChannel).toHaveBeenCalledTimes(5);
    const leaseReads = client.get.mock.calls.filter(([r]: any[]) => r.id === leaseDocId(NOTIFICATION_DISPATCHER_LEASE_ID)).length;
    expect(leaseReads).toBe(2); // acquire + the renewal after five entries
    for (let i = 0; i < 5; i += 1) expect(client.outbox[`n-${i}`].status).toBe('sent');
    for (const id of ['n-5', 'n-6']) expect(client.outbox[id]).toMatchObject({ status: 'pending', attempts: 0, claimed_by: null, next_attempt_at: NOW.toISOString() });
    // The new holder's status record is untouched.
    expect((await readNotificationDispatcherStatus(client))!.holder).toBe('h2');
    expect(client.index.mock.calls.find(([r]: any[]) => r.id === NOTIFICATION_DISPATCHER_STATUS_DOC_ID)).toBeUndefined();
  });

  test('an idle tick rewrites the status doc only when the stored one is older than a minute or from another holder', async () => {
    const recent = { last_tick_at: new Date(NOW.getTime() - 10_000).toISOString(), holder: 'h1', claimed: 0, sent: 0, failed: 0, dead: 0, errors: [] };
    expect(isIdleStatusWriteSkippable(recent, { claimed: 0, errors: [] }, 'h1', NOW)).toBe(true);
    expect(isIdleStatusWriteSkippable(recent, { claimed: 1, errors: [] }, 'h1', NOW)).toBe(false);
    expect(isIdleStatusWriteSkippable(recent, { claimed: 0, errors: ['x'] }, 'h1', NOW)).toBe(false);
    expect(isIdleStatusWriteSkippable(recent, { claimed: 0, errors: [] }, 'h2', NOW)).toBe(false);
    expect(isIdleStatusWriteSkippable({ ...recent, last_tick_at: new Date(NOW.getTime() - 61_000).toISOString() }, { claimed: 0, errors: [] }, 'h1', NOW)).toBe(false);
    expect(isIdleStatusWriteSkippable(null, { claimed: 0, errors: [] }, 'h1', NOW)).toBe(false);

    const client = fakeClient();
    client.meta[NOTIFICATION_DISPATCHER_STATUS_DOC_ID] = { _source: { document_type: 'notification_dispatcher_status', ...recent } };
    const result = await tickNotificationDispatcher(client, { holder: 'h1', ttlMs: 30_000, now: NOW, logger, settings });
    expect(result).toMatchObject({ acquired: true, claimed: 0, errors: [] });
    expect(client.index.mock.calls.find(([r]: any[]) => r.id === NOTIFICATION_DISPATCHER_STATUS_DOC_ID)).toBeUndefined();
    expect((await readNotificationDispatcherStatus(client))!.last_tick_at).toBe(recent.last_tick_at);

    client.meta[NOTIFICATION_DISPATCHER_STATUS_DOC_ID]._source.last_tick_at = new Date(NOW.getTime() - 120_000).toISOString();
    await tickNotificationDispatcher(client, { holder: 'h1', ttlMs: 30_000, now: NOW, logger, settings });
    expect((await readNotificationDispatcherStatus(client))!.last_tick_at).toBe(NOW.toISOString());
  });

  test('a transport that throws never escapes the tick; the error lands in the status doc (last ten kept)', async () => {
    const client = fakeClient([claimedOf('slack')]);
    client.meta[NOTIFICATION_DISPATCHER_STATUS_DOC_ID] = {
      _source: { document_type: 'notification_dispatcher_status', last_tick_at: 'x', holder: 'h0', claimed: 0, sent: 0, failed: 0, dead: 0, errors: Array.from({ length: 10 }, (_, i) => ({ at: 'old', message: `old ${i}` })) },
    };
    const sendIndexerChannel = jest.fn(async () => { throw new Error('socket hang up'); });
    const result = await tickNotificationDispatcher(client, { holder: 'h1', ttlMs: 30_000, now: NOW, logger, settings, deps: { sendIndexerChannel: sendIndexerChannel as any } });
    expect(result.acquired).toBe(true);
    expect(result.errors).toEqual(['n-slack (case.created -> slack): unexpected error: socket hang up']);
    const status = await readNotificationDispatcherStatus(client);
    expect(status!.errors).toHaveLength(10);
    expect(status!.errors[9]).toEqual({ at: NOW.toISOString(), message: 'n-slack (case.created -> slack): unexpected error: socket hang up' });
    expect(status!.errors[0]).toEqual({ at: 'old', message: 'old 1' });
    // The entry keeps its `sending` claim and is reclaimed as stale later.
    expect(client.outbox['n-slack'].status).toBe('sending');
  });

  test('a claim failure (search error) is logged and recorded, not thrown', async () => {
    const client = fakeClient();
    client.search = jest.fn(async () => { throw new Error('search down'); });
    const result = await tickNotificationDispatcher(client, { holder: 'h1', ttlMs: 30_000, now: NOW, logger, settings });
    expect(result.errors).toEqual(['tick failed: search down']);
    expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('tick failed: search down'));
  });
});

/** Settle a tick's promise chain under fake timers (every await in lease, settings, claim and status is a microtask). */
async function flush(): Promise<void> {
  for (let i = 0; i < 200; i += 1) await Promise.resolve();
}

describe('runtime + loop', () => {
  test('runtime record and lease TTL', () => {
    setNotificationDispatcherRuntime(null);
    expect(getNotificationDispatcherRuntime()).toEqual({ enabled: null, tickSeconds: 5 });
    setNotificationDispatcherRuntime({ notifications: { dispatcher: { enabled: false, tickSeconds: 20 } } } as any);
    expect(getNotificationDispatcherRuntime()).toEqual({ enabled: false, tickSeconds: 20 });
    expect(notificationDispatcherLeaseTtlMs(5)).toBe(30_000);
    expect(notificationDispatcherLeaseTtlMs(60)).toBe(180_000);
  });

  test('startNotificationDispatcher ticks on the configured interval, never overlaps, and releases the lease on stop', async () => {
    jest.useFakeTimers();
    try {
      const client = fakeClient();
      const config: any = { notifications: { dispatcher: { enabled: true, tickSeconds: 2 } } };
      const stop = startNotificationDispatcher(client, config, logger);
      expect(getNotificationDispatcherRuntime()).toEqual({ enabled: true, tickSeconds: 2 });
      expect(client.get).not.toHaveBeenCalled();
      jest.advanceTimersByTime(2000);
      // Let the tick's promise chain settle.
      await flush();
      const leaseCalls = () => client.get.mock.calls.filter(([r]: any[]) => r.id === leaseDocId(NOTIFICATION_DISPATCHER_LEASE_ID)).length;
      expect(leaseCalls()).toBe(1);
      expect(client.meta[leaseDocId(NOTIFICATION_DISPATCHER_LEASE_ID)]._source.holder_id).toMatch(/-\d+-[0-9a-f]{8}$/);
      jest.advanceTimersByTime(2000);
      await flush();
      expect(leaseCalls()).toBe(2);
      stop();
      await flush();
      expect(client.delete).toHaveBeenCalledWith(expect.objectContaining({ index: META_INDEX, id: leaseDocId(NOTIFICATION_DISPATCHER_LEASE_ID) }));
      jest.advanceTimersByTime(10_000);
      await flush();
      expect(leaseCalls()).toBe(3); // the release's own read; no further ticks
    } finally {
      jest.useRealTimers();
    }
  });
});
