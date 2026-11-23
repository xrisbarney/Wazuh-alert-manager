import { NOTIFICATIONS_INDEX, NOTIFICATION_BACKOFF_SECONDS, NOTIFICATION_FORBIDDEN_HINT, NOTIFICATION_MAX_ATTEMPTS, NOTIFICATION_OUTBOX_PAGE } from '../../../common/constants';
import type { NotificationSettings } from '../../../common/types';
import {
  ClaimedNotification,
  backoffSeconds,
  claimDue,
  countOutboxByStatus,
  decodeOutboxCursor,
  describeFailure,
  dueQuery,
  encodeOutboxCursor,
  enqueueForEvent,
  enqueueMany,
  enqueueNotification,
  getOutboxEntry,
  listOutbox,
  markFailed,
  markSent,
  retryOutboxEntry,
  toOutboxEntry,
} from './outbox';

const NOW = new Date('2026-11-21T10:00:00.000Z');

function conflict() {
  return Object.assign(new Error('version conflict'), { meta: { statusCode: 409, body: { error: { type: 'version_conflict_engine_exception' } } } });
}

function notFound() {
  return Object.assign(new Error('not found'), { meta: { statusCode: 404 } });
}

const settings: NotificationSettings = {
  enabled: true,
  channels: [
    { id: 'slack', name: 'Slack', kind: 'indexer_channel', enabled: true, events: ['case.created', 'sla.breached'], indexer_channel: { configId: 'cfg-1' } },
    { id: 'hook', name: 'Hook', kind: 'webhook', enabled: true, events: ['case.created'], webhook: { url: 'https://hooks.example.com/x', contentType: 'application/json' } },
    { id: 'off', name: 'Off', kind: 'webhook', enabled: false, events: ['case.created'], webhook: { url: 'https://hooks.example.com/y', contentType: 'application/json' } },
  ],
};

const payload = { event: 'case.created', occurred_at: NOW.toISOString(), source: 'wazuh-alert-manager', case: { id: 'c1', title: 'Phishing', case_uid: 'WAM-1' } };

function claimedOf(source: Partial<ClaimedNotification['source']> = {}): ClaimedNotification {
  return {
    id: 'n1',
    seqNo: 7,
    primaryTerm: 2,
    source: {
      id: 'n1',
      event: 'case.created',
      channel_id: 'slack',
      channel_kind: 'indexer_channel',
      status: 'sending',
      subject: 'subj',
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
      ...source,
    },
  };
}

describe('enqueueNotification', () => {
  test('writes a pending entry with op_type create into the outbox only', async () => {
    const client: any = { index: jest.fn(async () => ({ body: { result: 'created' } })) };
    const res = await enqueueNotification(client, {
      id: 'case.created:c1:slack',
      event: 'case.created',
      channelId: 'slack',
      channelKind: 'indexer_channel',
      targetType: 'case',
      targetId: 'c1',
      subject: 'Case created',
      payload,
      now: NOW,
    });
    expect(res).toEqual({ id: 'case.created:c1:slack', created: true });
    const call = client.index.mock.calls[0][0];
    expect(call.index).toBe(NOTIFICATIONS_INDEX);
    expect(call.op_type).toBe('create');
    expect(call.id).toBe('case.created:c1:slack');
    expect(call.body).toMatchObject({ status: 'pending', attempts: 0, next_attempt_at: NOW.toISOString(), created_at: NOW.toISOString(), payload, claimed_by: null, last_error: null });
  });

  test('a duplicate id is a silent no-op (created: false); other errors propagate', async () => {
    const client: any = { index: jest.fn(async () => { throw conflict(); }) };
    const res = await enqueueNotification(client, { id: 'dup', event: 'case.created', channelId: 'slack', channelKind: 'indexer_channel', targetType: 'case', targetId: 'c1', subject: 's', payload });
    expect(res).toEqual({ id: 'dup', created: false });
    client.index = jest.fn(async () => { throw new Error('boom'); });
    await expect(enqueueNotification(client, { event: 'case.created', channelId: 'slack', channelKind: 'indexer_channel', targetType: 'case', targetId: 'c1', subject: 's', payload })).rejects.toThrow('boom');
  });

  test('generates an id when none is given', async () => {
    const client: any = { index: jest.fn(async () => ({})) };
    const res = await enqueueNotification(client, { event: 'test', channelId: 'slack', channelKind: 'indexer_channel', targetType: 'system', targetId: 'x', subject: 's', payload: {} });
    expect(res.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(client.index.mock.calls[0][0].body.id).toBe(res.id);
  });
});

describe('enqueueMany', () => {
  const input = (id: string) => ({ id, event: 'sla.breached' as const, channelId: 'slack', channelKind: 'indexer_channel' as const, targetType: 'alert' as const, targetId: id, subject: 's', payload, now: NOW });

  test('one bulk of create ops on the outbox index; 409 items are duplicates, other item errors failures, the rest enqueued', async () => {
    const client: any = {
      bulk: jest.fn(async () => ({
        body: { errors: true, items: [
          { create: { status: 201, result: 'created' } },
          { create: { status: 409, error: { type: 'version_conflict_engine_exception', reason: 'exists' } } },
          { create: { status: 429, error: { type: 'es_rejected_execution_exception', reason: 'queue full' } } },
        ] },
      })),
    };
    const res = await enqueueMany(client, [input('a'), input('b'), input('c')]);
    expect(res).toEqual({ enqueued: ['a'], duplicates: ['b'], failures: [{ id: 'c', error: 'queue full' }] });
    expect(client.bulk).toHaveBeenCalledTimes(1);
    const { body } = client.bulk.mock.calls[0][0];
    expect(body).toHaveLength(6);
    expect(body[0]).toEqual({ create: { _index: NOTIFICATIONS_INDEX, _id: 'a' } });
    expect(body[1]).toEqual(expect.objectContaining({ id: 'a', event: 'sla.breached', status: 'pending', attempts: 0, created_at: NOW.toISOString(), next_attempt_at: NOW.toISOString(), channel_id: 'slack', target_id: 'a', payload }));
    expect(client.bulk.mock.calls[0][0].refresh).toBeUndefined();
  });

  test('an empty batch writes nothing; a short bulk answer marks the missing items failed; a transport error propagates', async () => {
    const client: any = { bulk: jest.fn(async () => ({ body: { items: [{ create: { status: 201 } }] } })) };
    expect(await enqueueMany(client, [])).toEqual({ enqueued: [], duplicates: [], failures: [] });
    expect(client.bulk).not.toHaveBeenCalled();
    expect(await enqueueMany(client, [input('a'), input('b')], { refresh: 'wait_for' })).toEqual({ enqueued: ['a'], duplicates: [], failures: [{ id: 'b', error: 'bulk response item missing' }] });
    expect(client.bulk.mock.calls[0][0].refresh).toBe('wait_for');
    client.bulk = jest.fn(async () => { throw new Error('boom'); });
    await expect(enqueueMany(client, [input('a')])).rejects.toThrow('boom');
  });
});

describe('enqueueForEvent', () => {
  test('fans out to every enabled channel bound to the event and reports duplicates', async () => {
    const seen = new Set<string>();
    const client: any = {
      index: jest.fn(async (req: any) => {
        if (seen.has(req.id)) throw conflict();
        seen.add(req.id);
        return {};
      }),
    };
    const first = await enqueueForEvent(client, settings, 'case.created', { targetType: 'case', targetId: 'c1', payload, idFactory: (c) => `case.created:c1:${c.id}`, now: NOW });
    expect(first).toEqual({ enqueued: ['case.created:c1:slack', 'case.created:c1:hook'], duplicates: [], channels: 2 });
    expect(client.index.mock.calls.map(([r]: any[]) => r.body.channel_kind)).toEqual(['indexer_channel', 'webhook']);
    expect(client.index.mock.calls[0][0].body.subject).toBe('[Wazuh Alert Manager] Case created: Phishing');
    const again = await enqueueForEvent(client, settings, 'case.created', { targetType: 'case', targetId: 'c1', payload, idFactory: (c) => `case.created:c1:${c.id}` });
    expect(again).toEqual({ enqueued: [], duplicates: ['case.created:c1:slack', 'case.created:c1:hook'], channels: 2 });
  });

  test('respects the event binding and the global switch', async () => {
    const client: any = { index: jest.fn(async () => ({})) };
    const sla = await enqueueForEvent(client, settings, 'sla.breached', { targetType: 'alert', targetId: 'a1', payload: { ...payload, event: 'sla.breached' }, idFactory: (c) => `sla:${c.id}`, subjectFactory: (c) => `custom ${c.id}` });
    expect(sla.enqueued).toEqual(['sla:slack']);
    expect(client.index.mock.calls[0][0].body.subject).toBe('custom slack');
    client.index.mockClear();
    const none = await enqueueForEvent(client, { ...settings, enabled: false }, 'case.created', { targetType: 'case', targetId: 'c1', payload, idFactory: (c) => c.id });
    expect(none).toEqual({ enqueued: [], duplicates: [], channels: 0 });
    expect(client.index).not.toHaveBeenCalled();
    const unbound = await enqueueForEvent(client, settings, 'report.scheduled', { targetType: 'report', targetId: 'r1', payload, idFactory: (c) => c.id });
    expect(unbound.channels).toBe(0);
  });

  test('one failed write does not stop the other channels; the first error is rethrown', async () => {
    const client: any = { index: jest.fn(async (req: any) => { if (req.id.endsWith(':slack')) throw new Error('storage down'); return {}; }) };
    await expect(enqueueForEvent(client, settings, 'case.created', { targetType: 'case', targetId: 'c1', payload, idFactory: (c) => `e:${c.id}` })).rejects.toThrow('storage down');
    expect(client.index).toHaveBeenCalledTimes(2);
  });
});

describe('claimDue', () => {
  const hit = (id: string, extra: any = {}) => ({ _id: id, _seq_no: 1, _primary_term: 1, _source: { id, status: 'pending', attempts: 0, next_attempt_at: NOW.toISOString(), ...extra } });

  test('searches due pending/failed entries and stale sending claims, then claims each with a guarded script', async () => {
    const client: any = {
      search: jest.fn(async () => ({ body: { hits: { hits: [hit('a'), hit('b', { status: 'sending', claimed_at: '2026-11-21T09:00:00.000Z' })] } } })),
      update: jest.fn(async () => ({ body: { _seq_no: 9, _primary_term: 1 } })),
    };
    const claimed = await claimDue(client, { now: NOW, limit: 10, holder: 'h1' });
    const search = client.search.mock.calls[0][0];
    expect(search.index).toBe(NOTIFICATIONS_INDEX);
    expect(search.size).toBe(10);
    expect(search.seq_no_primary_term).toBe(true);
    expect(search.body.query).toEqual(dueQuery(NOW.toISOString(), '2026-11-21T09:50:00.000Z'));
    expect(claimed.map((c) => c.id)).toEqual(['a', 'b']);
    expect(claimed[0]).toMatchObject({ seqNo: 9, primaryTerm: 1, source: { status: 'sending', claimed_by: 'h1', claimed_at: NOW.toISOString() } });
    const update = client.update.mock.calls[0][0];
    expect(update).toMatchObject({ index: NOTIFICATIONS_INDEX, id: 'a', if_seq_no: 1, if_primary_term: 1 });
    expect(update.body.script.params).toEqual({ holder: 'h1', now: NOW.toISOString() });
    expect(update.body.script.source).toContain("ctx._source.status = 'sending'");
  });

  test('a 409 on the claim means another replica took it: skipped; the limit is capped at the page size', async () => {
    const client: any = {
      search: jest.fn(async () => ({ body: { hits: { hits: [hit('a'), hit('b')] } } })),
      update: jest.fn(async (req: any) => { if (req.id === 'a') throw conflict(); return { body: {} }; }),
    };
    const claimed = await claimDue(client, { now: NOW, limit: 500, holder: 'h1' });
    expect(claimed.map((c) => c.id)).toEqual(['b']);
    expect(client.search.mock.calls[0][0].size).toBe(NOTIFICATION_OUTBOX_PAGE);
  });

  test('a missing outbox index answers an empty claim; other search errors propagate', async () => {
    const client: any = { search: jest.fn(async () => { throw notFound(); }), update: jest.fn() };
    expect(await claimDue(client, { now: NOW, holder: 'h1' })).toEqual([]);
    client.search = jest.fn(async () => { throw new Error('boom'); });
    await expect(claimDue(client, { now: NOW, holder: 'h1' })).rejects.toThrow('boom');
  });

  test('the due query covers pending/failed by next_attempt_at and sending by claimed_at', () => {
    const q = dueQuery('T', 'S');
    expect(q.bool.should[0].bool.filter).toEqual([{ terms: { status: ['pending', 'failed'] } }, { range: { next_attempt_at: { lte: 'T' } } }]);
    expect(q.bool.should[1].bool.filter).toEqual([{ term: { status: 'sending' } }, { range: { claimed_at: { lte: 'S' } } }]);
  });
});

describe('markSent / markFailed', () => {
  test('markSent records the delivery, clears the claim and counts the attempt, guarded by the claim token', async () => {
    const client: any = { update: jest.fn(async () => ({})) };
    const claimed = claimedOf({ attempts: 2 });
    const delivery = { transport: 'indexer_channel' as const, deliveryId: 'd1', statusCode: 200, durationMs: 40 };
    expect(await markSent(client, claimed, delivery, { now: NOW })).toBe(true);
    const req = client.update.mock.calls[0][0];
    expect(req).toMatchObject({ index: NOTIFICATIONS_INDEX, id: 'n1', if_seq_no: 7, if_primary_term: 2 });
    expect(req.body.doc).toEqual({ status: 'sent', attempts: 3, sent_at: NOW.toISOString(), next_attempt_at: null, claimed_by: null, claimed_at: null, last_error: null, last_status_code: 200, delivery, updated_at: NOW.toISOString() });
    expect(claimed.source.status).toBe('sent');
  });

  test('a lost claim (409) is reported as not applied, never thrown', async () => {
    const client: any = { update: jest.fn(async () => { throw conflict(); }) };
    expect(await markSent(client, claimedOf(), { transport: 'webhook', deliveryId: null, statusCode: 200, durationMs: 1 })).toBe(false);
    const failed = await markFailed(client, claimedOf(), 'x');
    expect(failed.applied).toBe(false);
  });

  test('backoff schedule by attempt number, then dead after NOTIFICATION_MAX_ATTEMPTS', async () => {
    expect(NOTIFICATION_BACKOFF_SECONDS).toEqual([30, 120, 600, 1800, 3600]);
    expect(NOTIFICATION_MAX_ATTEMPTS).toBe(5);
    expect([1, 2, 3, 4, 5, 9].map(backoffSeconds)).toEqual([30, 120, 600, 1800, 3600, 3600]);
    const client: any = { update: jest.fn(async () => ({})) };
    const expectations: Array<[number, string, string | null]> = [
      [0, 'failed', '2026-11-21T10:00:30.000Z'],
      [1, 'failed', '2026-11-21T10:02:00.000Z'],
      [2, 'failed', '2026-11-21T10:10:00.000Z'],
      [3, 'failed', '2026-11-21T10:30:00.000Z'],
      [4, 'dead', null],
    ];
    for (const [attempts, status, next] of expectations) {
      const res = await markFailed(client, claimedOf({ attempts }), 'Receiver answered HTTP 500', { statusCode: 500, now: NOW });
      expect(res).toMatchObject({ applied: true, status, attempts: attempts + 1, next_attempt_at: next, last_error: 'Receiver answered HTTP 500' });
      const doc = client.update.mock.calls[client.update.mock.calls.length - 1][0].body.doc;
      expect(doc).toMatchObject({ status, attempts: attempts + 1, next_attempt_at: next, claimed_by: null, claimed_at: null, last_status_code: 500 });
    }
  });

  test('a 403 is recorded verbatim with the role hint and counts as an attempt', async () => {
    const client: any = { update: jest.fn(async () => ({})) };
    const res = await markFailed(client, claimedOf(), 'no permissions for [cluster:admin/opendistro/alerting/monitor/execute]', { statusCode: 403, now: NOW });
    expect(res.attempts).toBe(1);
    expect(res.status).toBe('failed');
    expect(res.last_error).toBe(`no permissions for [cluster:admin/opendistro/alerting/monitor/execute] (hint: ${NOTIFICATION_FORBIDDEN_HINT})`);
    expect(describeFailure('already hinted: ' + NOTIFICATION_FORBIDDEN_HINT, 403)).toBe('already hinted: ' + NOTIFICATION_FORBIDDEN_HINT);
    expect(describeFailure('', 500)).toBe('Delivery failed.');
    expect(describeFailure('a\nb', null)).toBe('a b');
  });

  test('retryAfterMs replaces the backoff table and dead: true dead-letters at any attempt count', async () => {
    const client: any = { update: jest.fn(async () => ({})) };
    const hour = await markFailed(client, claimedOf(), 'no key', { retryAfterMs: 3600 * 1000, now: NOW });
    expect(hour).toMatchObject({ status: 'failed', next_attempt_at: '2026-11-21T11:00:00.000Z' });
    const dead = await markFailed(client, claimedOf(), 'Channel "x" no longer exists', { dead: true, now: NOW });
    expect(dead).toMatchObject({ status: 'dead', attempts: 1, next_attempt_at: null });
  });
});

describe('route helpers', () => {
  test('listOutbox pages newest first with search_after, omits the payload, answers the next cursor only when more exist', async () => {
    const hits = ['c', 'b', 'a'].map((id) => ({ _id: id, _source: { id, event: 'case.created', status: 'sent', created_at: `2026-11-21T0${id === 'c' ? 3 : id === 'b' ? 2 : 1}:00:00.000Z`, payload: { secret: true } } }));
    const client: any = { search: jest.fn(async () => ({ body: { hits: { total: { value: 3 }, hits } } })) };
    const page = await listOutbox(client, { status: 'sent', limit: 2 });
    const req = client.search.mock.calls[0][0];
    expect(req.size).toBe(3);
    expect(req.body.query).toEqual({ bool: { filter: [{ term: { status: 'sent' } }] } });
    expect(req.body._source).toEqual({ excludes: ['payload'] });
    expect(req.body.sort).toEqual([{ created_at: { order: 'desc' } }, { id: { order: 'desc' } }]);
    expect(page.items.map((i) => i.id)).toEqual(['c', 'b']);
    expect(page.items[0].payload).toBeUndefined();
    expect(page.total).toBe(3);
    expect(decodeOutboxCursor(page.next_cursor)).toEqual({ created_at: '2026-11-21T02:00:00.000Z', id: 'b' });
    const next = await listOutbox(client, { cursor: page.next_cursor!, limit: 5, channelId: 'slack', event: 'case.created' });
    const req2 = client.search.mock.calls[1][0];
    expect(req2.body.search_after).toEqual(['2026-11-21T02:00:00.000Z', 'b']);
    expect(req2.body.query.bool.filter).toEqual([{ term: { channel_id: 'slack' } }, { term: { event: 'case.created' } }]);
    expect(next.next_cursor).toBeNull();
    expect(() => decodeOutboxCursor('garbage')).toThrow('Invalid outbox cursor');
    expect(encodeOutboxCursor({ created_at: 'x', id: 'y' })).toBe(Buffer.from('{"created_at":"x","id":"y"}').toString('base64'));
  });

  test('listOutbox and countOutboxByStatus tolerate a missing index', async () => {
    const client: any = { search: jest.fn(async () => { throw notFound(); }) };
    expect(await listOutbox(client)).toEqual({ items: [], next_cursor: null, total: 0 });
    expect(await countOutboxByStatus(client)).toEqual({ pending: 0, sending: 0, sent: 0, failed: 0, dead: 0 });
  });

  test('countOutboxByStatus reads a terms aggregation', async () => {
    const client: any = { search: jest.fn(async () => ({ body: { aggregations: { by_status: { buckets: [{ key: 'sent', doc_count: 4 }, { key: 'dead', doc_count: 1 }, { key: 'weird', doc_count: 9 }] } } } })) };
    expect(await countOutboxByStatus(client)).toEqual({ pending: 0, sending: 0, sent: 4, failed: 0, dead: 1 });
    expect(client.search.mock.calls[0][0].body.aggs.by_status.terms.field).toBe('status');
  });

  test('getOutboxEntry includes the payload; toOutboxEntry normalises a sparse source', async () => {
    const client: any = { get: jest.fn(async () => ({ body: { found: true, _source: { id: 'n1', status: 'sent', payload: { event: 'x' } } } })) };
    expect((await getOutboxEntry(client, 'n1'))!.payload).toEqual({ event: 'x' });
    client.get = jest.fn(async () => { throw notFound(); });
    expect(await getOutboxEntry(client, 'n1')).toBeNull();
    expect(toOutboxEntry('x', { status: 'bogus' })).toMatchObject({ id: 'x', status: 'pending', attempts: 0, last_error: null, delivery: null });
  });

  test('retryOutboxEntry: dead|failed -> pending due now with attempts kept; 404 / 409 otherwise', async () => {
    const stored: any = { id: 'n1', status: 'dead', attempts: 5, last_error: 'x', next_attempt_at: null };
    const client: any = {
      get: jest.fn(async () => ({ body: { _seq_no: 3, _primary_term: 1, _source: stored } })),
      update: jest.fn(async () => ({})),
    };
    const entry = await retryOutboxEntry(client, 'n1', { now: NOW });
    expect(entry).toMatchObject({ status: 'pending', attempts: 5, next_attempt_at: NOW.toISOString(), last_error: 'x' });
    expect(client.update.mock.calls[0][0]).toMatchObject({ index: NOTIFICATIONS_INDEX, id: 'n1', if_seq_no: 3, if_primary_term: 1, refresh: 'wait_for', body: { doc: { status: 'pending', next_attempt_at: NOW.toISOString(), claimed_by: null } } });
    stored.status = 'sent';
    await expect(retryOutboxEntry(client, 'n1')).rejects.toMatchObject({ statusCode: 409 });
    stored.status = 'failed';
    client.update = jest.fn(async () => { throw conflict(); });
    await expect(retryOutboxEntry(client, 'n1')).rejects.toMatchObject({ statusCode: 409 });
    client.get = jest.fn(async () => { throw notFound(); });
    await expect(retryOutboxEntry(client, 'n1')).rejects.toMatchObject({ statusCode: 404 });
  });
});
