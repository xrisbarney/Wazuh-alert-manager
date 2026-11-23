// These assertions describe the Wazuh 4.x behaviour of this module (native
// alert indices, numeric rule levels, the 4.x channel/source set). The build
// target is a build-time constant and CI runs this suite once per matrix
// entry, including the 5.0 one, so pin it rather than assert whichever
// target happens to be checked in.
jest.mock('../../common/build_info', () => ({ ...(jest.requireActual('../../common/build_info') as object), TARGET_WAZUH_MAJOR: 4, TARGET_WAZUH_VERSION: '4.14.10' }));

import { ACTIVITY_WRITE_ALIAS, API_ROOT, META_INDEX, NOTIFICATIONS_INDEX, NOTIFICATION_DISPATCHER_STATUS_DOC_ID, NOTIFICATION_FORBIDDEN_HINT, NOTIFICATION_RETRIED_ACTION, NOTIFICATION_SETTINGS_DOC_ID } from '../../common';
import { ENCRYPTION_KEY_ENV_VAR } from '../lib/secrets_config';
import { invalidateNotificationSettingsCache } from '../lib/notifications/settings';
import { setNotificationDispatcherRuntime } from '../lib/notifications/dispatcher';
import { NOTIFICATION_REDACTED_ERROR, defineNotificationRoutes, outboxQuerySchema, runChannelTest, testPayload } from './notifications';

jest.mock('../lib/authorization', () => ({ requirePluginAdmin: jest.fn() }));
jest.mock('../lib/notifications/transports', () => {
  const actual = jest.requireActual('../lib/notifications/transports');
  return { ...actual, sendWebhook: jest.fn(), sendIndexerChannel: jest.fn() };
});

/* eslint-disable @typescript-eslint/no-var-requires */
const requirePluginAdmin: jest.Mock = require('../lib/authorization').requirePluginAdmin;
const sendWebhook: jest.Mock = require('../lib/notifications/transports').sendWebhook;
const sendIndexerChannel: jest.Mock = require('../lib/notifications/transports').sendIndexerChannel;
/* eslint-enable @typescript-eslint/no-var-requires */

const KEY = 'unit-test-encryption-key-with-32-plus-characters';

function forbidden() {
  const error: any = new Error('Administrator permission is required for this operation.');
  error.statusCode = 403;
  throw error;
}

function clientWith(settings: any | null, transport: (req: any) => any = () => ({ body: { config_list: [] } })) {
  const client = {
    get: jest.fn(async (req: any) => {
      if (req.index === META_INDEX && req.id === NOTIFICATION_SETTINGS_DOC_ID && settings !== null) return { body: { _source: settings } };
      throw Object.assign(new Error('not found'), { meta: { statusCode: 404 } });
    }),
    index: jest.fn(async (req: any) => {
      if (req.index === META_INDEX) settings = req.body;
      return { body: { result: 'created' } };
    }),
    indices: { exists: jest.fn(async () => ({ body: false })) },
    transport: { request: jest.fn(async (req: any) => transport(req)) },
  };
  return client;
}

function response() {
  return {
    ok: jest.fn((r: any) => ({ kind: 'ok', ...r })),
    badRequest: jest.fn((r: any) => ({ kind: 'badRequest', ...r })),
    forbidden: jest.fn((r: any) => ({ kind: 'forbidden', ...r })),
    notFound: jest.fn((r: any) => ({ kind: 'notFound', ...r })),
    customError: jest.fn((r: any) => ({ kind: 'customError', ...r })),
  };
}

function routes() {
  const router: any = { get: jest.fn(), post: jest.fn(), put: jest.fn() };
  defineNotificationRoutes(router);
  const find = (method: 'get' | 'post' | 'put', path: string) => {
    const registration = router[method].mock.calls.find(([config]: any[]) => config.path === `${API_ROOT}${path}`);
    expect(registration).toBeDefined();
    return registration as [any, any];
  };
  return {
    getSettings: find('get', '/notifications/settings'),
    putSettings: find('put', '/notifications/settings'),
    channels: find('get', '/notifications/channels'),
    test: find('post', '/notifications/test/{channelId}'),
  };
}

function contextWith(client: any) {
  return { core: { opensearch: { client: { asCurrentUser: client } } } } as any;
}

const slack = { id: 'soc-slack', name: 'SOC Slack', kind: 'indexer_channel', enabled: true, events: ['case.created'], indexer_channel: { configId: 'abc123' } };
const hook = { id: 'siem-hook', name: 'SIEM', kind: 'webhook', enabled: true, events: ['sla.breached'], webhook: { url: 'https://hooks.example.com/wam', secret: 'shh', headers: { 'X-Tenant': 'soc' } } };

describe('notification routes', () => {
  beforeEach(() => {
    process.env[ENCRYPTION_KEY_ENV_VAR] = KEY;
    invalidateNotificationSettingsCache();
    requirePluginAdmin.mockReset();
    requirePluginAdmin.mockResolvedValue({ name: 'admin', source: 'security_plugin', securityRoles: ['all_access'] });
    sendWebhook.mockReset();
    sendIndexerChannel.mockReset();
  });
  afterAll(() => {
    delete process.env[ENCRYPTION_KEY_ENV_VAR];
  });

  test('registers the four routes with schema validation on every input-taking route', () => {
    const r = routes();
    expect(r.getSettings[0].validate).toBe(false);
    expect(r.channels[0].validate).toBe(false);
    expect(r.putSettings[0].validate.body).toBeDefined();
    expect(r.test[0].validate.params).toBeDefined();
  });

  test('PUT body schema: defaults, enums, unknown keys, caps', () => {
    const body = routes().putSettings[0].validate.body;
    const ok = body.validate({ channels: [{ id: 'a', name: 'A', kind: 'webhook', webhook: { url: 'https://x.example/h', secret: null, secretConfigured: true, contentType: 'application/json' } }] });
    expect(ok.enabled).toBe(false);
    expect(ok.channels[0].enabled).toBe(false);
    expect(ok.channels[0].events).toEqual([]);
    expect(() => body.validate({ channels: [{ ...slack, kind: 'email' }] })).toThrow();
    expect(() => body.validate({ channels: [{ ...slack, events: ['case.deleted'] }] })).toThrow();
    expect(() => body.validate({ channels: [{ ...slack, extra: 1 }] })).toThrow();
    expect(() => body.validate({ channels: [{ ...hook, webhook: { ...hook.webhook, contentType: 'text/plain' } }] })).toThrow();
    expect(() => body.validate({ channels: new Array(51).fill(slack) })).toThrow();
    expect(() => routes().test[0].validate.params.validate({ channelId: '' })).toThrow();
  });

  test('GET settings: administrators get the masked configs, other users a redacted summary; PUT and test are admin-only; channels is open', async () => {
    const r = routes();
    const stored = { enabled: true, channels: [slack, { ...hook, webhook: { url: hook.webhook.url, secret: 'ciphertext', contentType: 'application/json', headers: { 'X-Api-Key': 'token-123' } } }] };
    const client = clientWith(stored);
    const res = response();
    const adminRead = await r.getSettings[1](contextWith(client), {}, res);
    expect(adminRead.kind).toBe('ok');
    expect(adminRead.body.channels[1].webhook).toEqual({ url: 'https://hooks.example.com/wam', contentType: 'application/json', headers: { 'X-Api-Key': 'token-123' }, secretConfigured: true });
    expect(JSON.stringify(adminRead.body)).not.toContain('ciphertext');
    expect(adminRead.body).toMatchObject({ enabled: true, encryptionConfigured: true, egressAllowedHosts: [], wazuhMajor: 4 });
    expect(adminRead.body.redacted).toBeUndefined();

    requirePluginAdmin.mockImplementation(async () => forbidden());
    const read = await r.getSettings[1](contextWith(client), {}, res);
    expect(read.kind).toBe('ok');
    expect(read.body).toMatchObject({ enabled: true, encryptionConfigured: true, wazuhMajor: 4, redacted: true });
    expect(read.body).not.toHaveProperty('egressAllowedHosts');
    expect(read.body.channels).toEqual([
      { id: 'soc-slack', name: 'SOC Slack', kind: 'indexer_channel', enabled: true, events: ['case.created'] },
      { id: 'siem-hook', name: 'SIEM', kind: 'webhook', enabled: true, events: ['sla.breached'] },
    ]);
    const text = JSON.stringify(read.body);
    expect(text).not.toContain('hooks.example.com');
    expect(text).not.toContain('token-123');
    expect(text).not.toContain('ciphertext');
    expect(text).not.toContain('abc123');

    // A non-403 failure of the identity check is not silently a "non-admin".
    requirePluginAdmin.mockRejectedValueOnce(Object.assign(new Error('security plugin unavailable'), { statusCode: 502 }));
    expect((await r.getSettings[1](contextWith(client), {}, res)).kind).toBe('customError');

    expect((await r.putSettings[1](contextWith(client), { body: { enabled: false, channels: [] } }, res)).kind).toBe('forbidden');
    expect((await r.test[1](contextWith(client), { params: { channelId: 'siem-hook' } }, res)).kind).toBe('forbidden');
    expect(client.index).not.toHaveBeenCalled();
    expect((await r.channels[1](contextWith(client), {}, res)).kind).toBe('ok');
  });

  test('PUT rejects a bad URL with 400, stores a good list with the secret encrypted, audits from/to and invalidates the cache', async () => {
    const r = routes();
    const client = clientWith(null);
    const res = response();
    const bad = await r.putSettings[1](contextWith(client), { body: { enabled: true, channels: [{ ...hook, webhook: { url: 'https://hooks.local/x' } }] } }, res);
    expect(bad.kind).toBe('badRequest');
    expect(bad.body.message).toMatch(/local/);
    expect(client.index).not.toHaveBeenCalled();

    const good = await r.putSettings[1](contextWith(client), { body: { enabled: true, channels: [slack, hook] } }, res);
    expect(good.kind).toBe('ok');
    expect(good.body.channels[1].webhook).toEqual({ url: 'https://hooks.example.com/wam', headers: { 'X-Tenant': 'soc' }, contentType: 'application/json', secretConfigured: true });
    const writes = client.index.mock.calls.map((c: any[]) => c[0]);
    expect(writes[0].index).toBe(META_INDEX);
    expect(writes[0].body.channels[1].webhook.secret).not.toBe('shh');
    expect(writes[1].index).toBe(ACTIVITY_WRITE_ALIAS);
    expect(writes[1].body).toMatchObject({
      target_type: 'system',
      target_id: 'notification_settings',
      action: 'notification_settings_updated',
      user: 'admin',
      from: 'enabled=false;channels=0',
      to: 'enabled=true;channels=2;soc-slack:indexer_channel,siem-hook:webhook',
    });

    const again = await r.putSettings[1](contextWith(client), { body: { enabled: false, channels: [slack] } }, res);
    expect(again.body.channels).toHaveLength(1);
    expect(client.index.mock.calls[3][0].body.from).toBe('enabled=true;channels=2;soc-slack:indexer_channel,siem-hook:webhook');
  });

  test('GET channels lists Notifications channels as the current user and maps 403 to forbidden (200)', async () => {
    const r = routes();
    const res = response();
    const listing = { config_list: [{ config_id: 'abc123', config: { name: 'SOC', config_type: 'slack', is_enabled: true } }] };
    const ok = await r.channels[1](contextWith(clientWith(null, () => ({ body: listing }))), {}, res);
    expect(ok.kind).toBe('ok');
    expect(ok.body).toEqual({ channels: [{ configId: 'abc123', name: 'SOC', type: 'slack', isEnabled: true, warnings: [] }], access: 'ok' });
    const denied = await r.channels[1](
      contextWith(
        clientWith(null, () => {
          throw Object.assign(new Error('forbidden'), { meta: { statusCode: 403 } });
        })
      ),
      {},
      res
    );
    expect(denied.kind).toBe('ok');
    expect(denied.body).toMatchObject({ channels: [], access: 'forbidden' });
  });

  test('test send: 404 for an unsaved channel, webhook path decrypts the secret, indexer path renders subject/text, failures are 200 results', async () => {
    const r = routes();
    const client = clientWith(null);
    const res = response();
    expect((await r.test[1](contextWith(client), { params: { channelId: 'nope' } }, res)).kind).toBe('notFound');

    await r.putSettings[1](contextWith(client), { body: { enabled: true, channels: [slack, hook] } }, res);
    sendWebhook.mockResolvedValue({ ok: true, statusCode: 204, error: null, deliveryId: 'd', durationMs: 12 });
    const hookTest = await r.test[1](contextWith(client), { params: { channelId: 'siem-hook' } }, res);
    expect(hookTest.kind).toBe('ok');
    expect(hookTest.body).toEqual({ channelId: 'siem-hook', kind: 'webhook', ok: true, statusCode: 204, error: null, durationMs: 12 });
    const [sentClient, sentChannel, sentSecret, sentPayload] = sendWebhook.mock.calls[0];
    expect(sentClient).toBe(client);
    expect(sentChannel.id).toBe('siem-hook');
    expect(sentSecret).toBe('shh');
    expect(sentPayload).toMatchObject({ event: 'test', case: null, actor: 'settings:test', message: expect.stringContaining('siem-hook') });

    sendIndexerChannel.mockResolvedValue({ ok: false, statusCode: 403, error: 'no permissions', deliveryId: 'd', durationMs: 5 });
    const slackTest = await r.test[1](contextWith(client), { params: { channelId: 'soc-slack' } }, res);
    expect(slackTest.kind).toBe('ok');
    expect(slackTest.body).toMatchObject({ channelId: 'soc-slack', kind: 'indexer_channel', ok: false, statusCode: 403, error: 'no permissions' });
    const [, configId, message] = sendIndexerChannel.mock.calls[0];
    expect(configId).toBe('abc123');
    expect(message.subject).toBe('[Wazuh Alert Manager] Test notification');
    expect(message.message).toContain('Test notification for channel "SOC Slack" (soc-slack).');
  });

  test('a webhook test without the encryption key is a 409', async () => {
    const r = routes();
    const client = clientWith(null);
    const res = response();
    await r.putSettings[1](contextWith(client), { body: { enabled: true, channels: [hook] } }, res);
    delete process.env[ENCRYPTION_KEY_ENV_VAR];
    const out = await r.test[1](contextWith(client), { params: { channelId: 'siem-hook' } }, res);
    expect(out).toMatchObject({ kind: 'customError', statusCode: 409 });
    expect(sendWebhook).not.toHaveBeenCalled();
  });

  test('runChannelTest / testPayload build a fixed allowlisted payload', async () => {
    const payload = testPayload(slack as any, new Date('2026-11-21T12:00:00.000Z'));
    expect(payload).toEqual({ event: 'test', occurred_at: '2026-11-21T12:00:00.000Z', source: 'wazuh-alert-manager', case: null, actor: 'settings:test', message: 'Test notification for channel "SOC Slack" (soc-slack).' });
    const send = jest.fn(async () => ({ ok: true, statusCode: 200, error: null, deliveryId: 'x', durationMs: 1 }));
    const out = await runChannelTest({}, slack as any, { sendIndexerChannel: send as any });
    expect(out).toMatchObject({ channelId: 'soc-slack', kind: 'indexer_channel', ok: true, statusCode: 200 });
  });
});

// ---------------------------------------------------------------------------
// Outbox routes (step 1.2)
// ---------------------------------------------------------------------------

describe('notification outbox routes (step 1.2)', () => {
  const NOW = '2026-11-21T10:00:00.000Z';

  function outboxRoutes() {
    const router: any = { get: jest.fn(), post: jest.fn(), put: jest.fn() };
    defineNotificationRoutes(router);
    const find = (method: 'get' | 'post', path: string) => {
      const registration = router[method].mock.calls.find(([config]: any[]) => config.path === `${API_ROOT}${path}`);
      expect(registration).toBeDefined();
      return registration as [any, any];
    };
    return {
      list: find('get', '/notifications/outbox'),
      one: find('get', '/notifications/outbox/{id}'),
      retry: find('post', '/notifications/outbox/{id}/retry'),
      status: find('get', '/notifications/status'),
    };
  }

  const entry = (id: string, extra: any = {}) => ({
    id, event: 'case.created', channel_id: 'soc-slack', channel_kind: 'indexer_channel', status: 'failed', subject: 's', target_type: 'case', target_id: 'c1',
    attempts: 2, created_at: NOW, next_attempt_at: NOW, sent_at: null, updated_at: NOW, last_error: 'HTTP 500', last_status_code: 500, delivery: null, dedupe_key: null,
    payload: { event: 'case.created', case: { id: 'c1' } }, ...extra,
  });

  function outboxClient(docs: Record<string, any>, statusDoc: any = null) {
    const client: any = {
      search: jest.fn(async (req: any) => {
        if (req.index !== NOTIFICATIONS_INDEX) throw new Error(`unexpected index ${req.index}`);
        if (req.size === 0) return { body: { aggregations: { by_status: { buckets: [{ key: 'failed', doc_count: 2 }, { key: 'sent', doc_count: 5 }] } } } };
        const hits = Object.entries(docs).map(([id, source]) => ({ _id: id, _source: source }));
        return { body: { hits: { total: { value: hits.length }, hits } } };
      }),
      get: jest.fn(async (req: any) => {
        if (req.index === META_INDEX && req.id === NOTIFICATION_DISPATCHER_STATUS_DOC_ID && statusDoc) return { body: { _source: statusDoc } };
        if (req.index === NOTIFICATIONS_INDEX && docs[req.id]) return { body: { _seq_no: 1, _primary_term: 1, found: true, _source: docs[req.id] } };
        throw Object.assign(new Error('not found'), { meta: { statusCode: 404 } });
      }),
      update: jest.fn(async (req: any) => {
        docs[req.id] = { ...docs[req.id], ...req.body.doc };
        return {};
      }),
      index: jest.fn(async () => ({})),
    };
    return client;
  }

  beforeEach(() => {
    requirePluginAdmin.mockReset();
    requirePluginAdmin.mockResolvedValue({ name: 'admin', source: 'security_plugin', securityRoles: ['all_access'] });
    setNotificationDispatcherRuntime({ notifications: { dispatcher: { enabled: true, tickSeconds: 5 } } } as any);
  });

  test('registers the four outbox routes with validation on every input-taking one', () => {
    const r = outboxRoutes();
    expect(r.list[0].validate.query).toBeDefined();
    expect(r.one[0].validate.params).toBeDefined();
    expect(r.retry[0].validate.params).toBeDefined();
    expect(r.status[0].validate).toBe(false);
    const q = outboxQuerySchema.validate({});
    expect(q.limit).toBe(50);
    expect(outboxQuerySchema.validate({ status: 'dead', event: 'sla.breached', channelId: 'x', cursor: 'abc', limit: 200 })).toMatchObject({ status: 'dead', limit: 200 });
    expect(() => outboxQuerySchema.validate({ status: 'lost' })).toThrow();
    expect(() => outboxQuerySchema.validate({ event: 'case.deleted' })).toThrow();
    expect(() => outboxQuerySchema.validate({ limit: 201 })).toThrow();
    expect(() => outboxQuerySchema.validate({ limit: 0 })).toThrow();
    expect(() => r.one[0].validate.params.validate({ id: '' })).toThrow();
  });

  test('GET outbox lists for any signed-in user without the payload and passes the filter through; administrators get the recorded error and the claim holder verbatim', async () => {
    const r = outboxRoutes();
    const hostError = 'Receiver answered HTTP 500: upstream hooks.internal.example said no';
    const client = outboxClient({
      n1: entry('n1', { last_error: hostError, claimed_by: 'host-1-abcd', claimed_at: NOW }),
      n2: entry('n2', { status: 'sent', last_error: null, last_status_code: 200 }),
    });
    const res = response();
    const out = await r.list[1](contextWith(client), { query: { status: 'failed', channelId: 'soc-slack', limit: 50 } }, res);
    expect(out.kind).toBe('ok');
    expect(out.body.items.map((i: any) => i.id)).toEqual(['n1', 'n2']);
    expect(out.body.items[0].payload).toBeUndefined();
    expect(out.body.items[0]).toMatchObject({ status: 'failed', last_error: hostError, attempts: 2, claimed_by: 'host-1-abcd', claimed_at: NOW });
    expect(out.body.next_cursor).toBeNull();
    expect(out.body.total).toBe(2);
    const req = client.search.mock.calls[0][0];
    expect(req.body.query.bool.filter).toEqual([{ term: { status: 'failed' } }, { term: { channel_id: 'soc-slack' } }]);
    expect(req.body._source).toEqual({ excludes: ['payload'] });
    const bad = await r.list[1](contextWith(client), { query: { cursor: '!!!', limit: 50 } }, response());
    expect(bad.kind).toBe('badRequest');
  });

  test('GET outbox redacts the recorded error and the claim holder for non-administrators (the role hint of a 403 is kept)', async () => {
    requirePluginAdmin.mockImplementation(forbidden);
    const r = outboxRoutes();
    const client = outboxClient({
      n1: entry('n1', { last_error: 'Request to hooks.internal.example timed out', last_status_code: null, claimed_by: 'host-1-abcd', claimed_at: NOW }),
      n2: entry('n2', { last_error: 'Receiver answered HTTP 500: secret body', last_status_code: 500 }),
      n3: entry('n3', { status: 'dead', last_error: `no permissions for [cluster:admin/opendistro/alerting/monitor/execute] (hint: ${NOTIFICATION_FORBIDDEN_HINT})`, last_status_code: 403 }),
      n4: entry('n4', { status: 'sent', last_error: null, last_status_code: 200 }),
    });
    const out = await r.list[1](contextWith(client), { query: { limit: 50 } }, response());
    expect(out.kind).toBe('ok');
    const byId = Object.fromEntries(out.body.items.map((i: any) => [i.id, i]));
    expect(byId.n1.last_error).toBe(NOTIFICATION_REDACTED_ERROR);
    expect(byId.n2.last_error).toBe('Delivery failed (HTTP 500); an administrator can read the recorded error.');
    expect(byId.n3.last_error).toBe(`Delivery failed (HTTP 403); an administrator can read the recorded error. Hint: ${NOTIFICATION_FORBIDDEN_HINT}.`);
    expect(byId.n4.last_error).toBeNull();
    for (const item of out.body.items) {
      expect(item).not.toHaveProperty('claimed_by');
      expect(item).not.toHaveProperty('claimed_at');
      expect(item).not.toHaveProperty('payload');
      expect(JSON.stringify(item)).not.toContain('hooks.internal.example');
      expect(JSON.stringify(item)).not.toContain('secret body');
    }
    expect(byId.n2.last_status_code).toBe(500);
  });

  test('GET outbox/{id} answers the payload to administrators only; 404 when absent', async () => {
    const r = outboxRoutes();
    const client = outboxClient({ n1: entry('n1') });
    const out = await r.one[1](contextWith(client), { params: { id: 'n1' } }, response());
    expect(out.kind).toBe('ok');
    expect(out.body.payload).toEqual({ event: 'case.created', case: { id: 'c1' } });
    const missing = await r.one[1](contextWith(client), { params: { id: 'nope' } }, response());
    expect(missing.kind).toBe('notFound');
    requirePluginAdmin.mockImplementation(forbidden);
    const denied = await r.one[1](contextWith(client), { params: { id: 'n1' } }, response());
    expect(denied.kind).toBe('forbidden');
    expect(client.get).toHaveBeenCalledTimes(2);
  });

  test('POST retry: admin-only; dead|failed -> pending due now with attempts kept, audited; 409 for other statuses; 404 when absent', async () => {
    const r = outboxRoutes();
    const docs = { dead1: entry('dead1', { status: 'dead', attempts: 5, next_attempt_at: null }), sent1: entry('sent1', { status: 'sent' }) };
    const client = outboxClient(docs);
    const out = await r.retry[1](contextWith(client), { params: { id: 'dead1' } }, response());
    expect(out.kind).toBe('ok');
    expect(out.body).toMatchObject({ id: 'dead1', status: 'pending', attempts: 5 });
    expect(typeof out.body.next_attempt_at).toBe('string');
    expect(docs.dead1).toMatchObject({ status: 'pending', attempts: 5, claimed_by: null });
    expect(client.update.mock.calls[0][0]).toMatchObject({ index: NOTIFICATIONS_INDEX, id: 'dead1', if_seq_no: 1, if_primary_term: 1 });
    const audit = client.index.mock.calls.find(([req]: any[]) => req.index === ACTIVITY_WRITE_ALIAS)[0];
    expect(audit.body).toMatchObject({ action: NOTIFICATION_RETRIED_ACTION, target_type: 'system', target_id: 'dead1', user: 'admin', from: 'dead', to: 'pending' });
    expect(audit.body.details).toMatchObject({ event: 'case.created', channel_id: 'soc-slack', target_type: 'case', target_id: 'c1', attempts: 5 });

    const conflict = await r.retry[1](contextWith(client), { params: { id: 'sent1' } }, response());
    expect(conflict.kind).toBe('customError');
    expect(conflict.statusCode).toBe(409);
    expect(conflict.body.message).toMatch(/only failed or dead entries can be retried/);
    const missing = await r.retry[1](contextWith(client), { params: { id: 'nope' } }, response());
    expect(missing.kind).toBe('notFound');

    requirePluginAdmin.mockImplementation(forbidden);
    const denied = await r.retry[1](contextWith(client), { params: { id: 'dead1' } }, response());
    expect(denied.kind).toBe('forbidden');
  });

  test('GET status: dispatcher status + runtime + counts; the lease holder only for administrators', async () => {
    const r = outboxRoutes();
    const stored = { document_type: 'notification_dispatcher_status', last_tick_at: NOW, holder: 'host-1-abcd', claimed: 3, sent: 2, failed: 1, dead: 0, errors: [{ at: NOW, message: 'x' }] };
    const client = outboxClient({}, stored);
    const admin = await r.status[1](contextWith(client), {}, response());
    expect(admin.kind).toBe('ok');
    expect(admin.body).toEqual({
      enabled: true,
      tickSeconds: 5,
      status: { last_tick_at: NOW, holder: 'host-1-abcd', claimed: 3, sent: 2, failed: 1, dead: 0, errors: [{ at: NOW, message: 'x' }] },
      counts: { pending: 0, sending: 0, sent: 5, failed: 2, dead: 0 },
    });
    requirePluginAdmin.mockImplementation(forbidden);
    const user = await r.status[1](contextWith(client), {}, response());
    expect(user.kind).toBe('ok');
    expect(user.body.status.holder).toBeUndefined();
    expect(user.body.status.errors).toEqual([]);
    expect(user.body.status.claimed).toBe(3);
    // Never ticked, no outbox index yet: nulls and zeros, not an error.
    const fresh = outboxClient({});
    fresh.search = jest.fn(async () => { throw Object.assign(new Error('no index'), { meta: { statusCode: 404 } }); });
    const empty = await r.status[1](contextWith(fresh), {}, response());
    expect(empty.body).toMatchObject({ status: null, counts: { pending: 0, sent: 0 } });
  });
});
