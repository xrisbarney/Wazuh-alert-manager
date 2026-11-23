import { META_INDEX, NOTIFICATION_SETTINGS_DOC_ID } from '../../../common';
import { EGRESS_ALLOWED_HOSTS_ENV_VAR } from '../egress/url_policy';
import { decryptSecret } from '../crypto';
import { ENCRYPTION_KEY_ENV_VAR } from '../secrets_config';
import {
  channelsForEvent,
  findChannel,
  getNotificationChannels,
  invalidateNotificationSettingsCache,
  loadNotificationSettings,
  normaliseNotificationSettings,
  notificationSettings,
  notificationSettingsAuditSummary,
  primeNotificationSettingsCache,
  resolveWebhookSecret,
  saveNotificationSettings,
} from './settings';

const KEY = 'unit-test-encryption-key-with-32-plus-characters';

function clientWith(stored: any | null) {
  let doc = stored;
  const client = {
    get: jest.fn(async (req: any) => {
      if (req.index === META_INDEX && req.id === NOTIFICATION_SETTINGS_DOC_ID && doc !== null) return { body: { _source: doc } };
      throw Object.assign(new Error('not found'), { meta: { statusCode: 404 } });
    }),
    index: jest.fn(async (req: any) => {
      if (req.index === META_INDEX && req.id === NOTIFICATION_SETTINGS_DOC_ID) doc = req.body;
      return { body: { result: 'created' } };
    }),
    stored: () => doc,
  };
  return client;
}

function expectBadRequest(fn: () => unknown, pattern: RegExp) {
  try {
    fn();
  } catch (e: any) {
    expect(e.statusCode).toBe(400);
    expect(e.message).toMatch(pattern);
    return;
  }
  throw new Error('expected a 400 error');
}

const slack = { id: 'soc-slack', name: 'SOC Slack', kind: 'indexer_channel', enabled: true, events: ['case.created', 'case.closed'], indexer_channel: { configId: 'abc123' } };
const hook = { id: 'siem-hook', name: 'SIEM webhook', kind: 'webhook', enabled: true, events: ['sla.breached'], webhook: { url: 'https://hooks.example.com/wam', headers: { 'X-Tenant': 'soc' } } };

describe('normaliseNotificationSettings', () => {
  beforeEach(() => {
    delete process.env[EGRESS_ALLOWED_HOSTS_ENV_VAR];
  });

  test('normalises both kinds, orders events canonically and drops empty headers', () => {
    const out = normaliseNotificationSettings({
      enabled: true,
      channels: [
        { ...slack, name: '  SOC Slack  ', events: ['case.closed', 'case.created', 'case.created'] },
        { ...hook, webhook: { url: ' https://hooks.example.com/wam ', headers: {}, contentType: 'application/json' } },
      ] as any,
    });
    expect(out.enabled).toBe(true);
    expect(out.channels[0]).toEqual({ id: 'soc-slack', name: 'SOC Slack', kind: 'indexer_channel', enabled: true, events: ['case.created', 'case.closed'], indexer_channel: { configId: 'abc123' } });
    expect(out.channels[1]).toEqual({ id: 'siem-hook', name: 'SIEM webhook', kind: 'webhook', enabled: true, events: ['sla.breached'], webhook: { url: 'https://hooks.example.com/wam', contentType: 'application/json' } });
    expect(normaliseNotificationSettings(null)).toEqual({ enabled: false, channels: [] });
  });

  test('rejects bad ids, duplicate ids, unknown kinds and unknown events', () => {
    expectBadRequest(() => normaliseNotificationSettings({ channels: [{ ...slack, id: 'Bad Id' }] } as any), /id must be/);
    expectBadRequest(() => normaliseNotificationSettings({ channels: [{ ...slack, id: ' soc-slack ' }] } as any), /id must be/);
    expectBadRequest(() => normaliseNotificationSettings({ channels: [slack, { ...hook, id: 'soc-slack' }] } as any), /more than once/);
    expectBadRequest(() => normaliseNotificationSettings({ channels: [{ ...slack, kind: 'email' }] } as any), /kind must be one of/);
    expectBadRequest(() => normaliseNotificationSettings({ channels: [{ ...slack, events: ['case.deleted'] }] } as any), /unknown event "case.deleted"/);
    expectBadRequest(() => normaliseNotificationSettings({ channels: [{ ...slack, events: 'case.created' }] } as any), /events must be a list/);
    expectBadRequest(() => normaliseNotificationSettings({ channels: [{ ...slack, name: '' }] } as any), /name is required/);
    expectBadRequest(() => normaliseNotificationSettings({ channels: [{ ...slack, indexer_channel: { configId: '' } }] } as any), /select a Notifications channel/);
    expectBadRequest(() => normaliseNotificationSettings({ channels: [{ ...slack, indexer_channel: { configId: 'a b' } }] } as any), /single Notifications config id/);
    expectBadRequest(() => normaliseNotificationSettings({ enabled: 'yes' } as any), /enabled must be a boolean/);
    expectBadRequest(() => normaliseNotificationSettings({ channels: new Array(51).fill(slack) } as any), /At most 50/);
  });

  test('applies the egress policy to webhook URLs exactly like enrichment sources', () => {
    const withUrl = (url: string, extra: any = {}) => normaliseNotificationSettings({ channels: [{ ...hook, webhook: { ...hook.webhook, url, ...extra } }] } as any);
    expectBadRequest(() => withUrl('http://hooks.example.com/wam'), /HTTPS/);
    expectBadRequest(() => withUrl('https://10.0.0.5/hook'), /IP literal/);
    expectBadRequest(() => withUrl('https://localhost/hook'), /local/);
    expectBadRequest(() => withUrl('https://user:pw@hooks.example.com/'), /credentials/);
    expectBadRequest(() => withUrl(''), /receiver URL/);
    expectBadRequest(() => withUrl('https://hooks.example.com/wam', { contentType: 'text/plain' }), /fixed to application\/json/);
    // Q9 escape hatch: an allowlisted local-suffix name may be private and plain http with the flag.
    process.env[EGRESS_ALLOWED_HOSTS_ENV_VAR] = 'receiver.internal';
    expectBadRequest(() => withUrl('https://hooks.example.com/wam'), /not allowed/);
    expectBadRequest(() => withUrl('http://receiver.internal/hook'), /HTTPS/);
    const ok = withUrl('http://receiver.internal/hook', { allowInsecure: true });
    expect(ok.channels[0].webhook).toEqual({ url: 'http://receiver.internal/hook', headers: { 'X-Tenant': 'soc' }, contentType: 'application/json', allowInsecure: true });
  });

  test('validates webhook headers: names, reserved names, duplicates, caps', () => {
    const withHeaders = (headers: any) => normaliseNotificationSettings({ channels: [{ ...hook, webhook: { ...hook.webhook, headers } }] } as any);
    expect(withHeaders({ 'X-Tenant': ' soc ' }).channels[0].webhook!.headers).toEqual({ 'X-Tenant': 'soc' });
    expectBadRequest(() => withHeaders({ 'Content-Type': 'text/plain' }), /cannot be overridden/);
    expectBadRequest(() => withHeaders({ authorization: 'Bearer x' }), /cannot be overridden/);
    expectBadRequest(() => withHeaders({ 'X-WAM-Signature': 'x' }), /cannot be overridden/);
    expectBadRequest(() => withHeaders({ 'X-Tenant': 'a', 'x-tenant': 'b' }), /more than once/);
    expectBadRequest(() => withHeaders({ 'Bad Name': 'a' }), /invalid header name/);
    expectBadRequest(() => withHeaders({ 'X-A': 'line1\nline2' }), /single-line/);
    expectBadRequest(() => withHeaders(['a']), /must be an object/);
    const many: Record<string, string> = {};
    for (let i = 0; i < 11; i += 1) many[`X-H${i}`] = 'v';
    expectBadRequest(() => withHeaders(many), /at most 10 headers/);
  });
});

describe('notification settings document', () => {
  beforeEach(() => {
    process.env[ENCRYPTION_KEY_ENV_VAR] = KEY;
    delete process.env[EGRESS_ALLOWED_HOSTS_ENV_VAR];
    invalidateNotificationSettingsCache();
  });
  afterAll(() => {
    delete process.env[ENCRYPTION_KEY_ENV_VAR];
  });

  test('declares the secret path and masks it as secretConfigured on read', () => {
    expect(notificationSettings.docId).toBe(NOTIFICATION_SETTINGS_DOC_ID);
    expect(notificationSettings.secretFields).toEqual(['channels[].webhook.secret']);
  });

  test('secret round trip: encrypted at rest, masked on load, kept on re-save, cleared with null, resolved server-side', async () => {
    const client = clientWith(null);
    const saved = await saveNotificationSettings(client, { enabled: true, channels: [slack, { ...hook, webhook: { ...hook.webhook, secret: 'top-secret' } }] }, { updatedBy: 'admin' });
    expect(saved.updated_by).toBe('admin');
    expect(saved.channels[1].webhook).toEqual({ url: 'https://hooks.example.com/wam', headers: { 'X-Tenant': 'soc' }, contentType: 'application/json', secretConfigured: true });
    expect((saved.channels[1].webhook as any).secret).toBeUndefined();
    const stored = client.stored();
    expect(stored.channels[1].webhook.secret).not.toBe('top-secret');
    expect(decryptSecret(stored.channels[1].webhook.secret, KEY)).toBe('top-secret');
    expect(stored.channels[0].webhook).toBeUndefined();

    const loaded = await loadNotificationSettings(client);
    expect(loaded.channels[1].webhook!.secretConfigured).toBe(true);
    expect(loaded.channels[0]).not.toHaveProperty('webhook');
    expect(await resolveWebhookSecret(client, loaded.channels[1])).toBe('top-secret');
    expect(await resolveWebhookSecret(client, loaded.channels[0])).toBe('');

    // Re-saving without the secret (or with the echoed flag / '' / mask) keeps it.
    const kept = await saveNotificationSettings(client, { enabled: true, channels: [{ ...hook, webhook: { ...hook.webhook, secret: '', secretConfigured: true } }] }, { updatedBy: 'admin' });
    expect(kept.channels[0].webhook!.secretConfigured).toBe(true);
    expect(await resolveWebhookSecret(client, kept.channels[0])).toBe('top-secret');
    // Reordering keeps the secret by id, not position.
    const reordered = await saveNotificationSettings(client, { enabled: true, channels: [slack, hook] }, { updatedBy: 'admin' });
    expect(reordered.channels[1].webhook!.secretConfigured).toBe(true);
    expect(await resolveWebhookSecret(client, reordered.channels[1])).toBe('top-secret');
    // null clears it.
    const cleared = await saveNotificationSettings(client, { enabled: true, channels: [{ ...hook, webhook: { ...hook.webhook, secret: null } }] }, { updatedBy: 'admin' });
    expect(cleared.channels[0].webhook!.secretConfigured).toBe(false);
    expect(await resolveWebhookSecret(client, cleared.channels[0])).toBe('');
  });

  test('a missing encryption key is a 400 on save and a typed 409 on resolve', async () => {
    const client = clientWith(null);
    await saveNotificationSettings(client, { enabled: true, channels: [{ ...hook, webhook: { ...hook.webhook, secret: 's3cret' } }] }, { updatedBy: 'admin' });
    delete process.env[ENCRYPTION_KEY_ENV_VAR];
    await expect(saveNotificationSettings(client, { enabled: true, channels: [{ ...hook, webhook: { ...hook.webhook, secret: 'other' } }] }, { updatedBy: 'admin' })).rejects.toMatchObject({ statusCode: 400 });
    await expect(resolveWebhookSecret(client, hook as any)).rejects.toMatchObject({ statusCode: 409, message: expect.stringContaining(ENCRYPTION_KEY_ENV_VAR) });
    process.env[ENCRYPTION_KEY_ENV_VAR] = 'a-different-key-of-at-least-32-characters!!';
    await expect(resolveWebhookSecret(client, hook as any)).rejects.toMatchObject({ statusCode: 409, message: expect.stringContaining('changed') });
  });

  test('save rejects a bad list before writing and the audit summary is compact', async () => {
    const client = clientWith(null);
    await expect(saveNotificationSettings(client, { enabled: true, channels: [{ ...hook, webhook: { url: 'https://10.1.1.1/x' } }] }, { updatedBy: 'admin' })).rejects.toMatchObject({ statusCode: 400 });
    expect(client.index).not.toHaveBeenCalled();
    expect(notificationSettingsAuditSummary({ enabled: true, channels: [slack as any, { ...hook, enabled: false } as any] })).toBe('enabled=true;channels=2;soc-slack:indexer_channel,siem-hook:webhook(off)');
    expect(notificationSettingsAuditSummary({ enabled: false, channels: [] })).toBe('enabled=false;channels=0');
  });

  test('getNotificationChannels caches for the TTL, never throws, and a save primes the cache', async () => {
    const client = clientWith({ enabled: true, channels: [slack] });
    const first = await getNotificationChannels(client);
    expect(first.channels.map((c) => c.id)).toEqual(['soc-slack']);
    await getNotificationChannels(client);
    expect(client.get).toHaveBeenCalledTimes(1);

    invalidateNotificationSettingsCache();
    client.get.mockRejectedValueOnce(new Error('cluster away'));
    const warn = jest.fn();
    const degraded = await getNotificationChannels(client, { warn });
    expect(degraded).toEqual({ enabled: false, channels: [] });
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('cluster away'));

    primeNotificationSettingsCache({ enabled: true, channels: [slack as any, hook as any] });
    const primed = await getNotificationChannels(client);
    expect(primed.channels).toHaveLength(2);

    await saveNotificationSettings(client, { enabled: false, channels: [slack] }, { updatedBy: 'admin' });
    const afterSave = await getNotificationChannels(client);
    expect(afterSave.enabled).toBe(false);
    expect(afterSave.channels).toHaveLength(1);
  });

  test('a stored webhook URL outside a later-narrowed egress allowlist still loads and caches; only that channel is flagged and disabled', async () => {
    const client = clientWith(null);
    await saveNotificationSettings(client, { enabled: true, channels: [slack, hook] }, { updatedBy: 'admin' });
    invalidateNotificationSettingsCache();
    process.env[EGRESS_ALLOWED_HOSTS_ENV_VAR] = 'intel.internal';

    const loaded = await loadNotificationSettings(client);
    expect(loaded.enabled).toBe(true);
    expect(loaded.channels.map((c) => c.id)).toEqual(['soc-slack', 'siem-hook']);
    expect(loaded.channels[0]).not.toHaveProperty('invalid');
    expect(loaded.channels[0].enabled).toBe(true);
    expect(loaded.channels[1]).toMatchObject({ enabled: false, invalid: expect.stringMatching(/not allowed/) });
    expect(loaded.channels[1].webhook).toMatchObject({ url: 'https://hooks.example.com/wam', secretConfigured: false });

    const cached = await getNotificationChannels(client);
    expect(cached.enabled).toBe(true);
    expect(channelsForEvent(cached, 'case.created').map((c) => c.id)).toEqual(['soc-slack']);
    expect(channelsForEvent(cached, 'sla.breached')).toEqual([]);

    // The write path still enforces the policy: re-saving the stale URL is a 400, nothing is written.
    const writes = client.index.mock.calls.length;
    await expect(saveNotificationSettings(client, { enabled: true, channels: [slack, hook] }, { updatedBy: 'admin' })).rejects.toMatchObject({ statusCode: 400 });
    expect(client.index).toHaveBeenCalledTimes(writes);
    // `invalid` is never stored.
    expect(JSON.stringify(client.stored())).not.toContain('"invalid"');
    expect(normaliseNotificationSettings({ channels: [hook] } as any, { egress: 'flag' }).channels[0]).toMatchObject({ enabled: false, invalid: expect.any(String) });
  });

  test('channelsForEvent honours the global switch, enabled flag and binding; findChannel by id', () => {
    const settings: any = { enabled: true, channels: [slack, { ...hook, enabled: false }, { ...hook, id: 'h2', events: ['sla.breached', 'case.created'] }] };
    expect(channelsForEvent(settings, 'case.created').map((c) => c.id)).toEqual(['soc-slack', 'h2']);
    expect(channelsForEvent(settings, 'sla.breached').map((c) => c.id)).toEqual(['h2']);
    expect(channelsForEvent(settings, 'rule.action')).toEqual([]);
    expect(channelsForEvent({ ...settings, enabled: false }, 'case.created')).toEqual([]);
    expect(channelsForEvent(null, 'case.created')).toEqual([]);
    expect(findChannel(settings, 'h2')!.id).toBe('h2');
    expect(findChannel(settings, 'nope')).toBeNull();
  });
});
