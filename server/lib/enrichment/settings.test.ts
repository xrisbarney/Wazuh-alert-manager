import { ENRICHMENT_SETTINGS_DOC_ID, META_INDEX, TARGET_WAZUH_MAJOR, WAZUH_CTI_LOCAL_SOURCE_ID } from '../../../common';
import { EGRESS_ALLOWED_HOSTS_ENV_VAR } from '../egress/url_policy';
import { ENCRYPTION_KEY_ENV_VAR } from '../secrets_config';
import { assertUrlTemplate, builtInCtiLocalSource, enrichmentSettings, normaliseEnrichmentSettings, withBuiltInSources } from './settings';

const KEY = 'unit-test-encryption-key-with-32-plus-characters';

function clientWith(stored: any | null) {
  return {
    get: jest.fn(async (_req: any) => {
      if (stored === null) throw Object.assign(new Error('not found'), { meta: { statusCode: 404 } });
      return { body: { _source: stored } };
    }),
    index: jest.fn(async (_req: any) => ({ body: { result: 'created' } })),
  };
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

const misp = { id: 'misp-1', name: 'Corp MISP', kind: 'misp', enabled: true, baseUrl: 'https://misp.example.org/' };

describe('normaliseEnrichmentSettings', () => {
  beforeEach(() => {
    delete process.env[EGRESS_ALLOWED_HOSTS_ENV_VAR];
  });

  test('applies defaults, bounds and kind capabilities', () => {
    const out = normaliseEnrichmentSettings({
      sources: [
        { id: 'abuseipdb', name: ' Abuse ', kind: 'abuseipdb', enabled: true, timeoutMs: 999999, cacheTtlSeconds: 1 } as any,
        { ...misp, supports: ['ip', 'hash'], timeoutMs: 500 } as any,
      ],
    });
    expect(out.sources[0]).toEqual({
      id: 'abuseipdb',
      name: 'Abuse',
      kind: 'abuseipdb',
      enabled: true,
      supports: ['ip'],
      cacheTtlSeconds: 60,
      timeoutMs: 30000,
    });
    expect(out.sources[1].baseUrl).toBe('https://misp.example.org');
    expect(out.sources[1].supports).toEqual(['ip', 'hash']);
    expect(out.sources[1].timeoutMs).toBe(1000);
  });

  test('rejects a type outside the kind capability, duplicate ids and bad ids', () => {
    expectBadRequest(
      () => normaliseEnrichmentSettings({ sources: [{ id: 'a', name: 'a', kind: 'abuseipdb', enabled: true, supports: ['domain'] } as any] }),
      /cannot look up "domain"/
    );
    expectBadRequest(() => normaliseEnrichmentSettings({ sources: [misp, { ...misp, name: 'other' }] as any }), /more than once/);
    expectBadRequest(() => normaliseEnrichmentSettings({ sources: [{ ...misp, id: 'Bad Id!' }] as any }), /id must be/);
    // Ids are validated as submitted, never rewritten (a rewritten id would detach the secret site).
    expectBadRequest(() => normaliseEnrichmentSettings({ sources: [{ ...misp, id: 'MyMisp' }] as any }), /id must be/);
    expectBadRequest(() => normaliseEnrichmentSettings({ sources: [{ ...misp, id: ' misp-1 ' }] as any }), /id must be/);
    expectBadRequest(() => normaliseEnrichmentSettings({ sources: [{ ...misp, kind: 'virustotal' }] as any }), /kind must be one of/);
  });

  test('rejects a MISP base URL the egress policy refuses', () => {
    expectBadRequest(() => normaliseEnrichmentSettings({ sources: [{ ...misp, baseUrl: 'http://misp.example.org' }] as any }), /HTTPS/);
    expectBadRequest(() => normaliseEnrichmentSettings({ sources: [{ ...misp, baseUrl: 'https://10.0.0.5' }] as any }), /IP literal/);
    expectBadRequest(() => normaliseEnrichmentSettings({ sources: [{ ...misp, baseUrl: 'https://misp.local' }] as any }), /local/);
    expectBadRequest(() => normaliseEnrichmentSettings({ sources: [{ ...misp, baseUrl: '' }] as any }), /base URL/);
    process.env[EGRESS_ALLOWED_HOSTS_ENV_VAR] = 'allowed.example.com';
    expectBadRequest(() => normaliseEnrichmentSettings({ sources: [misp] as any }), /not allowed/);
  });

  test('generic_http: template placeholders only in path/query, pointers must be RFC 6901, verdict or score required', () => {
    const generic = {
      id: 'g',
      name: 'Generic',
      kind: 'generic_http',
      enabled: true,
      urlTemplate: 'https://intel.example.com/lookup?q={value}&t={type}',
      verdictPath: '/verdict',
      headers: { Authorization: 'Bearer {apiKey}' },
      verdictMap: { bad: 'malicious' },
    };
    const out = normaliseEnrichmentSettings({ sources: [generic] as any });
    expect(out.sources[0]).toMatchObject({ urlTemplate: generic.urlTemplate, verdictPath: '/verdict', headers: generic.headers, verdictMap: { bad: 'malicious' } });

    expectBadRequest(() => normaliseEnrichmentSettings({ sources: [{ ...generic, urlTemplate: 'https://{value}.example.com/x' }] as any }), /not the host/);
    expectBadRequest(() => normaliseEnrichmentSettings({ sources: [{ ...generic, urlTemplate: 'https://intel.example.com/x' }] as any }), /\{value\}/);
    expectBadRequest(() => normaliseEnrichmentSettings({ sources: [{ ...generic, urlTemplate: 'https://intel.example.com/{other}/{value}' }] as any }), /only use/);
    expectBadRequest(() => normaliseEnrichmentSettings({ sources: [{ ...generic, urlTemplate: 'http://intel.example.com/{value}' }] as any }), /HTTPS/);
    // allowInsecure only helps for an allowlisted host; the flag is stored only when set.
    expectBadRequest(() => normaliseEnrichmentSettings({ sources: [{ ...generic, urlTemplate: 'http://intel.example.com/{value}', allowInsecure: true }] as any }), /HTTPS/);
    expect(out.sources[0].allowInsecure).toBeUndefined();
    process.env.WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS = 'intel.example.com';
    try {
      const insecure = normaliseEnrichmentSettings({ sources: [{ ...generic, urlTemplate: 'http://intel.example.com/{value}', allowInsecure: true }] as any });
      expect(insecure.sources[0]).toMatchObject({ urlTemplate: 'http://intel.example.com/{value}', allowInsecure: true });
      expectBadRequest(() => normaliseEnrichmentSettings({ sources: [{ ...generic, urlTemplate: 'http://intel.example.com/{value}' }] as any }), /HTTPS/);
    } finally {
      delete process.env.WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS;
    }
    expectBadRequest(() => normaliseEnrichmentSettings({ sources: [{ ...generic, verdictPath: 'verdict' }] as any }), /RFC 6901/);
    expectBadRequest(() => normaliseEnrichmentSettings({ sources: [{ ...generic, verdictPath: undefined }] as any }), /verdictPath or scorePath/);
    expectBadRequest(() => normaliseEnrichmentSettings({ sources: [{ ...generic, verdictMap: { bad: 'evil' } }] as any }), /verdictMap/);
    expectBadRequest(() => normaliseEnrichmentSettings({ sources: [{ ...generic, headers: { 'X-Bad': 'a\r\nb' } }] as any }), /single-line/);
    expect(() => assertUrlTemplate('https://intel.example.com/{value}', 'x')).not.toThrow();
  });

  test('reserves the wazuh_cti_local kind for the built-in id', () => {
    expectBadRequest(() => normaliseEnrichmentSettings({ sources: [{ id: 'mine', name: 'x', kind: 'wazuh_cti_local', enabled: true }] as any }), /reserved/);
    const out = normaliseEnrichmentSettings({ sources: [{ id: WAZUH_CTI_LOCAL_SOURCE_ID, name: 'CTI', kind: 'wazuh_cti_local', enabled: false }] as any });
    expect(out.sources[0].supports).toEqual(['ip', 'domain', 'url', 'hash']);
  });
});

describe('withBuiltInSources', () => {
  test('synthesises the local CTI source on 5.0 builds, enabled by default', () => {
    const list = withBuiltInSources([{ id: 'a', kind: 'misp' }], 5);
    expect(list.map((s) => s.id)).toEqual([WAZUH_CTI_LOCAL_SOURCE_ID, 'a']);
    expect((list[0] as any).builtIn).toBe(true);
    expect((list[0] as any).enabled).toBe(true);
    expect(builtInCtiLocalSource().supports).toEqual(['ip', 'domain', 'url', 'hash']);
  });

  test('keeps a stored built-in entry (toggled by an administrator) and marks it builtIn', () => {
    const list = withBuiltInSources([{ id: WAZUH_CTI_LOCAL_SOURCE_ID, kind: 'wazuh_cti_local', enabled: false }], 5);
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({ enabled: false, builtIn: true });
  });

  test('on a 4.x build the local CTI source is neither synthesised nor kept', () => {
    expect(withBuiltInSources([{ id: 'a', kind: 'misp' }], 4).map((s) => s.id)).toEqual(['a']);
    expect(withBuiltInSources([{ id: WAZUH_CTI_LOCAL_SOURCE_ID, kind: 'wazuh_cti_local', enabled: true }, { id: 'a', kind: 'misp' }], 4).map((s) => s.id)).toEqual(['a']);
  });

  test('defaults to the build target', () => {
    const list = withBuiltInSources([{ id: 'a', kind: 'misp' }]);
    expect(list.some((s) => s.kind === 'wazuh_cti_local')).toBe(Number(TARGET_WAZUH_MAJOR) === 5);
  });
});

describe('enrichmentSettings document', () => {
  beforeEach(() => {
    process.env[ENCRYPTION_KEY_ENV_VAR] = KEY;
    delete process.env[EGRESS_ALLOWED_HOSTS_ENV_VAR];
  });
  afterAll(() => {
    delete process.env[ENCRYPTION_KEY_ENV_VAR];
  });

  test('writes to the meta index with the api key encrypted and masks it on read', async () => {
    const client = clientWith(null);
    const masked = await enrichmentSettings.write(client, { sources: [{ ...misp, apiKey: 'secret-key' }] }, { actor: 'admin' });
    expect(masked.sources[0]).toMatchObject({ id: 'misp-1', apiKeyConfigured: true });
    expect((masked.sources[0] as any).apiKey).toBeUndefined();
    const call = client.index.mock.calls[0]![0];
    expect(call.index).toBe(META_INDEX);
    expect(call.id).toBe(ENRICHMENT_SETTINGS_DOC_ID);
    expect(call.body.sources[0].apiKey).not.toBe('secret-key');
    expect(call.body.sources[0].apiKey.length).toBeGreaterThan(10);
    expect(call.body.updated_by).toBe('admin');
  });

  test('a mixed-case id with an api key is rejected rather than stored with the key silently dropped', async () => {
    const client = clientWith(null);
    await expect(
      enrichmentSettings.write(client, { sources: [{ ...misp, id: 'MyMisp', apiKey: 'secret-key' }] }, { actor: 'admin' })
    ).rejects.toMatchObject({ statusCode: 400, message: expect.stringMatching(/id must be/) });
    expect(client.index).not.toHaveBeenCalled();
    // The same source with a valid id keeps its key through validation.
    const masked = await enrichmentSettings.write(client, { sources: [{ ...misp, id: 'mymisp', apiKey: 'secret-key' }] }, { actor: 'admin' });
    expect(masked.sources[0]).toMatchObject({ id: 'mymisp', apiKeyConfigured: true });
    expect(client.index.mock.calls[0]![0].body.sources[0].apiKey.length).toBeGreaterThan(10);
  });

  test('rejects a bad base URL with a 400 before anything is written', async () => {
    const client = clientWith(null);
    await expect(
      enrichmentSettings.write(client, { sources: [{ ...misp, baseUrl: 'https://127.0.0.1' }] }, { actor: 'admin' })
    ).rejects.toMatchObject({ statusCode: 400 });
    expect(client.index).not.toHaveBeenCalled();
  });

  test('read returns the stored list masked; readWithSecrets decrypts', async () => {
    const client = clientWith(null);
    await enrichmentSettings.write(client, { sources: [{ ...misp, apiKey: 'secret-key' }] }, { actor: 'admin' });
    const stored = client.index.mock.calls[0]![0].body;
    const reader = clientWith(stored);
    const masked = await enrichmentSettings.read(reader);
    expect(masked.sources[0]).toMatchObject({ apiKeyConfigured: true });
    const full = await enrichmentSettings.readWithSecrets(reader);
    expect(full.sources[0].apiKey).toBe('secret-key');
  });
});
