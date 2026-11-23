import { META_INDEX } from '../../common';
import { decryptSecret, encryptSecret } from './crypto';
import { ENCRYPTION_KEY_ENV_VAR } from './secrets_config';
import {
  SECRET_MASK,
  deepMerge,
  defineSettingsDoc,
  isSecretMask,
  parseSecretPath,
} from './plugin_settings';

const KEY = 'unit-test-encryption-key-with-32-plus-characters';

interface Source {
  id: string;
  name: string;
  apiKey?: string;
  enabled: boolean;
}

interface EnrichmentSettings {
  enabled: boolean;
  apiKey?: string;
  webhook: { url: string; secret?: string };
  sources: Source[];
}

const defaults: EnrichmentSettings = {
  enabled: false,
  apiKey: '',
  webhook: { url: '', secret: '' },
  sources: [],
};

function docOf(source: any | null) {
  return {
    get: jest.fn(async () => {
      if (source === null) {
        const error: any = new Error('not found');
        error.meta = { statusCode: 404 };
        throw error;
      }
      return { body: { _source: source } };
    }),
    index: jest.fn(async (_request: any) => ({ body: { result: 'updated' } })),
  };
}

function written(client: { index: jest.Mock }): any {
  return client.index.mock.calls[0]![0];
}

function stored(doc: EnrichmentSettings | Record<string, any>) {
  return docOf(doc);
}

const settings = defineSettingsDoc<EnrichmentSettings>({
  docId: 'enrichment_settings',
  defaults,
  secretFields: ['apiKey', 'webhook.secret', 'sources[].apiKey'],
});

describe('parseSecretPath', () => {
  test('parses dotted paths with [] array steps', () => {
    expect(parseSecretPath('sources[].apiKey')).toEqual([
      { key: 'sources', array: true },
      { key: 'apiKey', array: false },
    ]);
    expect(parseSecretPath('webhook.secret')).toEqual([
      { key: 'webhook', array: false },
      { key: 'secret', array: false },
    ]);
  });

  test('rejects malformed paths', () => {
    expect(() => parseSecretPath('sources[]')).toThrow(/must end with a field name/);
    expect(() => parseSecretPath('a..b')).toThrow(/Invalid secret path/);
    expect(() => parseSecretPath('a[0].b')).toThrow(/Invalid secret path/);
  });
});

describe('deepMerge / isSecretMask', () => {
  test('merges plain objects recursively and replaces arrays', () => {
    expect(deepMerge({ a: { x: 1, y: 2 }, list: [1, 2] }, { a: { y: 3 }, list: [9] })).toEqual({
      a: { x: 1, y: 3 },
      list: [9],
    });
    expect(deepMerge({ a: 1 }, { a: undefined })).toEqual({ a: 1 });
  });

  test('recognises only the exact mask object', () => {
    expect(isSecretMask(SECRET_MASK)).toBe(true);
    expect(isSecretMask({ hasSecret: true })).toBe(true);
    expect(isSecretMask({ hasSecret: true, extra: 1 })).toBe(false);
    expect(isSecretMask({ hasSecret: false })).toBe(false);
    expect(isSecretMask('x')).toBe(false);
  });
});

describe('defineSettingsDoc', () => {
  const originalKey = process.env[ENCRYPTION_KEY_ENV_VAR];

  beforeEach(() => {
    process.env[ENCRYPTION_KEY_ENV_VAR] = KEY;
  });

  afterAll(() => {
    if (originalKey === undefined) delete process.env[ENCRYPTION_KEY_ENV_VAR];
    else process.env[ENCRYPTION_KEY_ENV_VAR] = originalKey;
  });

  describe('read', () => {
    test('returns defaults with Configured flags when nothing is stored', async () => {
      const client = docOf(null);
      const result = await settings.read(client as any);
      expect(client.get).toHaveBeenCalledWith({ index: META_INDEX, id: 'enrichment_settings' });
      expect(result).toEqual({
        enabled: false,
        apiKeyConfigured: false,
        webhook: { url: '', secretConfigured: false },
        sources: [],
      });
      expect('apiKey' in result).toBe(false);
    });

    test('masks every secret site, including nested arrays, and keeps the envelope', async () => {
      const client = stored({
        enabled: true,
        apiKey: encryptSecret('top', KEY),
        webhook: { url: 'https://hook.example', secret: '' },
        sources: [
          { id: 'a', name: 'AbuseIPDB', apiKey: encryptSecret('k-a', KEY), enabled: true },
          { id: 'b', name: 'MISP', apiKey: '', enabled: false },
          { id: 'c', name: 'No key field', enabled: true },
        ],
        updated_at: '2026-11-20T10:00:00.000Z',
        updated_by: 'admin',
        source: 'workbench',
      });
      const result = await settings.read(client as any);
      expect(result).toEqual({
        enabled: true,
        apiKeyConfigured: true,
        webhook: { url: 'https://hook.example', secretConfigured: false },
        sources: [
          { id: 'a', name: 'AbuseIPDB', apiKeyConfigured: true, enabled: true },
          { id: 'b', name: 'MISP', apiKeyConfigured: false, enabled: false },
          { id: 'c', name: 'No key field', apiKeyConfigured: false, enabled: true },
        ],
        updated_at: '2026-11-20T10:00:00.000Z',
        updated_by: 'admin',
        source: 'workbench',
      });
      expect(JSON.stringify(result)).not.toContain(encryptSecret('top', KEY).slice(0, 8));
    });

    test('rethrows non-404 read failures', async () => {
      const client = {
        get: jest.fn(async () => {
          const error: any = new Error('forbidden');
          error.meta = { statusCode: 403 };
          throw error;
        }),
      };
      await expect(settings.read(client as any)).rejects.toThrow('forbidden');
    });
  });

  describe('readWithSecrets', () => {
    test('decrypts every stored secret and normalises absent ones to empty strings', async () => {
      const client = stored({
        enabled: true,
        apiKey: encryptSecret('top', KEY),
        webhook: { url: 'u', secret: encryptSecret('hmac', KEY) },
        sources: [{ id: 'a', name: 'A', apiKey: encryptSecret('k-a', KEY), enabled: true }, { id: 'b', name: 'B', enabled: true }],
      });
      const result = await settings.readWithSecrets(client as any);
      expect(result.apiKey).toBe('top');
      expect(result.webhook.secret).toBe('hmac');
      expect(result.sources[0].apiKey).toBe('k-a');
      expect(result.sources[1].apiKey).toBe('');
    });

    test('fails with a 500 typed error when the encryption key is missing or changed', async () => {
      const client = stored({ ...defaults, apiKey: encryptSecret('top', KEY) });
      delete process.env[ENCRYPTION_KEY_ENV_VAR];
      await expect(settings.readWithSecrets(client as any)).rejects.toMatchObject({
        statusCode: 500,
        message: expect.stringContaining(ENCRYPTION_KEY_ENV_VAR),
      });

      process.env[ENCRYPTION_KEY_ENV_VAR] = 'a-different-key-that-is-also-at-least-32-chars';
      await expect(settings.readWithSecrets(client as any)).rejects.toMatchObject({
        statusCode: 500,
        message: expect.stringContaining('re-enter'),
      });
    });

    test('does not need the key when no secret is stored', async () => {
      delete process.env[ENCRYPTION_KEY_ENV_VAR];
      const client = stored({ ...defaults, enabled: true });
      await expect(settings.readWithSecrets(client as any)).resolves.toMatchObject({ enabled: true, apiKey: '' });
    });
  });

  describe('write', () => {
    test('merges onto the stored document, encrypts secrets and writes with refresh wait_for', async () => {
      const client = stored({ ...defaults, enabled: false, webhook: { url: 'old', secret: '' } });
      const result = await settings.write(
        client as any,
        { enabled: true, apiKey: 'plain-key', sources: [{ id: 'a', name: 'A', apiKey: 'k-a', enabled: true }] },
        { actor: 'admin' }
      );

      expect(client.index).toHaveBeenCalledTimes(1);
      const call = written(client);
      expect(call).toMatchObject({ index: META_INDEX, id: 'enrichment_settings', refresh: 'wait_for' });
      expect(call.body.enabled).toBe(true);
      expect(call.body.webhook).toEqual({ url: 'old', secret: '' });
      expect(call.body.apiKey).not.toBe('plain-key');
      expect(decryptSecret(call.body.apiKey, KEY)).toBe('plain-key');
      expect(decryptSecret(call.body.sources[0].apiKey, KEY)).toBe('k-a');
      expect(call.body.updated_by).toBe('admin');
      expect(call.body.source).toBe('workbench');
      expect(typeof call.body.updated_at).toBe('string');

      expect(result).toMatchObject({
        enabled: true,
        apiKeyConfigured: true,
        webhook: { url: 'old', secretConfigured: false },
        sources: [{ id: 'a', name: 'A', apiKeyConfigured: true, enabled: true }],
        updated_by: 'admin',
      });
      expect(JSON.stringify(result)).not.toContain(call.body.apiKey);
    });

    test('preserves existing secrets when the patch omits them, sends "" or sends the mask', async () => {
      const topCipher = encryptSecret('top', KEY);
      const hookCipher = encryptSecret('hmac', KEY);
      const aCipher = encryptSecret('k-a', KEY);
      const bCipher = encryptSecret('k-b', KEY);
      const client = stored({
        enabled: true,
        apiKey: topCipher,
        webhook: { url: 'u', secret: hookCipher },
        sources: [
          { id: 'a', name: 'A', apiKey: aCipher, enabled: true },
          { id: 'b', name: 'B', apiKey: bCipher, enabled: true },
        ],
      });

      await settings.write(
        client as any,
        {
          apiKey: '',
          webhook: { url: 'u2', secret: SECRET_MASK },
          sources: [
            // reordered and renamed; matched by id, secret omitted
            { id: 'b', name: 'B renamed', enabled: false },
            // mask sent back from the UI
            { id: 'a', name: 'A', apiKey: SECRET_MASK, enabled: true },
            // brand new source with its own secret
            { id: 'c', name: 'C', apiKey: 'k-c', enabled: true },
          ],
        },
        { actor: 'admin' }
      );

      const body = written(client).body;
      expect(body.apiKey).toBe(topCipher);
      expect(body.webhook).toEqual({ url: 'u2', secret: hookCipher });
      expect(body.sources.map((s: any) => s.id)).toEqual(['b', 'a', 'c']);
      expect(body.sources[0]).toEqual({ id: 'b', name: 'B renamed', apiKey: bCipher, enabled: false });
      expect(body.sources[1].apiKey).toBe(aCipher);
      expect(decryptSecret(body.sources[2].apiKey, KEY)).toBe('k-c');
    });

    test('drops the Configured flags a client echoes back from read()', async () => {
      const topCipher = encryptSecret('top', KEY);
      const aCipher = encryptSecret('k-a', KEY);
      const client = stored({
        enabled: false,
        apiKey: topCipher,
        webhook: { url: 'u', secret: '' },
        sources: [{ id: 'a', name: 'A', apiKey: aCipher, enabled: true }],
        // a flag persisted by an older build must be scrubbed too
        apiKeyConfigured: true,
      });
      const result = await settings.write(
        client as any,
        {
          enabled: true,
          apiKeyConfigured: true,
          webhook: { url: 'u', secretConfigured: false },
          sources: [{ id: 'a', name: 'A', apiKeyConfigured: true, enabled: true }],
        },
        { actor: 'admin' }
      );
      const body = written(client).body;
      expect(body).not.toHaveProperty('apiKeyConfigured');
      expect(body.webhook).toEqual({ url: 'u', secret: '' });
      expect(body.sources[0]).toEqual({ id: 'a', name: 'A', apiKey: aCipher, enabled: true });
      expect(body.apiKey).toBe(topCipher);
      expect(result).toMatchObject({ enabled: true, apiKeyConfigured: true });

      const withSecrets = await settings.readWithSecrets(docOf(body) as any);
      expect(withSecrets).not.toHaveProperty('apiKeyConfigured');
      expect(withSecrets.sources[0]).toEqual({ id: 'a', name: 'A', apiKey: 'k-a', enabled: true });
    });

    test('matches array elements by position when they carry no id', async () => {
      const first = encryptSecret('one', KEY);
      const client = stored({
        ...defaults,
        sources: [
          { name: 'first', apiKey: first, enabled: true },
          { name: 'second', apiKey: encryptSecret('two', KEY), enabled: true },
        ],
      });
      await settings.write(client as any, { sources: [{ name: 'first again', enabled: false }] } as any, { actor: 'x' });
      const body = written(client).body;
      expect(body.sources).toEqual([{ name: 'first again', apiKey: first, enabled: false }]);
    });

    test('null clears a secret; a removed array element drops its secret', async () => {
      const client = stored({
        ...defaults,
        apiKey: encryptSecret('top', KEY),
        sources: [{ id: 'a', name: 'A', apiKey: encryptSecret('k-a', KEY), enabled: true }],
      });
      const result = await settings.write(client as any, { apiKey: null, sources: [] } as any, { actor: 'admin' });
      const body = written(client).body;
      expect(body.apiKey).toBe('');
      expect(body.sources).toEqual([]);
      expect(result).toMatchObject({ apiKeyConfigured: false, sources: [] });
    });

    test('rejects a new secret with a 400 typed error when no encryption key is configured, without writing', async () => {
      delete process.env[ENCRYPTION_KEY_ENV_VAR];
      const client = stored({ ...defaults });
      await expect(settings.write(client as any, { apiKey: 'plain' }, { actor: 'admin' })).rejects.toMatchObject({
        statusCode: 400,
        message: expect.stringContaining(ENCRYPTION_KEY_ENV_VAR),
      });
      expect(client.index).not.toHaveBeenCalled();
    });

    test('allows non-secret edits without an encryption key when stored secrets are untouched', async () => {
      delete process.env[ENCRYPTION_KEY_ENV_VAR];
      const cipher = encryptSecret('top', KEY);
      const client = stored({ ...defaults, apiKey: cipher });
      await settings.write(client as any, { enabled: true }, { actor: 'admin' });
      expect(written(client).body).toMatchObject({ enabled: true, apiKey: cipher });
    });

    test('rejects non-string secret values', async () => {
      const client = stored({ ...defaults });
      await expect(settings.write(client as any, { apiKey: 42 } as any, { actor: 'admin' })).rejects.toMatchObject({
        statusCode: 400,
      });
      expect(client.index).not.toHaveBeenCalled();
    });

    test('runs validate on the secret-free merged document and re-attaches secrets afterwards', async () => {
      const seen: any[] = [];
      const validated = defineSettingsDoc<EnrichmentSettings>({
        docId: 'enrichment_settings',
        defaults,
        secretFields: ['apiKey', 'sources[].apiKey'],
        validate: (value) => {
          seen.push(JSON.parse(JSON.stringify(value)));
          if (!value.sources.every((s) => s.name)) {
            const error: any = new Error('Every source needs a name.');
            error.statusCode = 400;
            throw error;
          }
          // Returns a fresh object with normalised names.
          return { ...value, sources: value.sources.map((s) => ({ ...s, name: s.name.trim() })) };
        },
      });
      const cipher = encryptSecret('k-a', KEY);
      const client = stored({ ...defaults, sources: [{ id: 'a', name: 'A', apiKey: cipher, enabled: true }] });

      await validated.write(client as any, { apiKey: 'top', sources: [{ id: 'a', name: '  A  ', enabled: true }] }, { actor: 'admin' });
      expect(seen[0]).toEqual({ enabled: false, webhook: { url: '', secret: '' }, sources: [{ id: 'a', name: '  A  ', enabled: true }] });
      const body = written(client).body;
      expect(body.sources[0]).toEqual({ id: 'a', name: 'A', apiKey: cipher, enabled: true });
      expect(decryptSecret(body.apiKey, KEY)).toBe('top');

      await expect(
        validated.write(client as any, { sources: [{ id: 'z', name: '', enabled: true }] }, { actor: 'admin' })
      ).rejects.toMatchObject({ statusCode: 400 });
      expect(client.index).toHaveBeenCalledTimes(1);
    });

    test('refuses to write without an actor', async () => {
      const client = stored({ ...defaults });
      await expect(settings.write(client as any, { enabled: true }, { actor: '' })).rejects.toThrow(/actor/);
      expect(client.index).not.toHaveBeenCalled();
    });

    test('only ever targets the managed meta index', async () => {
      const client = stored({ ...defaults });
      await settings.write(client as any, { enabled: true }, { actor: 'admin' });
      expect(written(client).index).toMatch(/^wazuh-alert-manager-v2-/);
    });
  });
});
