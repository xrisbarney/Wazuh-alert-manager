import { ASSET_SETTINGS_DOC_ID, META_INDEX } from '../../../common';
import { assetSettings, loadAssetMatcher, normaliseAssetSettings } from './settings';

const entry = (id: string, kind: any, value: string, criticality: any = 'high', tags: any = []) => ({
  id,
  match: { kind, value },
  criticality,
  tags,
});

describe('normaliseAssetSettings', () => {
  test('trims, dedupes tags and keeps list order', () => {
    const out = normaliseAssetSettings({
      assets: [
        entry('web', 'glob', ' web-* ', 'high', [' pci ', 'pci', 'dmz', '']),
        entry('db-1', 'name', 'db-01', 'critical'),
      ],
    } as any);
    expect(out.assets).toEqual([
      { id: 'web', match: { kind: 'glob', value: 'web-*' }, criticality: 'high', tags: ['pci', 'dmz'] },
      { id: 'db-1', match: { kind: 'name', value: 'db-01' }, criticality: 'critical', tags: [] },
    ]);
  });

  test('rejects bad ids, kinds, criticalities, duplicate ids, label syntax and non-glob globs', () => {
    const expectBad = (assets: any[], message: RegExp) =>
      expect(() => normaliseAssetSettings({ assets } as any)).toThrow(message);
    expectBad([entry('Bad Id', 'name', 'x')], /id must be/);
    expectBad([entry('a', 'regex', 'x')], /match.kind must be one of/);
    expectBad([entry('a', 'name', '')], /match.value is required/);
    expectBad([entry('a', 'name', 'x', 'urgent')], /criticality must be one of/);
    expectBad([entry('a', 'name', 'x'), entry('a', 'name', 'y')], /used more than once/);
    expectBad([entry('a', 'label', 'prod')], /key=value/);
    expectBad([entry('a', 'glob', 'web-01')], /needs at least one/);
    expectBad([entry('a', 'name', 'x', 'high', 'pci')], /tags must be a list/);
    expectBad([entry('a', 'name', 'x', 'high', Array.from({ length: 21 }, (_, i) => `t${i}`))], /at most 20 tags/);
    expectBad(Array.from({ length: 501 }, (_, i) => entry(`a${i}`, 'name', `h${i}`)), /At most 500 assets/);
  });

  test('absent list means no assets', () => {
    expect(normaliseAssetSettings({} as any)).toEqual({ assets: [] });
  });
});

describe('assetSettings document', () => {
  test('writes through the meta index with the envelope and no secrets', async () => {
    const client = {
      get: jest.fn().mockRejectedValue({ meta: { statusCode: 404 } }),
      index: jest.fn().mockResolvedValue({}),
    };
    const out = await assetSettings.write(client, { assets: [entry('web', 'glob', 'web-*')] }, { actor: 'admin' });
    expect(client.index).toHaveBeenCalledWith(
      expect.objectContaining({ index: META_INDEX, id: ASSET_SETTINGS_DOC_ID, refresh: 'wait_for' })
    );
    const body = client.index.mock.calls[0][0].body;
    expect(body.assets).toEqual([{ id: 'web', match: { kind: 'glob', value: 'web-*' }, criticality: 'high', tags: [] }]);
    expect(body.updated_by).toBe('admin');
    expect(out.assets).toHaveLength(1);
    expect(assetSettings.secretFields).toEqual([]);
  });

  test('a validation failure answers 400 and writes nothing', async () => {
    const client = {
      get: jest.fn().mockRejectedValue({ meta: { statusCode: 404 } }),
      index: jest.fn(),
    };
    await expect(assetSettings.write(client, { assets: [entry('a', 'name', 'x', 'urgent')] }, { actor: 'admin' })).rejects.toMatchObject({
      statusCode: 400,
    });
    expect(client.index).not.toHaveBeenCalled();
  });
});

describe('loadAssetMatcher', () => {
  test('an absent document is the empty matcher', async () => {
    const client = { get: jest.fn().mockRejectedValue({ meta: { statusCode: 404 } }) };
    const matcher = await loadAssetMatcher(client);
    expect(matcher.size).toBe(0);
    expect(client.get).toHaveBeenCalledWith({ index: META_INDEX, id: ASSET_SETTINGS_DOC_ID });
  });

  test('a stored document builds a matcher', async () => {
    const client = {
      get: jest.fn().mockResolvedValue({ body: { _source: { assets: [entry('web', 'glob', 'web-*', 'critical', ['pci'])] } } }),
    };
    const matcher = await loadAssetMatcher(client);
    expect(matcher.size).toBe(1);
    expect(matcher.resolve({ agentName: 'web-9' })).toMatchObject({ criticality: 'critical', tags: ['pci'] });
  });

  test('any other read failure degrades to the empty matcher and is logged', async () => {
    const client = { get: jest.fn().mockRejectedValue(new Error('index_not_found_exception')) };
    const logger = { debug: jest.fn(), warn: jest.fn() };
    const matcher = await loadAssetMatcher(client, logger);
    expect(matcher.size).toBe(0);
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('index_not_found_exception'));
  });
});
