import { resolveCase, resolveCases } from './case_index_resolution';

describe('case physical-index resolution', () => {
  it('resolves ids through the read alias and preserves physical indices', async () => {
    const client = { search: jest.fn(async () => ({ body: { hits: { hits: [
      { _id: 'c1', _index: 'wazuh-alert-manager-v2-cases-000001', _source: { status: 'open' } },
      { _id: 'c2', _index: 'wazuh-alert-manager-v2-cases-000002', _source: { status: 'closed' } },
    ] } } })) };
    const result = await resolveCases(client, ['c1', 'c2']);
    expect(result.get('c1')?.index).toBe('wazuh-alert-manager-v2-cases-000001');
    expect(result.get('c2')?.source.status).toBe('closed');
    expect(client.search).toHaveBeenCalledWith(expect.objectContaining({
      index: 'wazuh-alert-manager-v2-cases-read',
    }));
  });

  it('returns a 404-style error for a missing case', async () => {
    const client = { search: jest.fn(async () => ({ body: { hits: { hits: [] } } })) };
    await expect(resolveCase(client, 'missing')).rejects.toMatchObject({ statusCode: 404 });
  });

  it('refuses a case hit from an unmanaged index', async () => {
    const client = { search: jest.fn(async () => ({ body: { hits: { hits: [
      { _id: 'c1', _index: 'wazuh-alerts-4.x-2026.08.29', _source: {} },
    ] } } })) };
    await expect(resolveCase(client, 'c1')).rejects.toThrow(/unmanaged index/);
  });
});
