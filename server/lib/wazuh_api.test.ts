import { getWazuhApiClient, resolveWazuhCoreContract } from './wazuh_api';

function contractWith(overrides: any = {}) {
  return {
    manageHosts: { get: jest.fn(async () => [{ id: 'default', url: 'https://wazuh', port: 55000 }, { id: 'second' }]) },
    api: { client: { asInternalUser: { request: jest.fn(async () => ({ status: 200, data: { data: { affected_items: [] } } })) } } },
    ...overrides,
  };
}

describe('resolveWazuhCoreContract', () => {
  test('finds the contract on plugin deps, route context or the contract itself', () => {
    const contract = contractWith();
    expect(resolveWazuhCoreContract({ wazuhCore: contract })).toBe(contract);
    expect(resolveWazuhCoreContract({ wazuh_core: contract })).toBe(contract);
    expect(resolveWazuhCoreContract(contract)).toBe(contract);
  });

  test('returns null when nothing exposes an api', () => {
    expect(resolveWazuhCoreContract(undefined)).toBeNull();
    expect(resolveWazuhCoreContract(null)).toBeNull();
    expect(resolveWazuhCoreContract({})).toBeNull();
    expect(resolveWazuhCoreContract({ wazuhCore: undefined })).toBeNull();
    expect(resolveWazuhCoreContract({ core: {}, wazuh_core: { manageHosts: {} } } as any)).toBeNull();
  });
});

describe('getWazuhApiClient when wazuhCore is present', () => {
  test('resolves the first configured host and requests as the internal user', async () => {
    const contract = contractWith();
    const client = await getWazuhApiClient({ wazuhCore: contract });
    expect(client.available).toBe(true);
    if (!client.available) throw new Error('unreachable');
    expect(client.apiHostID).toBe('default');
    expect(contract.manageHosts.get).toHaveBeenCalledWith(undefined, { excludePassword: true });

    const result = await client.request('GET', '/agents', { select: 'id,name,group', limit: 500 });
    expect(result).toEqual({ ok: true, status: 200, data: { data: { affected_items: [] } } });
    expect(contract.api.client.asInternalUser.request).toHaveBeenCalledWith(
      'GET',
      '/agents',
      { params: { select: 'id,name,group', limit: 500 } },
      { apiHostID: 'default' }
    );
  });

  test('an explicit apiHostID skips host discovery', async () => {
    const contract = contractWith({ manageHosts: undefined });
    const client = await getWazuhApiClient({ wazuh_core: contract }, { apiHostID: 'manager-b' });
    expect(client).toMatchObject({ available: true, apiHostID: 'manager-b' });
    await client.request('GET', '/groups');
    expect(contract.api.client.asInternalUser.request).toHaveBeenCalledWith(
      'GET',
      '/groups',
      { params: {} },
      { apiHostID: 'manager-b' }
    );
  });

  test('a request that throws is reported, with the upstream HTTP status when present', async () => {
    const contract = contractWith();
    contract.api.client.asInternalUser.request.mockRejectedValueOnce({ message: 'Forbidden', response: { status: 403 } });
    const client = await getWazuhApiClient(contract);
    const result = await client.request('GET', '/mitre/techniques');
    expect(result).toEqual({ ok: false, status: 403, reason: 'Wazuh API GET /mitre/techniques failed (HTTP 403): Forbidden' });

    contract.api.client.asInternalUser.request.mockRejectedValueOnce(new Error('ECONNREFUSED'));
    expect(await client.request('GET', '/agents')).toEqual({
      ok: false,
      status: undefined,
      reason: 'Wazuh API GET /agents failed: ECONNREFUSED',
    });
  });

  test('a non-2xx response that does not throw is still a failure', async () => {
    const contract = contractWith();
    contract.api.client.asInternalUser.request.mockResolvedValueOnce({ status: 500, data: {} });
    const client = await getWazuhApiClient(contract);
    expect(await client.request('GET', '/agents')).toEqual({
      ok: false,
      status: 500,
      reason: 'Wazuh API GET /agents returned HTTP 500',
    });
  });

  test('rejects a relative path before touching the network', async () => {
    const contract = contractWith();
    const client = await getWazuhApiClient(contract);
    const result = await client.request('GET', 'agents');
    expect(result.ok).toBe(false);
    expect(contract.api.client.asInternalUser.request).not.toHaveBeenCalled();
  });
});

describe('getWazuhApiClient when wazuhCore is absent or broken', () => {
  test('absent plugin', async () => {
    const client = await getWazuhApiClient({ wazuhCore: undefined });
    expect(client).toMatchObject({ available: false, reason: 'wazuhCore plugin is not available' });
    expect(await client.request('GET', '/agents')).toEqual({ ok: false, reason: 'wazuhCore plugin is not available' });
  });

  test('plugin without an internal-user client', async () => {
    const client = await getWazuhApiClient({ wazuhCore: { api: { client: {} } } });
    expect(client).toMatchObject({ available: false, reason: 'wazuhCore does not expose an internal-user API client' });
  });

  test('no configured hosts', async () => {
    const contract = contractWith({ manageHosts: { get: jest.fn(async () => []) } });
    const client = await getWazuhApiClient(contract);
    expect(client).toMatchObject({ available: false, reason: 'Wazuh API host could not be resolved: no Wazuh API host is configured' });
  });

  test('manageHosts missing and no explicit host', async () => {
    const client = await getWazuhApiClient(contractWith({ manageHosts: undefined }));
    expect(client.available).toBe(false);
    if (client.available) throw new Error('unreachable');
    expect(client.reason).toMatch(/pass an explicit apiHostID/);
  });

  test('host discovery that throws is mapped to unavailable', async () => {
    const contract = contractWith({ manageHosts: { get: jest.fn(async () => { throw new Error('config unreadable'); }) } });
    const client = await getWazuhApiClient(contract);
    expect(client).toMatchObject({ available: false, reason: 'Wazuh API host could not be resolved: config unreadable' });
    expect(await client.request('GET', '/agents')).toEqual({
      ok: false,
      reason: 'Wazuh API host could not be resolved: config unreadable',
    });
  });
});
