import { AgentGroupCache, NO_AGENT_GROUPS } from './agent_groups';

function contractWith(request: jest.Mock) {
  return {
    manageHosts: { get: jest.fn(async () => [{ id: 'default' }]) },
    api: { client: { asInternalUser: { request } } },
  };
}

const agentsResponse = (items: any[]) => ({ status: 200, data: { data: { affected_items: items } } });

describe('AgentGroupCache', () => {
  test('fetches only unseen ids, caches results (including empty) for the TTL', async () => {
    let now = 1_000_000;
    const request = jest.fn(async () => agentsResponse([{ id: '001', group: ['default', 'dmz'] }]));
    const cache = new AgentGroupCache({ wazuhCore: contractWith(request) }, { ttlMs: 600_000, now: () => now });

    const first = await cache.lookup(['001', '000', '001']);
    expect(first.get('001')).toEqual(['default', 'dmz']);
    expect(first.get('000')).toEqual([]); // agent 000 has no group and is cached as such
    expect(request).toHaveBeenCalledTimes(1);
    expect(request).toHaveBeenCalledWith(
      'GET',
      '/agents',
      { params: { agents_list: '001,000', select: 'id,group', limit: 2 } },
      { apiHostID: 'default' }
    );

    now += 1000;
    const second = await cache.lookup(['001', '000', '002']);
    expect(second.get('001')).toEqual(['default', 'dmz']);
    expect(request).toHaveBeenCalledTimes(2);
    expect((request.mock.calls[1] as any[])[2]).toEqual({ params: { agents_list: '002', select: 'id,group', limit: 1 } });

    now += 600_001;
    await cache.lookup(['001']);
    expect(request).toHaveBeenCalledTimes(3);
  });

  test('a failed call answers [] for the batch and caches nothing', async () => {
    const request = jest.fn().mockRejectedValueOnce(new Error('boom')).mockResolvedValueOnce(agentsResponse([{ id: '001', group: ['g'] }]));
    const logger = { debug: jest.fn() };
    const cache = new AgentGroupCache({ wazuhCore: contractWith(request) }, { logger });
    expect((await cache.lookup(['001'])).get('001')).toEqual([]);
    expect(cache.size).toBe(0);
    expect(logger.debug).toHaveBeenCalledWith(expect.stringContaining('agent group lookup failed'));
    expect((await cache.lookup(['001'])).get('001')).toEqual(['g']);
  });

  test('without wazuhCore every agent resolves to [] and no request is made', async () => {
    const logger = { debug: jest.fn() };
    const cache = new AgentGroupCache(undefined, { logger });
    expect(await cache.lookup(['001', ''])).toEqual(new Map([['001', []]]));
    expect(logger.debug).toHaveBeenCalledWith(expect.stringContaining('wazuhCore plugin is not available'));
    expect(await NO_AGENT_GROUPS.lookup(['007'])).toEqual(new Map([['007', []]]));
  });

  test('splits large batches into requests of at most 100 ids', async () => {
    const request = jest.fn(async () => agentsResponse([]));
    const cache = new AgentGroupCache({ wazuhCore: contractWith(request) });
    await cache.lookup(Array.from({ length: 150 }, (_, i) => String(i)));
    expect(request).toHaveBeenCalledTimes(2);
  });

  test('stops issuing chunks once the per-lookup deadline is spent and leaves the rest uncached', async () => {
    let now = 0;
    const request = jest.fn(async () => {
      now += 20_000; // each API call takes 20 s
      return agentsResponse([]);
    });
    const logger = { debug: jest.fn() };
    const cache = new AgentGroupCache({ wazuhCore: contractWith(request) }, { now: () => now, lookupDeadlineMs: 30_000, logger });
    const result = await cache.lookup(Array.from({ length: 250 }, (_, i) => String(i)));
    expect(request).toHaveBeenCalledTimes(2); // third chunk would start at 40 s > 30 s budget
    expect(result.size).toBe(250);
    expect(cache.size).toBe(200);
    expect(logger.debug).toHaveBeenCalledWith(expect.stringContaining('deadline reached, 50 agent(s)'));
  });
});
