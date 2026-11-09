import {
  _resetSourceStateCache,
  eligibleFamilies,
  persistSourceState,
  resolveSource,
  syncStateDocId,
} from './source_runtime';

const build4 = { wazuhMajor: 4, wazuhVersion: '4.14.9', osdVersion: '2.19.6' };
const build5 = { wazuhMajor: 5, wazuhVersion: '5.0.0-rc2', osdVersion: '3.6.0' };

function cfg(sync: any): any {
  return { sync: { enabled: true, intervalSeconds: 60, initialLookbackMinutes: 10, overlapSeconds: 120, batchSize: 100, ...sync } };
}

function clientResolving(body: any, fields: Record<string, any> = { '@timestamp': { date: {} } }) {
  return {
    transport: { request: jest.fn().mockResolvedValue({ body }) },
    fieldCaps: jest.fn().mockResolvedValue({ body: { fields } }),
    index: jest.fn().mockResolvedValue({}),
  } as any;
}

describe('build eligibility', () => {
  test('a build reads exactly one family', () => {
    expect(eligibleFamilies(build4)).toEqual(['wazuh4_alerts']);
    expect(eligibleFamilies(build5)).toEqual(['wazuh5_findings']);
    expect(eligibleFamilies({ wazuhMajor: 6, wazuhVersion: '6.0.0', osdVersion: '4.0.0' })).toEqual([]);
  });

  test('sync cursors are namespaced; 4.x keeps the v2 document id for rollback', () => {
    expect(syncStateDocId('wazuh4_alerts')).toBe('sync_state');
    expect(syncStateDocId('wazuh5_findings')).toBe('sync_state:wazuh5_findings');
  });
});

describe('resolveSource', () => {
  beforeEach(() => _resetSourceStateCache());

  test('auto on a 4.x build selects wazuh-alerts-* and is ready when indices exist', async () => {
    const client = clientResolving({ indices: [{ name: 'wazuh-alerts-4.x-2026.10.31' }], aliases: [], data_streams: [] });
    const r = await resolveSource(client, cfg({ sourceMode: 'auto' }), build4);
    expect(r.status).toBe('ready');
    expect(r.family).toBe('wazuh4_alerts');
    expect(r.pattern).toBe('wazuh-alerts-*');
    expect(client.transport.request).toHaveBeenCalledWith(
      expect.objectContaining({ method: 'GET', path: '/_resolve/index/wazuh-alerts-*' })
    );
  });

  test('auto on a 5.0 build selects findings data streams', async () => {
    const client = clientResolving({ indices: [], aliases: [], data_streams: [{ name: 'wazuh-findings-v5-security' }] });
    const r = await resolveSource(client, cfg({}), build5);
    expect(r.status).toBe('ready');
    expect(r.family).toBe('wazuh5_findings');
    expect(r.pattern).toBe('wazuh-findings-v5-*');
    expect(r.probe).toEqual({ indices: 0, dataStreams: 1, aliases: 0, timestampMapped: true });
  });

  test('a fresh install waits instead of erroring when nothing matches yet', async () => {
    const client = clientResolving({ indices: [], aliases: [], data_streams: [] });
    const r = await resolveSource(client, cfg({}), build4);
    expect(r.status).toBe('waiting');
    expect(r.reason).toMatch(/matches no index or data stream yet/);
    expect(client.fieldCaps).not.toHaveBeenCalled();
  });

  test('a 404 from resolve is the same as nothing matching', async () => {
    const client = clientResolving({});
    client.transport.request.mockRejectedValue({ meta: { statusCode: 404 }, message: 'index_not_found' });
    const r = await resolveSource(client, cfg({}), build5);
    expect(r.status).toBe('waiting');
  });

  test('an explicit mode outside the build eligibility blocks sync', async () => {
    const client = clientResolving({ indices: [{ name: 'x' }], aliases: [], data_streams: [] });
    const r = await resolveSource(client, cfg({ sourceMode: 'wazuh5_findings' }), build4);
    expect(r.status).toBe('blocked');
    expect(r.family).toBeNull();
    expect(r.reason).toMatch(/not eligible for this build/);
    expect(client.transport.request).not.toHaveBeenCalled();
  });

  test('an off-family or hostile pattern override blocks sync and never reaches OpenSearch', async () => {
    const client = clientResolving({ indices: [{ name: 'x' }], aliases: [], data_streams: [] });
    for (const pattern of ['wazuh-findings-v5-*', '*', 'wazuh-alert-status-v2-*', 'wazuh-alerts-*,wazuh-events-v5-*']) {
      const r = await resolveSource(client, cfg({ sourceIndexPattern: pattern }), build4);
      expect(r.status).toBe('blocked');
      expect(r.reason).toMatch(/sourceIndexPattern rejected/);
    }
    const five = await resolveSource(client, cfg({ sourceIndexPattern: 'wazuh-alerts-*' }), build5);
    expect(five.status).toBe('blocked');
    expect(client.transport.request).not.toHaveBeenCalled();
  });

  test('a stale 4.x-style plain index under the 5.0 default pattern is refused', async () => {
    const client = clientResolving({ indices: [{ name: 'wazuh-findings-v5-oops' }], aliases: [], data_streams: [] });
    const r = await resolveSource(client, cfg({}), build5);
    expect(r.status).toBe('blocked');
    expect(r.reason).toMatch(/plain indices, not data streams/);
  });

  test('a source without the timestamp field is not a Wazuh source', async () => {
    const client = clientResolving({ indices: [{ name: 'wazuh-alerts-4.x-x' }], aliases: [], data_streams: [] }, {});
    const r = await resolveSource(client, cfg({}), build4);
    expect(r.status).toBe('blocked');
    expect(r.reason).toMatch(/no mapped @timestamp/);
  });

  test('a transport error blocks rather than guesses', async () => {
    const client = clientResolving({});
    client.transport.request.mockRejectedValue({ meta: { statusCode: 500 }, message: 'boom' });
    const r = await resolveSource(client, cfg({}), build4);
    expect(r.status).toBe('blocked');
    expect(r.reason).toMatch(/resolve failed: boom/);
  });

  test('clients without resolve/field_caps (unit doubles) are treated as resolvable', async () => {
    const r = await resolveSource({} as any, cfg({ sourceIndexPattern: 'wazuh-alerts-*' }), build4);
    expect(r.status).toBe('ready');
  });

  test('persistSourceState writes to the meta index only, and only on change', async () => {
    const client = clientResolving({ indices: [{ name: 'wazuh-alerts-4.x-x' }], aliases: [], data_streams: [] });
    const r = await resolveSource(client, cfg({}), build4);
    await persistSourceState(client, r);
    await persistSourceState(client, { ...r, checkedAt: 'later' });
    expect(client.index).toHaveBeenCalledTimes(1);
    expect(client.index.mock.calls[0][0]).toMatchObject({
      index: 'wazuh-alert-manager-v2-meta',
      id: 'source_state',
      body: { status: 'ready', family: 'wazuh4_alerts', pattern: 'wazuh-alerts-*', sync_state_doc_id: 'sync_state' },
    });
    await persistSourceState(client, { ...r, status: 'blocked', reason: 'changed' });
    expect(client.index).toHaveBeenCalledTimes(2);
  });
});
