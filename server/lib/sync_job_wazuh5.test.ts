// A Wazuh 5.0 build: the sync job must read wazuh-findings-v5-* through the
// 5.x adapter, keep its own cursor document, and never touch the 4.x
// `sync_state` cursor or fall back to wazuh-alerts-*.
jest.mock('../../common', () => ({
  ...jest.requireActual('../../common'),
  TARGET_WAZUH_MAJOR: 5,
  TARGET_WAZUH_VERSION: '5.0.0-rc2',
  TARGET_OSD_VERSION: '3.6.0',
}));
jest.mock('./sync_lock', () => ({
  acquireOrRenewLock: jest.fn().mockResolvedValue(true),
  releaseLock: jest.fn().mockResolvedValue(undefined),
  generateHolderId: jest.fn(() => 'holder'),
}));
jest.mock('./index_resolution', () => ({ resolveAlerts: jest.fn().mockResolvedValue(new Map()) }));
jest.mock('./automation_queue', () => ({
  activateAutomationEvents: jest.fn().mockResolvedValue(1),
  enqueueAutomationEvents: jest.fn().mockResolvedValue({ enqueued: 1, duplicates: 0, failed: 0 }),
  reconcileAutomationAdmissions: jest.fn().mockResolvedValue({ enqueued: 0, duplicates: 0, failed: 0 }),
  recordAutomationEnqueueFailure: jest.fn().mockResolvedValue(undefined),
}));

import { alertUid } from './operational_projection';
import { _resetSourceStateCache } from './source_runtime';
import { runSyncOnce } from './sync_job';

const logger: any = { debug: jest.fn(), info: jest.fn(), warn: jest.fn(), error: jest.fn() };

function config(overrides: any = {}): any {
  return {
    sync: {
      enabled: true,
      intervalSeconds: 60,
      sourceMode: 'auto',
      initialLookbackMinutes: 10,
      overlapSeconds: 120,
      batchSize: 100,
      minRuleLevel: 7,
      ...overrides,
    },
  };
}

const finding = {
  _index: '.ds-wazuh-findings-v5-security-000001',
  _id: 'f-1',
  sort: ['2026-10-31T10:00:00.000Z', 3],
  _source: {
    '@timestamp': '2026-10-31T10:00:00.000Z',
    wazuh: { agent: { id: '001', name: 'h' }, rule: { id: 'r-1', title: 'T', level: 'high', tags: ['high'] } },
    source: { ip: '203.0.113.9' },
    event: { index: '.ds-wazuh-events-v5-security-000001', doc_id: 'e-1' },
  },
};

function client(resolveBody: any, hits: any[]) {
  const meta: Record<string, any> = {
    // A stale 4.x cursor left behind by a 4.x installation whose plugin
    // stores were carried over to the 5.0 indexer.
    sync_state: { completed_at: '2020-01-01T00:00:00.000Z', value: '2020-01-01T00:00:00.000Z', pit_id: 'old-4x-pit' },
  };
  return {
    transport: { request: jest.fn().mockResolvedValue({ body: resolveBody }) },
    fieldCaps: jest.fn().mockResolvedValue({ body: { fields: { '@timestamp': { date: {} } } } }),
    get: jest.fn(async ({ id }: any) => {
      if (meta[id]) return { body: { _source: meta[id] } };
      const err: any = new Error('not found'); err.meta = { statusCode: 404 }; throw err;
    }),
    index: jest.fn(async ({ id, body }: any) => { meta[id] = body; return {}; }),
    createPit: jest.fn().mockResolvedValue({ body: { pit_id: 'pit-5' } }),
    deletePit: jest.fn().mockResolvedValue({}),
    search: jest.fn().mockResolvedValue({ body: { hits: { hits } } }),
    mget: jest.fn(async (args: any) => ({ body: { docs: args.body.ids.map((id: string) => ({ _id: id, found: false })) } })),
    bulk: jest.fn().mockResolvedValue({ body: { errors: false, items: [{ update: { status: 201 } }] } }),
    meta,
  } as any;
}

describe('sync on a Wazuh 5.0 build', () => {
  beforeEach(() => { jest.clearAllMocks(); _resetSourceStateCache(); });

  test('reads findings data streams with a fresh 5.x cursor and never reuses the 4.x cursor', async () => {
    const c = client({ indices: [], aliases: [], data_streams: [{ name: 'wazuh-findings-v5-security' }] }, [finding]);
    await runSyncOnce(c, config(), logger, 'holder', 120);

    expect(c.createPit).toHaveBeenCalledWith({ index: 'wazuh-findings-v5-*', keep_alive: '120s' });
    expect(c.get).toHaveBeenCalledWith(expect.objectContaining({ id: 'sync_state:wazuh5_findings' }));
    expect(c.get).not.toHaveBeenCalledWith(expect.objectContaining({ id: 'sync_state' }));
    // the stale 4.x PIT is never presented to OpenSearch
    const searchBody = c.search.mock.calls[0][0].body;
    expect(searchBody.pit.id).toBe('pit-5');
    // labelled severity: no numeric rule.level filter is injected
    expect(JSON.stringify(searchBody.query)).not.toContain('rule.level');
    expect(searchBody.sort).toEqual([{ '@timestamp': { order: 'asc', numeric_type: 'date' } }, { _doc: { order: 'asc' } }]);

    // projection is the 5.x canonical shape
    const bulkBody = c.bulk.mock.calls[0][0].body;
    expect(bulkBody[0].update).toEqual({ _index: 'wazuh-alert-status-v2-write', _id: alertUid(finding._index, finding._id) });
    const doc = bulkBody[1].script.params.doc;
    expect(doc.source_family).toBe('wazuh5_findings');
    expect(doc.severity_label).toBe('high');
    expect(doc.rule.level).toBeNull();
    expect(doc.data.srcip).toBe('203.0.113.9');
    expect(doc.event_index).toBe('.ds-wazuh-events-v5-security-000001');

    // cursor and source state are written to the meta index only
    expect(c.meta['sync_state:wazuh5_findings']).toMatchObject({ source_family: 'wazuh5_findings' });
    expect(c.meta.sync_state.pit_id).toBe('old-4x-pit');
    expect(c.meta.source_state).toMatchObject({ status: 'ready', family: 'wazuh5_findings', pattern: 'wazuh-findings-v5-*' });
    for (const call of c.index.mock.calls) expect(call[0].index).toBe('wazuh-alert-manager-v2-meta');
  });

  test('stops safely when the 5.0 findings streams are not there yet', async () => {
    const c = client({ indices: [], aliases: [], data_streams: [] }, [finding]);
    await runSyncOnce(c, config(), logger, 'holder', 120);
    expect(c.createPit).not.toHaveBeenCalled();
    expect(c.search).not.toHaveBeenCalled();
    expect(c.bulk).not.toHaveBeenCalled();
    expect(c.meta.source_state).toMatchObject({ status: 'waiting', family: 'wazuh5_findings' });
    expect(logger.info).toHaveBeenCalledWith(expect.stringContaining('source waiting'));
  });

  test('refuses a 4.x pattern override on a 5.0 build instead of reading stale alerts', async () => {
    const c = client({ indices: [{ name: 'wazuh-alerts-4.x-old' }], aliases: [], data_streams: [] }, [finding]);
    await runSyncOnce(c, config({ sourceIndexPattern: 'wazuh-alerts-*' }), logger, 'holder', 120);
    expect(c.transport.request).not.toHaveBeenCalled();
    expect(c.createPit).not.toHaveBeenCalled();
    expect(c.meta.source_state).toMatchObject({ status: 'blocked' });
    expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('sourceIndexPattern rejected for wazuh5_findings'));
  });

  test('an explicit wazuh4_alerts mode is not eligible on a 5.0 build', async () => {
    const c = client({ indices: [{ name: 'wazuh-alerts-4.x-old' }], aliases: [], data_streams: [] }, [finding]);
    await runSyncOnce(c, config({ sourceMode: 'wazuh4_alerts' }), logger, 'holder', 120);
    expect(c.createPit).not.toHaveBeenCalled();
    expect(c.meta.source_state).toMatchObject({ status: 'blocked', family: null, eligible: ['wazuh5_findings'] });
  });
});
