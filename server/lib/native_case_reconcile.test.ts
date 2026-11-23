jest.mock('./sync_lock', () => ({
  acquireOrRenewLock: jest.fn().mockResolvedValue(true),
  releaseLock: jest.fn().mockResolvedValue(undefined),
  generateHolderId: jest.fn(() => 'holder'),
}));
jest.mock('./index_resolution', () => ({ resolveAlerts: jest.fn().mockResolvedValue(new Map()) }));
jest.mock('./automation_queue', () => ({
  activateAutomationEvents: jest.fn().mockResolvedValue(0),
  enqueueAutomationEvents: jest.fn().mockResolvedValue({ enqueued: 0, duplicates: 0, failed: 0 }),
  reconcileAutomationAdmissions: jest.fn().mockResolvedValue({ enqueued: 0, duplicates: 0, failed: 0 }),
  recordAutomationEnqueueFailure: jest.fn().mockResolvedValue(undefined),
}));
jest.mock('./source_runtime', () => ({
  ...(jest.requireActual('./source_runtime') as object),
  resolveSource: jest.fn(),
  persistSourceState: jest.fn().mockResolvedValue(undefined),
}));

import { acquireOrRenewLock } from './sync_lock';
import { resolveAlerts } from './index_resolution';
import { resolveSource } from './source_runtime';
import { alertUid } from './operational_projection';
import { runSyncOnce, PLUGIN_OWNED_FIELDS } from './sync_job';
import {
  NATIVE_CASE_RECONCILE_DOC_ID,
  NATIVE_CASE_RECONCILE_PAGE,
  nativeCaseReconcileQuery,
  nativeCaseReconcileSort,
  reconcileNativeCases,
} from './native_case_reconcile';

const config: any = {
  sync: {
    enabled: true,
    intervalSeconds: 60,
    sourceMode: 'wazuh5_findings',
    sourceIndexPattern: 'wazuh-findings-v5-*',
    initialLookbackMinutes: 10,
    overlapSeconds: 120,
    batchSize: 100,
  },
};
const logger: any = { debug: jest.fn(), info: jest.fn(), warn: jest.fn(), error: jest.fn() };

// A finding ingested long ago whose native case was edited just now: its
// @timestamp is far outside any sync window, only wazuh.case.updated_at moved.
const OLD_INDEX = '.ds-wazuh-findings-v5-standard-000001';
const oldFinding = (wazuhCase: any) => ({
  _index: OLD_INDEX,
  _id: 'finding-old',
  _source: { wazuh: { case: wazuhCase } },
});
const editedCase = {
  status: 'completed',
  severity: 'high',
  title: 'Resolved after review',
  tags: ['ssh'],
  description: 'must not be copied',
  created_at: '2026-11-01T00:00:00Z',
  updated_at: '2026-11-21T10:00:00Z',
};
const uid = alertUid(OLD_INDEX, 'finding-old');

function reconcileClient(hits: any[]) {
  return {
    get: jest.fn().mockRejectedValue({ meta: { statusCode: 404 } }),
    search: jest.fn().mockResolvedValue({ body: { hits: { hits } } }),
    bulk: jest.fn().mockResolvedValue({ body: { errors: false, items: hits.map(() => ({ update: { status: 200 } })) } }),
    index: jest.fn().mockResolvedValue({}),
  } as any;
}

describe('native case reconciliation (step 2.6)', () => {
  const now = new Date('2026-11-21T10:05:00.000Z');
  const renewLock = jest.fn().mockResolvedValue(true);

  beforeEach(() => {
    jest.clearAllMocks();
    renewLock.mockResolvedValue(true);
    (resolveAlerts as jest.Mock).mockResolvedValue(new Map());
  });

  test('query matches cases created or edited in the window; sort is oldest edit first in milliseconds', () => {
    const query = nativeCaseReconcileQuery('2026-11-21T09:00:00.000Z', '2026-11-21T10:00:00.000Z');
    expect(query.bool.minimum_should_match).toBe(1);
    expect(query.bool.should).toEqual([
      { range: { 'wazuh.case.updated_at': { gte: '2026-11-21T09:00:00.000Z', lte: '2026-11-21T10:00:00.000Z' } } },
      { range: { 'wazuh.case.created_at': { gte: '2026-11-21T09:00:00.000Z', lte: '2026-11-21T10:00:00.000Z' } } },
    ]);
    expect(nativeCaseReconcileSort()[0]['wazuh.case.updated_at']).toMatchObject({ order: 'asc', numeric_type: 'date', unmapped_type: 'date' });
    expect(nativeCaseReconcileSort()[1]).toEqual({ _doc: { order: 'asc' } });
  });

  test('an edited case on an old, already-synced finding is re-projected as a partial native_case update', async () => {
    const client = reconcileClient([oldFinding(editedCase)]);
    (resolveAlerts as jest.Mock).mockResolvedValue(new Map([[uid, { id: uid, index: 'wazuh-alert-status-v2-000003' }]]));

    const result = await reconcileNativeCases(client, config, logger, { pattern: 'wazuh-findings-v5-*', renewLock, now });

    expect(result).toMatchObject({ status: 'ok', scanned: 1, updated: 1, skipped: 0, more: false });
    // First run: the window starts at the initial lookback minus the overlap and ends now.
    expect(result.windowFrom).toBe('2026-11-21T09:53:00.000Z');
    expect(result.windowTo).toBe('2026-11-21T10:05:00.000Z');
    const search = client.search.mock.calls[0][0];
    expect(search.index).toBe('wazuh-findings-v5-*');
    expect(search.size).toBe(NATIVE_CASE_RECONCILE_PAGE);
    expect(search.body._source).toEqual(['wazuh.case']);
    expect(search.body.query).toEqual(nativeCaseReconcileQuery(result.windowFrom, result.windowTo));

    expect(renewLock).toHaveBeenCalledTimes(1);
    expect(client.bulk).toHaveBeenCalledTimes(1);
    const body = client.bulk.mock.calls[0][0].body;
    expect(body).toEqual([
      { update: { _index: 'wazuh-alert-status-v2-000003', _id: uid } },
      {
        doc: {
          native_case: {
            id: null,
            status: 'completed',
            severity: 'high',
            priority: null,
            tlp: null,
            title: 'Resolved after review',
            tags: ['ssh'],
            updated_at: '2026-11-21T10:00:00.000Z',
          },
        },
      },
    ]);
    // Only native_case travels: no plugin-owned field, no upsert, no script.
    expect(Object.keys(body[1])).toEqual(['doc']);
    expect(Object.keys(body[1].doc)).toEqual(['native_case']);
    for (const field of PLUGIN_OWNED_FIELDS) expect(body[1].doc).not.toHaveProperty(field);
    // The watermark advances to the end of the window once the write succeeded.
    expect(client.index).toHaveBeenCalledWith(
      expect.objectContaining({ id: NATIVE_CASE_RECONCILE_DOC_ID, body: expect.objectContaining({ watermark: '2026-11-21T10:05:00.000Z' }) })
    );
  });

  test('resumes from the stored watermark minus the overlap', async () => {
    const client = reconcileClient([]);
    client.get.mockResolvedValue({ body: { _source: { watermark: '2026-11-21T10:00:00.000Z' } } });
    const result = await reconcileNativeCases(client, config, logger, { pattern: 'wazuh-findings-v5-*', renewLock, now });
    expect(result.windowFrom).toBe('2026-11-21T09:58:00.000Z');
    expect(client.bulk).not.toHaveBeenCalled();
    expect(client.index).toHaveBeenCalledWith(expect.objectContaining({ id: NATIVE_CASE_RECONCILE_DOC_ID }));
  });

  test('a finding the main sync has not carried yet is skipped, never inserted', async () => {
    const client = reconcileClient([oldFinding(editedCase)]);
    const result = await reconcileNativeCases(client, config, logger, { pattern: 'wazuh-findings-v5-*', renewLock, now });
    expect(result).toMatchObject({ status: 'ok', scanned: 1, updated: 0, skipped: 1 });
    expect(client.bulk).not.toHaveBeenCalled();
  });

  test('a removed native case clears the field (null projection)', async () => {
    const client = reconcileClient([oldFinding({ updated_at: '2026-11-21T10:00:00Z' })]);
    (resolveAlerts as jest.Mock).mockResolvedValue(new Map([[uid, { id: uid, index: 'wazuh-alert-status-v2-000001' }]]));
    await reconcileNativeCases(client, config, logger, { pattern: 'wazuh-findings-v5-*', renewLock, now });
    expect(client.bulk.mock.calls[0][0].body[1]).toEqual({ doc: { native_case: null } });
  });

  test('aborts without writing when the lease is lost after the source read', async () => {
    const client = reconcileClient([oldFinding(editedCase)]);
    (resolveAlerts as jest.Mock).mockResolvedValue(new Map([[uid, { id: uid, index: 'wazuh-alert-status-v2-000001' }]]));
    renewLock.mockResolvedValue(false);
    const result = await reconcileNativeCases(client, config, logger, { pattern: 'wazuh-findings-v5-*', renewLock, now });
    expect(result.status).toBe('lock_lost');
    expect(client.bulk).not.toHaveBeenCalled();
    expect(client.index).not.toHaveBeenCalled();
  });

  test('keeps the watermark when the bulk update reports errors so the window replays', async () => {
    const client = reconcileClient([oldFinding(editedCase)]);
    (resolveAlerts as jest.Mock).mockResolvedValue(new Map([[uid, { id: uid, index: 'wazuh-alert-status-v2-000001' }]]));
    client.bulk.mockResolvedValue({ body: { errors: true, items: [{ update: { status: 409, error: { type: 'version_conflict' } } }] } });
    const result = await reconcileNativeCases(client, config, logger, { pattern: 'wazuh-findings-v5-*', renewLock, now });
    expect(result.status).toBe('write_failed');
    expect(client.index).not.toHaveBeenCalled();
    expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('native case reconciliation updates failed'));
  });

  test('a full page checkpoints on the last edit seen instead of fast-forwarding to now', async () => {
    const hits = Array.from({ length: NATIVE_CASE_RECONCILE_PAGE }, (_, i) => ({
      _index: OLD_INDEX,
      _id: `f-${i}`,
      _source: { wazuh: { case: { status: 'active', updated_at: `2026-11-21T09:${String(55 + Math.floor(i / 100)).padStart(2, '0')}:00Z` } } },
    }));
    const client = reconcileClient(hits);
    const result = await reconcileNativeCases(client, config, logger, { pattern: 'wazuh-findings-v5-*', renewLock, now });
    expect(result.more).toBe(true);
    expect(client.index).toHaveBeenCalledWith(
      expect.objectContaining({ body: expect.objectContaining({ watermark: '2026-11-21T09:59:00.000Z' }) })
    );
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('page (500) full'));
  });

  test('refuses to write outside the managed alert family', async () => {
    const client = reconcileClient([oldFinding(editedCase)]);
    (resolveAlerts as jest.Mock).mockResolvedValue(new Map([[uid, { id: uid, index: 'wazuh-alerts-4.x-2026.11.21' }]]));
    await expect(reconcileNativeCases(client, config, logger, { pattern: 'wazuh-findings-v5-*', renewLock, now })).rejects.toThrow();
    expect(client.bulk).not.toHaveBeenCalled();
  });
});

describe('runSyncOnce wires the reconciliation into a 5.0 tick', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (acquireOrRenewLock as jest.Mock).mockResolvedValue(true);
    (resolveAlerts as jest.Mock).mockResolvedValue(new Map([[uid, { id: uid, index: 'wazuh-alert-status-v2-000002' }]]));
  });

  function tickClient(family: 'wazuh5_findings' | 'wazuh4_alerts', reconcileHits: any[]) {
    (resolveSource as jest.Mock).mockResolvedValue({
      status: 'ready',
      family,
      pattern: family === 'wazuh5_findings' ? 'wazuh-findings-v5-*' : 'wazuh-alerts-*',
      profile: {},
      reason: 'test',
    });
    return {
      get: jest.fn().mockRejectedValue({ meta: { statusCode: 404 } }),
      createPit: jest.fn().mockResolvedValue({ body: { pit_id: 'pit-1' } }),
      deletePit: jest.fn().mockResolvedValue({}),
      // The main window (PIT search) is empty: the old finding's @timestamp is
      // outside it. The reconciliation search (by index pattern) finds the edit.
      search: jest.fn(async (args: any) => (args.body?.pit ? { body: { hits: { hits: [] } } } : { body: { hits: { hits: reconcileHits } } })),
      mget: jest.fn(async (args: any) => ({ body: { docs: args.body.ids.map((id: string) => ({ _id: id, found: false })) } })),
      bulk: jest.fn().mockResolvedValue({ body: { errors: false, items: [{ update: { status: 200 } }] } }),
      index: jest.fn().mockResolvedValue({}),
    } as any;
  }

  test('an old finding whose case was edited outside the sync window is picked up on the next 5.0 tick', async () => {
    const client = tickClient('wazuh5_findings', [oldFinding(editedCase)]);
    await runSyncOnce(client, config, logger, 'holder', 120);

    const reconcileSearch = client.search.mock.calls.map((c: any) => c[0]).find((args: any) => args.index === 'wazuh-findings-v5-*');
    expect(reconcileSearch).toBeDefined();
    const update = client.bulk.mock.calls
      .map((c: any) => c[0].body)
      .find((body: any[]) => body[1] && body[1].doc && 'native_case' in body[1].doc);
    expect(update).toEqual([
      { update: { _index: 'wazuh-alert-status-v2-000002', _id: uid } },
      { doc: { native_case: expect.objectContaining({ status: 'completed', title: 'Resolved after review' }) } },
    ]);
    expect(client.index).toHaveBeenCalledWith(expect.objectContaining({ id: NATIVE_CASE_RECONCILE_DOC_ID }));
  });

  test('a 4.x tick never runs the reconciliation', async () => {
    const client = tickClient('wazuh4_alerts', [oldFinding(editedCase)]);
    await runSyncOnce(client, config, logger, 'holder', 120);
    expect(client.search.mock.calls.every((c: any) => c[0].body?.pit)).toBe(true);
    expect(client.index).not.toHaveBeenCalledWith(expect.objectContaining({ id: NATIVE_CASE_RECONCILE_DOC_ID }));
  });

  test('a reconciliation failure is logged and never blocks the main cursor', async () => {
    const client = tickClient('wazuh5_findings', []);
    client.search.mockImplementation(async (args: any) => {
      if (args.body?.pit) return { body: { hits: { hits: [] } } };
      throw new Error('findings read failed');
    });
    await runSyncOnce(client, config, logger, 'holder', 120);
    expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('native case reconciliation failed: findings read failed'));
    // The main watermark was still committed before the pass ran.
    expect(client.index).toHaveBeenCalledWith(expect.objectContaining({ id: 'sync_state:wazuh5_findings' }));
  });
});
