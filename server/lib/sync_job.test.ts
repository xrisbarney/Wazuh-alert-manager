// These assertions describe the Wazuh 4.x behaviour of this module (native
// alert indices, numeric rule levels, the 4.x channel/source set). The build
// target is a build-time constant and CI runs this suite once per matrix
// entry, including the 5.0 one, so pin it rather than assert whichever
// target happens to be checked in.
jest.mock('../../common/build_info', () => ({ ...(jest.requireActual('../../common/build_info') as object), TARGET_WAZUH_MAJOR: 4, TARGET_WAZUH_VERSION: '4.14.10' }));

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

import {
  activateAutomationEvents,
  enqueueAutomationEvents,
  reconcileAutomationAdmissions,
  recordAutomationEnqueueFailure,
} from './automation_queue';
import { resolveAlerts } from './index_resolution';
import { alertUid } from './operational_projection';
import { runSyncOnce } from './sync_job';
import { invalidateSlaPolicyCache } from './sla/policy';

const config: any = {
  sync: {
    enabled: true,
    intervalSeconds: 60,
    sourceIndexPattern: 'wazuh-alerts-*',
    initialLookbackMinutes: 10,
    overlapSeconds: 120,
    batchSize: 1,
  },
};
const logger: any = {
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
};

function clientWithHits(hits: any[]) {
  return {
    get: jest.fn().mockRejectedValue({ meta: { statusCode: 404 } }),
    createPit: jest.fn().mockResolvedValue({ body: { pit_id: 'pit-1' } }),
    deletePit: jest.fn().mockResolvedValue({}),
    search: jest.fn().mockResolvedValue({ body: { hits: { hits } } }),
    mget: jest.fn(async (args: any) => ({
      body: { docs: args.body.ids.map((id: string) => ({ _id: id, found: false })) },
    })),
    bulk: jest.fn().mockResolvedValue({ body: { errors: false, items: [{ update: { status: 201 } }] } }),
    index: jest.fn().mockResolvedValue({}),
  } as any;
}

describe('source pagination', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    config.sync.batchSize = 1;
    (enqueueAutomationEvents as jest.Mock).mockResolvedValue({ enqueued: 1, duplicates: 0, failed: 0 });
    (resolveAlerts as jest.Mock).mockResolvedValue(new Map());
  });

  test('uses PIT and _doc without sorting on _id', async () => {
    const client = clientWithHits([
      {
        _id: 'source-1',
        _index: 'wazuh-alerts-4.x-2026.08.28',
        _source: { '@timestamp': '2026-08-28T10:00:00.000Z', rule: { id: '100', level: 5 } },
        sort: ['2026-08-28T10:00:00.000Z', 7],
      },
    ]);

    await runSyncOnce(client, config, logger, 'holder', 120);

    expect(client.createPit).toHaveBeenCalledWith({ index: 'wazuh-alerts-*', keep_alive: '120s' });
    const request = client.search.mock.calls[0][0];
    expect(request.index).toBeUndefined();
    expect(request.body.pit).toEqual({ id: 'pit-1', keep_alive: '120s' });
    expect(request.body.sort).toEqual([
      { '@timestamp': { order: 'asc' } },
      { _doc: { order: 'asc' } },
    ]);
    expect(JSON.stringify(request.body.sort)).not.toContain('_id');
    expect(client.index).toHaveBeenCalledWith(
      expect.objectContaining({
        id: 'sync_state',
        body: expect.objectContaining({ search_after: ['2026-08-28T10:00:00.000Z', 7], pit_id: 'pit-1' }),
      })
    );
  });

  test('uses the transport PIT API with the dashboard legacy client', async () => {
    const client: any = clientWithHits([]);
    delete client.createPit;
    delete client.deletePit;
    client.transport = {
      request: jest
        .fn()
        // v3: the source is resolved read-only before any PIT is opened.
        .mockResolvedValueOnce({ body: { indices: [{ name: 'wazuh-alerts-4.x-2026.10.31' }], aliases: [], data_streams: [] } })
        .mockResolvedValueOnce({ body: { pit_id: 'transport-pit' } })
        .mockResolvedValueOnce({ body: { succeeded: true } }),
    };

    await runSyncOnce(client, config, logger, 'holder', 120);

    expect(client.transport.request).toHaveBeenNthCalledWith(1, {
      method: 'GET',
      path: '/_resolve/index/wazuh-alerts-*',
      querystring: { expand_wildcards: 'open' },
    });
    expect(client.transport.request).toHaveBeenNthCalledWith(2, {
      method: 'POST',
      path: '/wazuh-alerts-*/_search/point_in_time',
      querystring: { keep_alive: '120s' },
    });
    expect(client.transport.request).toHaveBeenNthCalledWith(3, {
      method: 'DELETE',
      path: '/_search/point_in_time',
      body: { pit_id: ['transport-pit'] },
    });
  });

  test('resets a stale PIT and cursor so the window replays without gaps', async () => {
    const client: any = clientWithHits([]);
    client.get.mockResolvedValue({
      body: {
        _source: {
          completed_at: '2026-08-28T09:00:00.000Z',
          window_from: '2026-08-28T08:58:00.000Z',
          window_to: '2026-08-28T10:00:00.000Z',
          search_after: ['2026-08-28T09:30:00.000Z', 42],
          pit_id: 'expired-pit',
        },
      },
    });
    client.search.mockRejectedValue(new Error('point in time missing'));

    await runSyncOnce(client, config, logger, 'holder', 120);

    expect(client.createPit).not.toHaveBeenCalled();
    expect(client.index).toHaveBeenCalledWith(
      expect.objectContaining({
        body: expect.objectContaining({
          completed_at: '2026-08-28T09:00:00.000Z',
          window_from: '2026-08-28T08:58:00.000Z',
          window_to: '2026-08-28T10:00:00.000Z',
          search_after: null,
          pit_id: null,
        }),
      })
    );
  });

  test('commits ingestion progress when automation enqueue and its DLQ fail', async () => {
    const client = clientWithHits([
      {
        _id: 'source-1',
        _index: 'wazuh-alerts-4.x-2026.08.28',
        _source: { '@timestamp': '2026-08-28T10:00:00.000Z' },
        sort: ['2026-08-28T10:00:00.000Z', 7],
      },
    ]);
    config.sync.batchSize = 2;
    (enqueueAutomationEvents as jest.Mock).mockRejectedValue(new Error('queue unavailable'));
    (recordAutomationEnqueueFailure as jest.Mock).mockRejectedValue(new Error('dlq unavailable'));

    await runSyncOnce(client, config, logger, 'holder', 120);

    expect(client.index).toHaveBeenCalledWith(
      expect.objectContaining({ body: expect.objectContaining({ search_after: null, pit_id: null }) })
    );
    expect(client.deletePit).toHaveBeenCalledWith({ body: { pit_id: ['pit-1'] } });
  });

  test('does not halt sync for a user-created over-limit ruleset', async () => {
    const client = clientWithHits([{
      _id: 'source-1', _index: 'wazuh-alerts-4.x-2026.08.28',
      _source: { '@timestamp': '2026-08-28T10:00:00.000Z' },
      sort: ['2026-08-28T10:00:00.000Z', 7],
    }]);
    config.sync.batchSize = 2;
    (enqueueAutomationEvents as jest.Mock).mockRejectedValue(
      Object.assign(new Error('too many enabled rules'), { automationRulesOverLimit: true })
    );

    await runSyncOnce(client, config, logger, 'holder', 120);

    expect(client.bulk).toHaveBeenCalled();
    expect(client.index).toHaveBeenCalledWith(expect.objectContaining({ id: 'sync_state' }));
  });

  test('fails closed before operational storage when admission markers cannot be persisted', async () => {
    const client = clientWithHits([
      {
        _id: 'source-1',
        _index: 'wazuh-alerts-4.x-2026.08.28',
        _source: { '@timestamp': '2026-08-28T10:00:00.000Z' },
        sort: ['2026-08-28T10:00:00.000Z', 7],
      },
    ]);
    config.sync.batchSize = 2;
    (enqueueAutomationEvents as jest.Mock).mockRejectedValue(
      Object.assign(new Error('marker unavailable'), { automationAdmissionUnsafe: true })
    );

    await runSyncOnce(client, config, logger, 'holder', 120);

    expect(client.bulk).not.toHaveBeenCalled();
    expect(recordAutomationEnqueueFailure).not.toHaveBeenCalled();
    expect(client.index).not.toHaveBeenCalledWith(expect.objectContaining({ id: 'sync_state' }));
  });

  test('runs bounded admission recovery independently before querying native alerts', async () => {
    const client = clientWithHits([]);

    await runSyncOnce(client, config, logger, 'holder', 120);

    expect(reconcileAutomationAdmissions).toHaveBeenCalledWith(client);
    expect((reconcileAutomationAdmissions as jest.Mock).mock.invocationCallOrder[0])
      .toBeLessThan(client.search.mock.invocationCallOrder[0]);
  });

  test('does not automate overlap history on an existing deployment', async () => {
    const client = clientWithHits([
      {
        _id: 'old-overlap',
        _index: 'wazuh-alerts-4.x-2026.08.28',
        _source: { '@timestamp': '2026-08-28T09:59:00.000Z' },
        sort: ['2026-08-28T09:59:00.000Z', 1],
      },
      {
        _id: 'new-alert',
        _index: 'wazuh-alerts-4.x-2026.08.28',
        _source: { '@timestamp': '2026-08-28T10:01:00.000Z' },
        sort: ['2026-08-28T10:01:00.000Z', 2],
      },
    ]);
    client.get.mockResolvedValue({ body: { _source: { completed_at: '2026-08-28T10:00:00.000Z' } } });
    (resolveAlerts as jest.Mock).mockResolvedValue(new Map([
      [alertUid('wazuh-alerts-4.x-2026.08.28', 'old-overlap'), { index: 'wazuh-alert-status-v2-000001' }],
    ]));
    config.sync.batchSize = 3;

    await runSyncOnce(client, config, logger, 'holder', 120);

    expect(enqueueAutomationEvents).toHaveBeenCalledWith(
      client,
      [expect.objectContaining({ source_id: 'new-alert', '@timestamp': '2026-08-28T10:01:00.000Z' })]
    );
  });

  test('admits a newly discovered late alert regardless of its source timestamp', async () => {
    const client = clientWithHits([
      {
        _id: 'late-alert',
        _index: 'wazuh-alerts-4.x-2026.08.28',
        _source: { '@timestamp': '2026-08-28T09:59:00.000Z' },
        sort: ['2026-08-28T09:59:00.000Z', 3],
      },
    ]);
    client.get.mockResolvedValue({ body: { _source: { completed_at: '2026-08-28T10:00:00.000Z' } } });
    config.sync.batchSize = 2;

    await runSyncOnce(client, config, logger, 'holder', 120);

    expect(enqueueAutomationEvents).toHaveBeenCalledWith(
      client,
      [expect.objectContaining({ source_id: 'late-alert', '@timestamp': '2026-08-28T09:59:00.000Z' })]
    );
  });

  test('writes the queue outbox before the operational upsert to close the crash window', async () => {
    const client = clientWithHits([
      {
        _id: 'source-1',
        _index: 'wazuh-alerts-4.x-2026.08.28',
        _source: { '@timestamp': '2026-08-28T10:01:00.000Z' },
        sort: ['2026-08-28T10:01:00.000Z', 1],
      },
    ]);
    config.sync.batchSize = 2;

    await runSyncOnce(client, config, logger, 'holder', 120);

    expect((enqueueAutomationEvents as jest.Mock).mock.invocationCallOrder[0])
      .toBeLessThan(client.bulk.mock.invocationCallOrder[0]);
    expect(client.bulk).toHaveBeenCalledWith(expect.objectContaining({ refresh: 'wait_for' }));
    expect(client.bulk.mock.invocationCallOrder[0])
      .toBeLessThan((activateAutomationEvents as jest.Mock).mock.invocationCallOrder[0]);
  });

  test('activates only alerts selected by the immutable admission ruleset', async () => {
    const client = clientWithHits([
      {
        _id: 'control', _index: 'wazuh-alerts-4.x-2026.08.28',
        _source: { '@timestamp': '2026-08-28T10:01:00.000Z' },
        sort: ['2026-08-28T10:01:00.000Z', 1],
      },
      {
        _id: 'candidate', _index: 'wazuh-alerts-4.x-2026.08.28',
        _source: { '@timestamp': '2026-08-28T10:01:01.000Z' },
        sort: ['2026-08-28T10:01:01.000Z', 2],
      },
    ]);
    config.sync.batchSize = 3;
    client.bulk.mockImplementation(async ({ body }: any) => ({
      body: {
        errors: false,
        items: body.filter((item: any) => item.update).map(() => ({ update: { status: 201 } })),
      },
    }));
    (enqueueAutomationEvents as jest.Mock).mockImplementation(async (_client: any, events: any[]) => ({
      enqueued: 1, duplicates: 0, failed: 0, candidateAlertUids: [events[1].alert_uid],
    }));

    await runSyncOnce(client, config, logger, 'holder', 120);

    const admitted = (enqueueAutomationEvents as jest.Mock).mock.calls[0][1];
    expect(activateAutomationEvents).toHaveBeenCalledWith(client, [admitted[1]]);
  });

  test('bounds large operational bulks and refreshes all targets once', async () => {
    config.sync.batchSize = 1001;
    const hits = Array.from({ length: 1001 }, (_, id) => ({
      _id: `source-${id}`,
      _index: 'wazuh-alerts-4.x-2026.08.28',
      _source: {
        '@timestamp': `2026-08-28T10:00:${String(id % 60).padStart(2, '0')}.000Z`,
        rule: { id: '100', level: 5 },
      },
      sort: [`2026-08-28T10:00:${String(id % 60).padStart(2, '0')}.000Z`, id],
    }));
    const client: any = clientWithHits(hits);
    client.bulk.mockImplementation(async ({ body }: any) => ({
      body: {
        errors: false,
        items: body.filter((item: any) => item.update).map(() => ({ update: { status: 201 } })),
      },
    }));
    client.indices = { refresh: jest.fn().mockResolvedValue({}) };

    await runSyncOnce(client, config, logger, 'holder', 120);

    expect(client.bulk).toHaveBeenCalledTimes(2);
    expect(client.bulk.mock.calls[0][0].body).toHaveLength(2000);
    expect(client.bulk.mock.calls[1][0].body).toHaveLength(2);
    expect(client.bulk.mock.calls.every((call: any[]) => call[0].refresh == null)).toBe(true);
    expect(client.indices.refresh).toHaveBeenCalledTimes(1);
    expect(client.indices.refresh).toHaveBeenCalledWith({ index: ['wazuh-alert-status-v2-write'] });
  });

  test('initializes the immutable ingestion boundary without overwriting it on replay', async () => {
    const client = clientWithHits([{
      _id: 'source-1', _index: 'wazuh-alerts-4.x-2026.08.28',
      _source: { '@timestamp': '2026-08-28T10:01:00.000Z', rule: { id: '5710', level: 5 } },
      sort: ['2026-08-28T10:01:00.000Z', 1],
    }]);
    config.sync.batchSize = 2;

    await runSyncOnce(client, config, logger, 'holder', 120);

    const bulkBody = client.bulk.mock.calls[0][0].body;
    const update = bulkBody[1];
    expect(update.script.params.protected).toContain('ingested_at');
    expect(update.script.params.doc.ingested_at).toBeTruthy();
    expect(update.script.source).toContain('if (ctx._source.ingested_at == null)');
    expect(update.script.source).toContain('ctx._source.ingested_at = params.doc.ingested_at');
    expect(update.script.source).toContain("if (!ctx._source.containsKey('related_alert_ids'))");
  });

  test('seeds the due timestamps only when absent and protects reporting from replay (step 3.2)', async () => {
    const client = clientWithHits([{
      _id: 'source-1', _index: 'wazuh-alerts-4.x-2026.08.28',
      _source: { '@timestamp': '2026-08-28T10:01:00.000Z', rule: { id: '5710', level: 12 } },
      sort: ['2026-08-28T10:01:00.000Z', 1],
    }]);
    config.sync.batchSize = 2;
    invalidateSlaPolicyCache();

    await runSyncOnce(client, config, logger, 'holder', 120);

    const update = client.bulk.mock.calls[0][0].body[1];
    // The policy document is read once per tick (404 here -> built-in targets).
    expect(client.get).toHaveBeenCalledWith(expect.objectContaining({ id: 'sla_policy' }));
    expect(update.script.params.doc.reporting).toEqual({
      sla_due_at: '2026-08-28T11:01:00.000Z',
      assign_due_at: '2026-08-28T10:16:00.000Z',
    });
    expect(update.script.params.protected).toContain('reporting');
    expect(update.script.source).toContain('if (ctx._source.reporting.sla_due_at == null && params.doc.reporting.sla_due_at != null)');
    expect(update.script.source).toContain('if (ctx._source.reporting.assign_due_at == null && params.doc.reporting.assign_due_at != null)');
  });

  test('does not create an automation backlog for operational alerts found during upgrade overlap', async () => {
    const index = 'wazuh-alerts-4.x-2026.08.28';
    const client = clientWithHits([
      {
        _id: 'existing-alert', _index: index,
        _source: { '@timestamp': '2026-08-28T10:01:00.000Z' },
        sort: ['2026-08-28T10:01:00.000Z', 1],
      },
    ]);
    client.get.mockResolvedValue({ body: { _source: { completed_at: '2026-08-28T10:00:00.000Z' } } });
    (resolveAlerts as jest.Mock).mockResolvedValue(new Map([
      [alertUid(index, 'existing-alert'), { index: 'wazuh-alert-status-v2-000001' }],
    ]));
    config.sync.batchSize = 2;

    await runSyncOnce(client, config, logger, 'holder', 120);

    expect(enqueueAutomationEvents).toHaveBeenCalledWith(client, []);
  });

  test('does not replay an archive-only alert when native overlap sees it again', async () => {
    const index = 'wazuh-alerts-4.x-2026.08.28';
    const hit = {
      _id: 'archived', _index: index,
      _source: { '@timestamp': '2026-08-28T10:01:00.000Z' },
      sort: ['2026-08-28T10:01:00.000Z', 1],
    };
    const client = clientWithHits([hit]);
    client.search
      .mockResolvedValueOnce({ body: { hits: { hits: [hit] } } })
      .mockResolvedValueOnce({ body: { hits: { hits: [{
        _id: alertUid(index, 'archived'), _index: 'wazuh-alert-status-v2-000001',
      }] } } })
      // Covers the alias-cutover gap before retirement metadata is refreshed.
      .mockResolvedValueOnce({ body: { hits: { total: { value: 0 }, hits: [] } } });
    config.sync.batchSize = 2;

    await runSyncOnce(client, config, logger, 'holder', 120);

    expect(enqueueAutomationEvents).toHaveBeenCalledWith(client, []);
    expect(client.bulk).not.toHaveBeenCalled();
    expect(client.index).toHaveBeenCalledWith(expect.objectContaining({ id: 'sync_state' }));
  });

  test('suppresses only an exactly tombstoned alert after archive deletion', async () => {
    const index = 'wazuh-alerts-4.x-2026.08.28';
    const purgedHit = {
      _id: 'purged', _index: index,
      _source: { '@timestamp': '2026-08-28T10:01:00.000Z' },
      sort: ['2026-08-28T10:01:00.000Z', 1],
    };
    const newHit = {
      _id: 'new-alert', _index: index,
      _source: { '@timestamp': '2026-08-28T10:02:00.000Z' },
      sort: ['2026-08-28T10:02:00.000Z', 2],
    };
    const purgedId = alertUid(index, 'purged');
    const newId = alertUid(index, 'new-alert');
    const client = clientWithHits([purgedHit, newHit]);
    client.search
      .mockResolvedValueOnce({ body: { hits: { hits: [purgedHit, newHit] } } })
      .mockResolvedValueOnce({ body: { hits: { hits: [] } } })
      .mockResolvedValueOnce({ body: { hits: { total: { value: 1 }, hits: [{
        _id: 'retirement:wazuh-alert-status-v2-000001',
        _source: { status: 'purged', retiring_index: 'wazuh-alert-status-v2-000001' },
      }] } } });
    client.mget.mockResolvedValueOnce({ body: { docs: [
      {
        _id: `retired-alert:${purgedId}`,
        found: true,
        _source: {
          document_type: 'retired_alert', alert_uid: purgedId,
          retiring_index: 'wazuh-alert-status-v2-000001',
        },
      },
      { _id: `retired-alert:${newId}`, found: false },
    ] } });
    config.sync.batchSize = 3;

    await runSyncOnce(client, config, logger, 'holder', 120);

    expect(enqueueAutomationEvents).toHaveBeenCalledWith(
      client,
      [expect.objectContaining({ alert_uid: newId, source_id: 'new-alert' })]
    );
    expect(client.bulk).toHaveBeenCalledWith(expect.objectContaining({
      body: expect.arrayContaining([
        { update: { _index: 'wazuh-alert-status-v2-write', _id: newId } },
      ]),
    }));
    expect(JSON.stringify(client.bulk.mock.calls[0][0].body)).not.toContain(purgedId);
    expect(client.index).toHaveBeenCalledWith(expect.objectContaining({ id: 'sync_state' }));
  });

  test('fails closed on incomplete purged alert tombstone evidence', async () => {
    const hit = {
      _id: 'purged', _index: 'wazuh-alerts-4.x-2026.08.28',
      _source: { '@timestamp': '2026-08-28T10:01:00.000Z' },
      sort: ['2026-08-28T10:01:00.000Z', 1],
    };
    const client = clientWithHits([hit]);
    client.search
      .mockResolvedValueOnce({ body: { hits: { hits: [hit] } } })
      .mockResolvedValueOnce({ body: { hits: { hits: [] } } });
    client.mget.mockResolvedValueOnce({ body: { docs: [] } });
    config.sync.batchSize = 2;

    await runSyncOnce(client, config, logger, 'holder', 120);

    expect(enqueueAutomationEvents).not.toHaveBeenCalled();
    expect(client.bulk).not.toHaveBeenCalled();
    expect(client.index).not.toHaveBeenCalledWith(expect.objectContaining({ id: 'sync_state' }));
    expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('failed to resolve managed alert evidence'));
  });

  test('ignores non-retirement meta documents that share a completed status (sla_due_backfill)', async () => {
    const index = 'wazuh-alerts-4.x-2026.08.28';
    const hit = {
      _id: 'fresh', _index: index,
      _source: { '@timestamp': '2026-08-28T10:01:00.000Z' },
      sort: ['2026-08-28T10:01:00.000Z', 1],
    };
    const client = clientWithHits([hit]);
    client.search
      .mockResolvedValueOnce({ body: { hits: { hits: [hit] } } })
      .mockResolvedValueOnce({ body: { hits: { hits: [] } } })
      // The due-date backfill run (server/lib/sla/due_backfill.ts) and the
      // escalation status live in the same meta index with a `status` field;
      // they carry no retiring_index and must not fail the evidence scan.
      .mockResolvedValueOnce({ body: { hits: { total: { value: 2 }, hits: [
        { _id: 'sla_due_backfill', _source: { status: 'completed' } },
        { _id: 'retirement:wazuh-alert-status-v2-000001', _source: { status: 'completed', retiring_index: 'wazuh-alert-status-v2-000001' } },
      ] } } });
    client.mget
      .mockResolvedValueOnce({ body: { docs: [{ _id: `retired-alert:${alertUid(index, 'fresh')}`, found: false }] } })
      .mockResolvedValueOnce({ body: { docs: [{ _id: alertUid(index, 'fresh'), found: false }] } });
    config.sync.batchSize = 2;

    await runSyncOnce(client, config, logger, 'holder', 120);

    expect(logger.error).not.toHaveBeenCalledWith(expect.stringContaining('failed to resolve managed alert evidence'));
    expect(client.mget).toHaveBeenCalledWith(expect.objectContaining({ index: 'wazuh-alert-status-v2-000001' }));
    expect(enqueueAutomationEvents).toHaveBeenCalledWith(client, [expect.objectContaining({ source_id: 'fresh' })]);
    expect(client.bulk).toHaveBeenCalledTimes(1);
    expect(client.index).toHaveBeenCalledWith(expect.objectContaining({ id: 'sync_state' }));
  });

  test('repairs a restored missing-live projection without replaying automation', async () => {
    const index = 'wazuh-alerts-4.x-2026.08.28';
    const hit = {
      _id: 'restored', _index: index,
      _source: { '@timestamp': '2026-08-28T10:01:00.000Z' },
      sort: ['2026-08-28T10:01:00.000Z', 1],
    };
    const client = clientWithHits([hit]);
    client.search
      .mockResolvedValueOnce({ body: { hits: { hits: [hit] } } })
      .mockResolvedValueOnce({ body: { hits: { hits: [{
        _id: alertUid(index, 'restored'), _index: 'wazuh-alert-status-v2-000001',
      }] } } })
      .mockResolvedValueOnce({ body: { hits: { total: { value: 1 }, hits: [{
        _id: 'retirement:wazuh-alert-status-v2-000001',
        _source: { status: 'restored', retiring_index: 'wazuh-alert-status-v2-000001' },
      }] } } });
    client.mget
      .mockResolvedValueOnce({ body: { docs: [{
        _id: `retired-alert:${alertUid(index, 'restored')}`, found: false,
      }] } })
      .mockResolvedValueOnce({ body: { docs: [{ _id: alertUid(index, 'restored'), found: true }] } });
    config.sync.batchSize = 2;

    await runSyncOnce(client, config, logger, 'holder', 120);

    expect(enqueueAutomationEvents).toHaveBeenCalledWith(client, []);
    expect(client.bulk).toHaveBeenCalledTimes(1);
  });
});

describe('asset stamping per sync batch (step 6.4a)', () => {
  const twoHits = [
    {
      _id: 's1', _index: 'wazuh-alerts-4.x-2026.11.20',
      _source: { '@timestamp': '2026-11-20T10:00:00.000Z', agent: { id: '001', name: 'web-01' }, rule: { id: '100', level: 5 } },
      sort: ['2026-11-20T10:00:00.000Z', 1],
    },
    {
      _id: 's2', _index: 'wazuh-alerts-4.x-2026.11.20',
      _source: { '@timestamp': '2026-11-20T10:00:01.000Z', agent: { id: '002', name: 'db-01', labels: { env: 'prod' } }, rule: { id: '101', level: 5 } },
      sort: ['2026-11-20T10:00:01.000Z', 2],
    },
  ];
  const assetDoc = {
    assets: [
      { id: 'web', match: { kind: 'glob', value: 'web-*' }, criticality: 'high', tags: ['pci'] },
      { id: 'dmz', match: { kind: 'group', value: 'dmz' }, criticality: 'critical', tags: [] },
    ],
  };
  const twoOk = { body: { errors: false, items: [{ update: { status: 201 } }, { update: { status: 201 } }] } };

  beforeEach(() => {
    jest.clearAllMocks();
    config.sync.batchSize = 10;
    (enqueueAutomationEvents as jest.Mock).mockResolvedValue({ enqueued: 2, duplicates: 0, failed: 0 });
    (resolveAlerts as jest.Mock).mockResolvedValue(new Map());
  });

  const upsertedDocs = (client: any) =>
    client.bulk.mock.calls[0][0].body.filter((_: any, i: number) => i % 2 === 1).map((op: any) => op.script.params.doc);

  test('reads asset_settings once per batch and stamps every record with cached 4.x groups', async () => {
    const client = clientWithHits(twoHits);
    client.get.mockImplementation(async (req: any) => {
      if (req.id === 'asset_settings') return { body: { _source: assetDoc } };
      throw { meta: { statusCode: 404 } };
    });
    client.bulk.mockResolvedValue(twoOk);
    const agentGroups = { lookup: jest.fn(async () => new Map([['001', []], ['002', ['dmz']]])) };

    await runSyncOnce(client, config, logger, 'holder', 120, { agentGroups });

    expect(client.get.mock.calls.filter(([req]: any[]) => req.id === 'asset_settings')).toHaveLength(1);
    expect(agentGroups.lookup).toHaveBeenCalledTimes(1);
    expect(Array.from((agentGroups.lookup.mock.calls[0] as any[])[0] as Set<string>)).toEqual(['001', '002']);
    const docs = upsertedDocs(client);
    expect(docs[0].asset).toEqual({ criticality: 'high', tags: ['pci'], groups: [], labels: null, matched_id: 'web', matched_by: 'glob' });
    expect(docs[1].asset).toEqual({ criticality: 'critical', tags: [], groups: ['dmz'], labels: { env: 'prod' }, matched_id: 'dmz', matched_by: 'group' });
    // The protected list never freezes the stamp.
    expect(client.bulk.mock.calls[0][0].body[1].script.params.protected).not.toContain('asset');
  });

  test('re-validates the sync lock after the group lookup and never writes when it was lost meanwhile', async () => {
    const { acquireOrRenewLock } = jest.requireMock('./sync_lock');
    const client = clientWithHits(twoHits);
    client.bulk.mockResolvedValue(twoOk);
    const order: string[] = [];
    const agentGroups = {
      lookup: jest.fn(async () => {
        order.push('lookup');
        // Simulate a slow Wazuh API: the lease is gone by the time it answers.
        acquireOrRenewLock.mockImplementationOnce(async () => { order.push('lock'); return false; });
        return new Map([['001', []], ['002', []]]);
      }),
    };
    acquireOrRenewLock.mockImplementation(async () => {
      order.push('lock');
      return true;
    });
    acquireOrRenewLock.mockClear();

    await runSyncOnce(client, config, logger, 'holder', 120, { agentGroups });

    expect(order.indexOf('lookup')).toBeGreaterThanOrEqual(0);
    // The lock check that guards the bulk write happens after the lookup.
    expect(order.slice(order.indexOf('lookup') + 1)).toContain('lock');
    expect(client.bulk).not.toHaveBeenCalled();
    expect(enqueueAutomationEvents).not.toHaveBeenCalled();
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('lost the sync lock before bulk upsert'));
    acquireOrRenewLock.mockReset();
    acquireOrRenewLock.mockResolvedValue(true);
  });

  test('keeps syncing when the settings document is absent and no group lookup is given', async () => {
    const client = clientWithHits(twoHits);
    client.bulk.mockResolvedValue(twoOk);

    await runSyncOnce(client, config, logger, 'holder', 120);

    const docs = upsertedDocs(client);
    expect(docs).toHaveLength(2);
    expect(docs.every((doc: any) => doc.asset.criticality === null && doc.asset.groups.length === 0)).toBe(true);
    expect(logger.error).not.toHaveBeenCalled();
  });

  test('a failing settings read or group lookup degrades instead of aborting the tick', async () => {
    const client = clientWithHits(twoHits);
    client.get.mockImplementation(async (req: any) => {
      if (req.id === 'asset_settings') throw new Error('meta index unavailable');
      throw { meta: { statusCode: 404 } };
    });
    client.bulk.mockResolvedValue(twoOk);
    const agentGroups = { lookup: jest.fn(async () => { throw new Error('api down'); }) };

    await runSyncOnce(client, config, logger, 'holder', 120, { agentGroups });

    expect(upsertedDocs(client)).toHaveLength(2);
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('meta index unavailable'));
    expect(logger.debug).toHaveBeenCalledWith(expect.stringContaining('api down'));
  });
});
