jest.mock('./sync_lock', () => ({
  acquireOrRenewLock: jest.fn().mockResolvedValue(true),
  releaseLock: jest.fn().mockResolvedValue(undefined),
  generateHolderId: jest.fn(() => 'holder'),
}));
jest.mock('./index_resolution', () => ({ resolveAlerts: jest.fn().mockResolvedValue(new Map()) }));
jest.mock('./automation_queue', () => ({
  enqueueAutomationEvents: jest.fn().mockResolvedValue({ enqueued: 1, duplicates: 0, failed: 0 }),
  reconcileAutomationAdmissions: jest.fn().mockResolvedValue({ enqueued: 0, duplicates: 0, failed: 0 }),
  recordAutomationEnqueueFailure: jest.fn().mockResolvedValue(undefined),
}));

import {
  enqueueAutomationEvents,
  reconcileAutomationAdmissions,
  recordAutomationEnqueueFailure,
} from './automation_queue';
import { resolveAlerts } from './index_resolution';
import { alertUid } from './operational_projection';
import { runSyncOnce } from './sync_job';

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
        .mockResolvedValueOnce({ body: { pit_id: 'transport-pit' } })
        .mockResolvedValueOnce({ body: { succeeded: true } }),
    };

    await runSyncOnce(client, config, logger, 'holder', 120);

    expect(client.transport.request).toHaveBeenNthCalledWith(1, {
      method: 'POST',
      path: '/wazuh-alerts-*/_search/point_in_time',
      querystring: { keep_alive: '120s' },
    });
    expect(client.transport.request).toHaveBeenNthCalledWith(2, {
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
