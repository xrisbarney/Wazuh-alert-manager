jest.mock('./sync_lock', () => ({
  acquireOrRenewLock: jest.fn().mockResolvedValue(true),
  releaseLock: jest.fn().mockResolvedValue(undefined),
  generateHolderId: jest.fn(() => 'holder'),
}));

import { LEGACY_ALERT_STATUS_INDEX, LEGACY_RULES_INDEX, MIGRATION_INDEX, RULES_INDEX } from '../../common';
import { migrateLegacyData } from './legacy_migration';

const config: any = {
  sync: { sourceIndexPattern: 'wazuh-alerts-*' },
  migration: { enabled: true, batchSize: 1000 },
};

const logger: any = {
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
};

function legacyHit(id: string): any {
  return {
    _id: id,
    _index: LEGACY_ALERT_STATUS_INDEX,
    _source: {
      '@timestamp': `2026-08-28T10:00:0${id.slice(-1)}.000Z`,
      status: 'in_progress',
      rule: { id: '100', level: 5 },
    },
  };
}

function successfulBulk(body: any[]): any {
  const items = body.filter((_: any, index: number) => index % 2 === 0).map((action: any) => {
    const operation = Object.keys(action)[0];
    return { [operation]: { status: 200 } };
  });
  return { body: { errors: false, items } };
}

function migrationClient(alertPages: any[][], legacyRules: any[] = []) {
  let state: any;
  let alertSession = 0;
  const scrollPages = new Map<string, any[][]>();

  const client: any = {
    indices: {
      exists: jest.fn(async ({ index }: any) => ({
        body: index === LEGACY_ALERT_STATUS_INDEX || (index === LEGACY_RULES_INDEX && legacyRules.length > 0),
      })),
    },
    get: jest.fn(async ({ index, id }: any) => {
      if (index === MIGRATION_INDEX && id === 'legacy-v1-to-v2' && state) {
        return { body: { _source: state } };
      }
      const error: any = new Error('not found');
      error.meta = { statusCode: 404 };
      throw error;
    }),
    index: jest.fn(async ({ index, id, body }: any) => {
      if (index === MIGRATION_INDEX && id === 'legacy-v1-to-v2') state = { ...body };
      return { body: { result: 'updated' } };
    }),
    search: jest.fn(async (request: any) => {
      if (request.index === LEGACY_ALERT_STATUS_INDEX) {
        const scrollId = `alerts-${++alertSession}`;
        scrollPages.set(scrollId, [...alertPages.slice(1), []]);
        return { body: { _scroll_id: scrollId, hits: { hits: alertPages[0] || [] } } };
      }
      if (request.index === 'wazuh-alert-status-v2-read') {
        const scrollId = `related-${alertSession}`;
        scrollPages.set(scrollId, []);
        return { body: { _scroll_id: scrollId, hits: { hits: [] } } };
      }
      if (request.index === LEGACY_RULES_INDEX) {
        const scrollId = `rules-${alertSession}`;
        scrollPages.set(scrollId, [[]]);
        return { body: { _scroll_id: scrollId, hits: { hits: legacyRules } } };
      }
      return { body: { hits: { hits: [] } } };
    }),
    scroll: jest.fn(async ({ scrollId }: any) => {
      const pages = scrollPages.get(scrollId) || [];
      return { body: { _scroll_id: scrollId, hits: { hits: pages.shift() || [] } } };
    }),
    clearScroll: jest.fn(async () => ({})),
    bulk: jest.fn(async ({ body }: any) => successfulBulk(body)),
    mget: jest.fn(async () => ({ body: { docs: [] } })),
    create: jest.fn(async () => ({})),
  };

  return { client, state: () => state };
}

describe('legacy migration pagination', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('migrates multiple bounded scroll pages without _id sorting', async () => {
    const { client, state } = migrationClient([[legacyHit('legacy-1')], [legacyHit('legacy-2')]]);

    await migrateLegacyData(client, config, logger);

    const request = client.search.mock.calls.find(([arg]: any[]) => arg.index === LEGACY_ALERT_STATUS_INDEX)[0];
    expect(request.size).toBe(500);
    expect(request.body.sort).toEqual(['_doc']);
    expect(JSON.stringify(request)).not.toContain('search_after');
    expect(JSON.stringify(request.body.sort)).not.toContain('_id');
    expect(client.scroll).toHaveBeenCalledTimes(2);
    expect(client.clearScroll).toHaveBeenCalledWith({ scrollId: 'alerts-1' });
    expect(state()).toEqual(expect.objectContaining({ phase: 'complete', status: 'completed', migrated: 2 }));
  });

  test('clears the active scroll when a batch write throws', async () => {
    const { client } = migrationClient([[legacyHit('legacy-1')]]);
    client.bulk.mockRejectedValueOnce(new Error('bulk unavailable'));

    await expect(migrateLegacyData(client, config, logger)).rejects.toThrow('bulk unavailable');

    expect(client.clearScroll).toHaveBeenCalledWith({ scrollId: 'alerts-1' });
  });

  test('replays deterministic alert batches on resume without inflating progress', async () => {
    const { client, state } = migrationClient([[legacyHit('legacy-1')], [legacyHit('legacy-2')]]);
    let failSecondAlertOnce = true;
    client.bulk.mockImplementation(async ({ body }: any) => {
      if (
        failSecondAlertOnce &&
        body[0]?.update?._index === 'wazuh-alert-status-v2-write' &&
        body[1]?.upsert?.legacy_id === 'legacy-2'
      ) {
        failSecondAlertOnce = false;
        throw new Error('interrupted');
      }
      return successfulBulk(body);
    });

    await expect(migrateLegacyData(client, config, logger)).rejects.toThrow('interrupted');
    await migrateLegacyData(client, config, logger);

    const firstAlertWrites = client.bulk.mock.calls
      .map(([arg]: any[]) => arg.body)
      .filter((body: any[]) => body[1]?.upsert?.legacy_id === 'legacy-1');
    expect(firstAlertWrites).toHaveLength(2);
    expect(firstAlertWrites[0][0]).toEqual(firstAlertWrites[1][0]);
    expect(firstAlertWrites[1][1].script.source).toContain('migrated_from_legacy != true');
    expect(state()).toEqual(expect.objectContaining({ status: 'completed', migrated: 2 }));
  });

  test('rejects an item-level bulk failure even when errors is false', async () => {
    const { client } = migrationClient([[legacyHit('legacy-1')]]);
    client.bulk.mockResolvedValueOnce({
      body: { errors: false, items: [{ update: { status: 500, error: { reason: 'rejected' } } }] },
    });

    await expect(migrateLegacyData(client, config, logger)).rejects.toThrow(
      'One or more legacy alert documents failed to migrate'
    );
  });

  test('imports legacy saved rules using only the canonical trigger shape', async () => {
    const rule = {
      _id: 'legacy-rule',
      _source: {
        name: 'Burst', enabled: true, revision: 4, created_by: 'owner', counters: { matchedAlerts: 8 },
        trigger: { type: 'burst', entity: 'agent', threshold: 3, windowMinutes: 15 },
        actions: { createCase: true, caseSeverity: 'medium' },
      },
    };
    const { client } = migrationClient([], [rule]);

    await migrateLegacyData(client, config, logger);

    const body = client.bulk.mock.calls
      .map(([arg]: any[]) => arg.body)
      .find((value: any[]) => value[0]?.update?._index === RULES_INDEX);
    expect(body[0].update._id).toBe('legacy-rule');
    expect(body[1].upsert).toMatchObject({
      enabled: true, revision: 4, created_by: 'owner', counters: { matchedAlerts: 8 }, schemaVersion: 2,
      trigger: {
        routing: 'separate_by_group',
        entityExpression: { groups: [{ predicates: [{ entity: 'agent', operator: 'exists' }] }] },
      },
    });
    expect(body[1].upsert.trigger.entity).toBeUndefined();
  });
});
