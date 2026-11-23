import { META_INDEX, WAM_ALERT_SEVERITY_COLUMN } from '../../common';
import {
  INDEX_REF_NAME,
  SAVED_OBJECTS_BRIDGE_DOC_ID,
  SAVED_OBJECTS_BRIDGE_REVISION,
  SAVED_OBJECTS_BRIDGE_VERSION,
  bridgeSavedObjects,
  ensureSavedObjectsBridge,
  getSavedObjectsBridgeStatus,
  resetSavedObjectsBridgeStatus,
  runSavedObjectsBridge,
} from './saved_objects_bridge';
import { MAPPING_VERSION } from './provision';

const NOW = new Date('2026-11-20T10:00:00.000Z');

function notFound() {
  // Boom-shaped, as SavedObjectsErrorHelpers.createGenericNotFoundError produces.
  return { isBoom: true, output: { statusCode: 404, payload: { message: 'Saved object not found' } }, message: 'Saved object not found' };
}

function mockLogger() {
  return { debug: jest.fn(), info: jest.fn(), warn: jest.fn(), error: jest.fn() } as any;
}

/** In-memory repository: `store` maps "type/id" to the stored object. */
function fakeRepository(initial: Record<string, any> = {}) {
  const store: Record<string, any> = { ...initial };
  const repo = {
    store,
    get: jest.fn(async (type: string, id: string) => {
      const key = `${type}/${id}`;
      if (!store[key]) throw notFound();
      return { type, id, attributes: store[key].attributes, references: store[key].references };
    }),
    create: jest.fn(async (type: string, attributes: any, options: any): Promise<any> => {
      const key = `${type}/${options.id}`;
      if (store[key] && !options.overwrite) throw { output: { statusCode: 409 }, message: 'conflict' };
      store[key] = { attributes, references: options.references };
      return { type, id: options.id, attributes };
    }),
  };
  return repo;
}

function fakeClient(storedVersion: number | null) {
  const client = {
    get: jest.fn(async ({ index, id }: any) => {
      if (storedVersion == null) throw { meta: { statusCode: 404 }, message: 'not found' };
      return { body: { _index: index, _id: id, _source: { document_type: 'saved_objects_bridge', version: storedVersion, updated_at: '2026-01-01T00:00:00.000Z', objects: {} } } };
    }),
    index: jest.fn(async (_params: any) => ({ body: { result: 'created' } })),
  };
  return client;
}

describe('saved objects bridge definitions', () => {
  test('version moves with MAPPING_VERSION and with the bridge revision, and differs from the first release value', () => {
    expect(SAVED_OBJECTS_BRIDGE_VERSION).toBe(MAPPING_VERSION * 1000 + SAVED_OBJECTS_BRIDGE_REVISION);
    expect(SAVED_OBJECTS_BRIDGE_REVISION).toBeGreaterThanOrEqual(2);
    // Installs that recorded the bare MAPPING_VERSION (first build of the bridge) must be rewritten.
    expect(SAVED_OBJECTS_BRIDGE_VERSION).not.toBe(MAPPING_VERSION);
  });

  test('defines two index patterns with fields and two saved searches referencing them', () => {
    const objects = bridgeSavedObjects();
    expect(objects.map((o) => `${o.type}/${o.id}`)).toEqual([
      'index-pattern/wam-alerts',
      'index-pattern/wam-cases',
      'search/wam-open-alerts',
      'search/wam-open-cases',
    ]);
    const [alerts, cases, openAlerts, openCases] = objects;
    expect(alerts.attributes).toEqual({ title: 'wazuh-alert-status-v2-read', timeFieldName: '@timestamp', fields: '[]' });
    expect(cases.attributes).toEqual({ title: 'wazuh-alert-manager-v2-cases-read', timeFieldName: 'created_at', fields: '[]' });
    expect(openAlerts.attributes.columns).toEqual(['agent.name', 'rule.description', WAM_ALERT_SEVERITY_COLUMN, 'status', 'assigned_to']);
    expect(openCases.attributes.columns).toEqual(['title', 'status', 'severity', 'assigned_to', 'created_at']);
    expect(openAlerts.attributes.sort).toEqual([['@timestamp', 'desc']]);
    const source = JSON.parse((openAlerts.attributes as any).kibanaSavedObjectMeta.searchSourceJSON);
    expect(source.query).toEqual({ query: 'status:open OR status:in_progress', language: 'kuery' });
    expect(source.indexRefName).toBe(INDEX_REF_NAME);
    expect(openAlerts.references).toEqual([{ name: INDEX_REF_NAME, type: 'index-pattern', id: 'wam-alerts' }]);
    expect(openCases.references).toEqual([{ name: INDEX_REF_NAME, type: 'index-pattern', id: 'wam-cases' }]);
    expect(openCases.attributes.sort).toEqual([['created_at', 'desc']]);
    // No object carries a non-mapped attribute: the `search` type mapping is strict.
    for (const object of objects) {
      expect(Object.keys(object.attributes)).not.toContain('wam_bridge_version');
    }
  });
});

describe('ensureSavedObjectsBridge', () => {
  test('creates all four objects on a fresh install and records the version in the meta index', async () => {
    const repo = fakeRepository();
    const client = fakeClient(null);
    const logger = mockLogger();

    const status = await ensureSavedObjectsBridge(client, repo, logger, { version: 15, now: () => NOW });

    expect(status.indexPatterns).toBe('ok');
    expect(status.version).toBe(15);
    expect(status.checkedAt).toBe(NOW.toISOString());
    expect(status.objects).toEqual({ 'wam-alerts': 'created', 'wam-cases': 'created', 'wam-open-alerts': 'created', 'wam-open-cases': 'created' });
    expect(repo.create).toHaveBeenCalledTimes(4);
    expect(repo.create).toHaveBeenCalledWith(
      'index-pattern',
      { title: 'wazuh-alert-status-v2-read', timeFieldName: '@timestamp', fields: '[]' },
      { id: 'wam-alerts', overwrite: true, references: [] }
    );
    expect(client.index).toHaveBeenCalledTimes(1);
    expect(client.index.mock.calls[0][0]).toMatchObject({
      index: META_INDEX,
      id: SAVED_OBJECTS_BRIDGE_DOC_ID,
      body: { document_type: 'saved_objects_bridge', version: 15, updated_at: NOW.toISOString() },
    });
    expect(logger.warn).not.toHaveBeenCalled();
    expect(status.message).toContain('global tenant');
  });

  test('never touches a default index pattern or uiSettings', async () => {
    const repo: any = fakeRepository();
    const client = fakeClient(null);
    await ensureSavedObjectsBridge(client, repo, mockLogger(), { version: 15 });
    const touched = repo.create.mock.calls.map((c: any[]) => c[0]);
    expect(touched.every((type: string) => type === 'index-pattern' || type === 'search')).toBe(true);
    expect(repo.create.mock.calls.some((c: any[]) => c[0] === 'config')).toBe(false);
  });

  test('leaves existing objects alone when the recorded version is current', async () => {
    const repo = fakeRepository({
      'index-pattern/wam-alerts': { attributes: { title: 'wazuh-alert-status-v2-read', fields: '[{"name":"custom"}]' } },
      'index-pattern/wam-cases': { attributes: { title: 'wazuh-alert-manager-v2-cases-read' } },
      'search/wam-open-alerts': { attributes: { title: 'edited by an analyst' } },
      'search/wam-open-cases': { attributes: { title: 'WAM open cases' } },
    });
    const client = fakeClient(15);

    const status = await ensureSavedObjectsBridge(client, repo, mockLogger(), { version: 15 });

    expect(status.indexPatterns).toBe('ok');
    expect(status.objects).toEqual({ 'wam-alerts': 'unchanged', 'wam-cases': 'unchanged', 'wam-open-alerts': 'unchanged', 'wam-open-cases': 'unchanged' });
    expect(repo.create).not.toHaveBeenCalled();
    expect(client.index).not.toHaveBeenCalled();
    expect(repo.store['search/wam-open-alerts'].attributes.title).toBe('edited by an analyst');
    expect(status.message).toContain('all current');
  });

  test('recreates only the missing object when the version is current', async () => {
    const repo = fakeRepository({
      'index-pattern/wam-alerts': { attributes: { title: 'wazuh-alert-status-v2-read' } },
      'index-pattern/wam-cases': { attributes: { title: 'wazuh-alert-manager-v2-cases-read' } },
      'search/wam-open-cases': { attributes: { title: 'WAM open cases' } },
    });
    const client = fakeClient(15);

    const status = await ensureSavedObjectsBridge(client, repo, mockLogger(), { version: 15 });

    expect(status.indexPatterns).toBe('ok');
    expect(status.objects['wam-open-alerts']).toBe('created');
    expect(status.objects['wam-alerts']).toBe('unchanged');
    expect(repo.create).toHaveBeenCalledTimes(1);
    expect(repo.create.mock.calls[0][2]).toMatchObject({ id: 'wam-open-alerts', overwrite: true });
    expect(client.index).toHaveBeenCalledTimes(1);
  });

  test('rewrites every object when MAPPING_VERSION moved past the recorded version', async () => {
    const repo = fakeRepository({
      'index-pattern/wam-alerts': { attributes: { title: 'old' } },
      'index-pattern/wam-cases': { attributes: { title: 'old' } },
      'search/wam-open-alerts': { attributes: { title: 'old' } },
      'search/wam-open-cases': { attributes: { title: 'old' } },
    });
    const client = fakeClient(14);

    const status = await ensureSavedObjectsBridge(client, repo, mockLogger(), { version: 15 });

    expect(status.indexPatterns).toBe('ok');
    expect(Object.values(status.objects)).toEqual(['updated', 'updated', 'updated', 'updated']);
    expect(repo.create).toHaveBeenCalledTimes(4);
    expect(repo.create.mock.calls.every((c) => c[2].overwrite === true)).toBe(true);
    expect(repo.store['index-pattern/wam-alerts'].attributes.title).toBe('wazuh-alert-status-v2-read');
    expect(client.index.mock.calls[0][0].body.version).toBe(15);
  });

  test('an unreadable (non-404) version record creates only missing objects, never overwrites, and reports error', async () => {
    const repo = fakeRepository({ 'index-pattern/wam-alerts': { attributes: { title: 'edited by an analyst' } } });
    const client = { get: jest.fn().mockRejectedValue(new Error('cluster unavailable')), index: jest.fn().mockResolvedValue({}) };
    const logger = mockLogger();

    const status = await ensureSavedObjectsBridge(client, repo, logger, { version: 15 });

    expect(status.indexPatterns).toBe('error');
    expect(status.message).toContain('version record');
    expect(status.message).toContain('cluster unavailable');
    expect(status.version).toBeNull();
    expect(status.objects).toEqual({ 'wam-alerts': 'unchanged', 'wam-cases': 'created', 'wam-open-alerts': 'created', 'wam-open-cases': 'created' });
    expect(repo.create).toHaveBeenCalledTimes(3);
    expect(repo.store['index-pattern/wam-alerts'].attributes.title).toBe('edited by an analyst');
    // The version is not advanced, so the next start re-checks.
    expect(client.index).not.toHaveBeenCalled();
    expect(logger.warn).toHaveBeenCalledTimes(1);
  });

  test('an absent version record (404 / meta index missing) still re-upserts everything', async () => {
    const repo = fakeRepository({ 'index-pattern/wam-alerts': { attributes: { title: 'old' } } });
    const client = { get: jest.fn().mockRejectedValue({ meta: { statusCode: 404 }, message: 'index_not_found_exception' }), index: jest.fn().mockResolvedValue({}) };

    const status = await ensureSavedObjectsBridge(client, repo, mockLogger(), { version: 15 });

    expect(status.indexPatterns).toBe('ok');
    expect(status.objects['wam-alerts']).toBe('updated');
    expect(repo.create).toHaveBeenCalledTimes(4);
    expect(client.index).toHaveBeenCalledTimes(1);
  });

  test('tolerates a failing object, continues with the others, and reports error without throwing', async () => {
    const repo = fakeRepository();
    repo.create.mockImplementation(async (type: string, attributes: any, options: any) => {
      if (options.id === 'wam-cases') throw { output: { statusCode: 403, payload: { message: 'no permissions for [indices:data/write/index] on .kibana' } }, message: 'forbidden' };
      repo.store[`${type}/${options.id}`] = { attributes, references: options.references };
      return {};
    });
    const client = fakeClient(null);
    const logger = mockLogger();

    const status = await ensureSavedObjectsBridge(client, repo, logger, { version: 15 });

    expect(status.indexPatterns).toBe('error');
    expect(status.objects).toEqual({ 'wam-alerts': 'created', 'wam-cases': 'error', 'wam-open-alerts': 'created', 'wam-open-cases': 'created' });
    expect(status.message).toContain('index-pattern/wam-cases: no permissions');
    expect(status.message).toContain('keeps running');
    expect(status.version).toBeNull();
    // The version record is not advanced while any object is missing, so the next start retries.
    expect(client.index).not.toHaveBeenCalled();
    expect(logger.warn).toHaveBeenCalledTimes(1);
    expect(logger.warn.mock.calls[0][0]).toContain('wam-cases');
  });

  test('a repository read failure that is not 404 is an error for that object only', async () => {
    const repo = fakeRepository();
    repo.get.mockImplementation(async (type: string, id: string) => {
      if (id === 'wam-open-alerts') throw new Error('.kibana index is red');
      throw notFound();
    });
    const status = await ensureSavedObjectsBridge(fakeClient(null), repo, mockLogger(), { version: 15 });
    expect(status.indexPatterns).toBe('error');
    expect(status.objects['wam-open-alerts']).toBe('error');
    expect(status.objects['wam-alerts']).toBe('created');
    expect(repo.create).toHaveBeenCalledTimes(3);
  });

  test('a failed version record write is reported as an error', async () => {
    const repo = fakeRepository();
    const client = { get: jest.fn().mockRejectedValue({ meta: { statusCode: 404 } }), index: jest.fn().mockRejectedValue(new Error('index_not_found_exception')) };
    const logger = mockLogger();
    const status = await ensureSavedObjectsBridge(client, repo, logger, { version: 15 });
    expect(status.indexPatterns).toBe('error');
    expect(status.message).toContain('version record');
    expect(status.message).toContain('index_not_found_exception');
    expect(Object.values(status.objects)).toEqual(['created', 'created', 'created', 'created']);
    expect(logger.warn).toHaveBeenCalledTimes(1);
  });

  test('writes the version record only to the plugin meta index (assertManagedWriteTarget)', async () => {
    const client = fakeClient(null);
    await ensureSavedObjectsBridge(client, fakeRepository(), mockLogger(), { version: 15 });
    expect(client.index.mock.calls[0][0].index).toBe('wazuh-alert-manager-v2-meta');
  });
});

describe('runSavedObjectsBridge and the status payload', () => {
  beforeEach(() => resetSavedObjectsBridgeStatus());

  test('initial status is skipped', () => {
    const status = getSavedObjectsBridgeStatus();
    expect(status.indexPatterns).toBe('skipped');
    expect(status.version).toBeNull();
    expect(status.objects).toEqual({});
  });

  test('publishes ok after a successful run', async () => {
    const repo = fakeRepository();
    const core = { savedObjects: { createInternalRepository: jest.fn(() => repo) } };
    const status = await runSavedObjectsBridge(core, fakeClient(null), mockLogger());
    expect(core.savedObjects.createInternalRepository).toHaveBeenCalledTimes(1);
    expect(status.indexPatterns).toBe('ok');
    expect(status.version).toBe(SAVED_OBJECTS_BRIDGE_VERSION);
    expect(getSavedObjectsBridgeStatus()).toBe(status);
  });

  test('reports skipped when core has no internal repository factory', async () => {
    const logger = mockLogger();
    const status = await runSavedObjectsBridge({ savedObjects: {} }, fakeClient(null), logger);
    expect(status.indexPatterns).toBe('skipped');
    expect(status.message).toContain('not provisioned');
    expect(logger.warn).toHaveBeenCalledTimes(1);
    expect(getSavedObjectsBridgeStatus().indexPatterns).toBe('skipped');
  });

  test('reports error and does not throw when the repository cannot be created (e.g. .kibana missing)', async () => {
    const logger = mockLogger();
    const core = {
      savedObjects: {
        createInternalRepository: () => {
          throw new Error('Saved objects index .kibana does not exist');
        },
      },
    };
    await expect(runSavedObjectsBridge(core, fakeClient(null), logger)).resolves.toMatchObject({ indexPatterns: 'error' });
    expect(getSavedObjectsBridgeStatus().message).toContain('.kibana does not exist');
    expect(getSavedObjectsBridgeStatus().message).toContain('keeps running');
    expect(logger.warn).toHaveBeenCalledTimes(1);
  });
});
