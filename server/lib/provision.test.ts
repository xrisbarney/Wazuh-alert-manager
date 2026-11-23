import {
  ACTIVITY_INITIAL_INDEX,
  ACTIVITY_READ_ALIAS,
  ACTIVITY_WRITE_ALIAS,
  ALERTS_INITIAL_INDEX,
  ALERTS_READ_ALIAS,
  ALERTS_WRITE_ALIAS,
  EVIDENCE_INITIAL_INDEX,
  EVIDENCE_READ_ALIAS,
  EVIDENCE_WRITE_ALIAS,
  META_INDEX,
  ATTACHMENTS_INDEX,
  TASK_LISTS_INDEX,
  NOTIFICATIONS_INDEX,
  CASES_READ_ALIAS,
} from '../../common';
import { ADDITIVE_MAPPING_TARGETS, ensureIndex, ensureMappingAdditions, ensureRolloverFamily, isResourceAlreadyExists, MAPPING_VERSION } from './provision';
import { alertStatusMapping, attachmentsMapping, casesMapping, metaMapping, notificationsMapping, taskListsMapping } from './mappings';

const logger: any = { info: jest.fn(), warn: jest.fn(), error: jest.fn() };

describe('rollover alias repair', () => {
  beforeEach(() => jest.clearAllMocks());

  function clientWithTopology({
    read = {},
    write = {},
    settings = {},
  }: {
    read?: Record<string, any>;
    write?: Record<string, any>;
    settings?: Record<string, any>;
  }) {
    return {
      indices: {
        existsAlias: jest.fn(({ name }: any) => ({
          body: Object.keys(name === ALERTS_READ_ALIAS ? read : write).length > 0,
        })),
        exists: jest.fn().mockResolvedValue({ body: true }),
        getAlias: jest.fn(({ name }: any) => ({ body: name === ALERTS_READ_ALIAS ? read : write })),
        getSettings: jest.fn(({ index }: any) => ({
          body: { [index]: { settings: settings[index] || { index: { blocks: { write: 'false' } } } } },
        })),
        updateAliases: jest.fn().mockResolvedValue({}),
      },
    } as any;
  }

  const readMember = () => ({ aliases: { [ALERTS_READ_ALIAS]: {} } });
  const writeMember = (isWriteIndex?: boolean) => ({
    aliases: {
      [ALERTS_WRITE_ALIAS]: isWriteIndex === undefined ? {} : { is_write_index: isWriteIndex },
    },
  });

  test('repairs a missing write alias to the latest post-rollover generation', async () => {
    const latest = 'wazuh-alert-status-v2-000002';
    const client = clientWithTopology({
      read: { [ALERTS_INITIAL_INDEX]: readMember(), [latest]: readMember() },
    });

    await ensureRolloverFamily(
      client,
      ALERTS_INITIAL_INDEX,
      ALERTS_READ_ALIAS,
      ALERTS_WRITE_ALIAS,
      {},
      logger
    );

    expect(client.indices.getSettings).toHaveBeenCalledWith({ index: latest });
    expect(client.indices.updateAliases).toHaveBeenCalledWith({
      body: {
        actions: [{
          add: {
            index: latest,
            alias: ALERTS_WRITE_ALIAS,
            is_write_index: true,
          },
        }],
      },
    });
  });

  test('repairs an existing initial index with neither alias', async () => {
    const client = clientWithTopology({});

    await ensureRolloverFamily(client, ALERTS_INITIAL_INDEX, ALERTS_READ_ALIAS, ALERTS_WRITE_ALIAS, {}, logger);

    expect(client.indices.updateAliases).toHaveBeenCalledWith({ body: { actions: [
      { add: { index: ALERTS_INITIAL_INDEX, alias: ALERTS_READ_ALIAS } },
      { add: { index: ALERTS_INITIAL_INDEX, alias: ALERTS_WRITE_ALIAS, is_write_index: true } },
    ] } });
  });

  test.each([
    ['an implicit writer', writeMember()],
    ['an explicitly disabled writer', writeMember(false)],
  ])('normalizes %s to one explicit writer', async (_label, member) => {
    const client = clientWithTopology({
      read: { [ALERTS_INITIAL_INDEX]: readMember() },
      write: { [ALERTS_INITIAL_INDEX]: member },
    });

    await ensureRolloverFamily(client, ALERTS_INITIAL_INDEX, ALERTS_READ_ALIAS, ALERTS_WRITE_ALIAS, {}, logger);

    expect(client.indices.updateAliases).toHaveBeenCalledWith({
      body: { actions: [{ add: { index: ALERTS_INITIAL_INDEX, alias: ALERTS_WRITE_ALIAS, is_write_index: true } }] },
    });
  });

  test('repairs multiple write-alias members with no writer to the highest generation', async () => {
    const latest = 'wazuh-alert-status-v2-000002';
    const client = clientWithTopology({
      read: { [ALERTS_INITIAL_INDEX]: readMember(), [latest]: readMember() },
      write: { [ALERTS_INITIAL_INDEX]: writeMember(), [latest]: writeMember() },
    });

    await ensureRolloverFamily(client, ALERTS_INITIAL_INDEX, ALERTS_READ_ALIAS, ALERTS_WRITE_ALIAS, {}, logger);

    expect(client.indices.updateAliases).toHaveBeenCalledWith({ body: { actions: [
      { remove: { index: ALERTS_INITIAL_INDEX, alias: ALERTS_WRITE_ALIAS } },
      { add: { index: latest, alias: ALERTS_WRITE_ALIAS, is_write_index: true } },
    ] } });
  });

  test('adds a valid writer missing from the read alias without removing read history', async () => {
    const latest = 'wazuh-alert-status-v2-000002';
    const client = clientWithTopology({
      read: { [ALERTS_INITIAL_INDEX]: readMember() },
      write: { [latest]: writeMember(true) },
    });

    await ensureRolloverFamily(client, ALERTS_INITIAL_INDEX, ALERTS_READ_ALIAS, ALERTS_WRITE_ALIAS, {}, logger);

    expect(client.indices.updateAliases).toHaveBeenCalledWith({
      body: { actions: [{ add: { index: latest, alias: ALERTS_READ_ALIAS } }] },
    });
  });

  test('atomically replaces a stale writer with the highest read generation', async () => {
    const latest = 'wazuh-alert-status-v2-000002';
    const client = clientWithTopology({
      read: { [ALERTS_INITIAL_INDEX]: readMember(), [latest]: readMember() },
      write: { [ALERTS_INITIAL_INDEX]: writeMember(true) },
    });

    await ensureRolloverFamily(client, ALERTS_INITIAL_INDEX, ALERTS_READ_ALIAS, ALERTS_WRITE_ALIAS, {}, logger);

    expect(client.indices.updateAliases).toHaveBeenCalledWith({ body: { actions: [
      { remove: { index: ALERTS_INITIAL_INDEX, alias: ALERTS_WRITE_ALIAS } },
      { add: { index: latest, alias: ALERTS_WRITE_ALIAS, is_write_index: true } },
    ] } });
  });

  test('leaves a valid sole explicit writer unchanged after validation', async () => {
    const client = clientWithTopology({
      read: { [ALERTS_INITIAL_INDEX]: readMember() },
      write: { [ALERTS_INITIAL_INDEX]: writeMember(true) },
    });

    await ensureRolloverFamily(client, ALERTS_INITIAL_INDEX, ALERTS_READ_ALIAS, ALERTS_WRITE_ALIAS, {}, logger);

    expect(client.indices.getSettings).toHaveBeenCalledWith({ index: ALERTS_INITIAL_INDEX });
    expect(client.indices.updateAliases).not.toHaveBeenCalled();
  });

  test('accepts the post-retirement topology and keeps the latest numeric generation as writer', async () => {
    const latest = 'wazuh-alert-status-v2-000002';
    const carry = 'wazuh-alert-status-v2-carry-20260829123456789';
    const client = clientWithTopology({
      read: { [latest]: readMember(), [carry]: readMember() },
      write: { [latest]: writeMember(true) },
    });

    await ensureRolloverFamily(client, ALERTS_INITIAL_INDEX, ALERTS_READ_ALIAS, ALERTS_WRITE_ALIAS, {}, logger);

    expect(client.indices.getSettings).toHaveBeenCalledWith({ index: latest });
    expect(client.indices.getSettings).not.toHaveBeenCalledWith({ index: carry });
    expect(client.indices.updateAliases).not.toHaveBeenCalled();
  });

  test('fails closed when a carry member is attached to the write alias', async () => {
    const carry = 'wazuh-alert-status-v2-carry-20260829123456789';
    const client = clientWithTopology({
      read: { [ALERTS_INITIAL_INDEX]: readMember(), [carry]: readMember() },
      write: { [carry]: writeMember(true) },
    });

    await expect(ensureRolloverFamily(
      client, ALERTS_INITIAL_INDEX, ALERTS_READ_ALIAS, ALERTS_WRITE_ALIAS, {}, logger
    )).rejects.toThrow('rollover membership is ambiguous');
    expect(client.indices.getSettings).not.toHaveBeenCalled();
    expect(client.indices.updateAliases).not.toHaveBeenCalled();
  });

  test.each([
    [ACTIVITY_INITIAL_INDEX, ACTIVITY_READ_ALIAS, ACTIVITY_WRITE_ALIAS],
    [EVIDENCE_INITIAL_INDEX, EVIDENCE_READ_ALIAS, EVIDENCE_WRITE_ALIAS],
  ])('does not allow auxiliary carry members for the %s rollover family', async (initial, readAlias, writeAlias) => {
    const carry = initial.replace(/\d+$/, 'carry-20260829123456789');
    const client: any = {
      indices: {
        existsAlias: jest.fn(({ name }: any) => ({ body: name === readAlias })),
        exists: jest.fn().mockResolvedValue({ body: true }),
        getAlias: jest.fn(({ name }: any) => ({
          body: name === readAlias ? { [initial]: {}, [carry]: {} } : {},
        })),
        getSettings: jest.fn(),
        updateAliases: jest.fn(),
      },
    };

    await expect(ensureRolloverFamily(
      client, initial, readAlias, writeAlias, {}, logger
    )).rejects.toThrow('rollover membership is ambiguous');
    expect(client.indices.getSettings).not.toHaveBeenCalled();
    expect(client.indices.updateAliases).not.toHaveBeenCalled();
  });

  test('fails instead of falling back when the latest generation is blocked', async () => {
    const latest = 'wazuh-alert-status-v2-000002';
    const client = clientWithTopology({
      read: { [ALERTS_INITIAL_INDEX]: readMember(), [latest]: readMember() },
      settings: { [latest]: { index: { blocks: { write: 'true' } } } },
    });

    await expect(ensureRolloverFamily(
      client,
      ALERTS_INITIAL_INDEX,
      ALERTS_READ_ALIAS,
      ALERTS_WRITE_ALIAS,
      {},
      logger
    )).rejects.toThrow('write-blocked or retired');

    expect(client.indices.updateAliases).not.toHaveBeenCalled();
  });

  test('fails when the selected generation is read-only or retired', async () => {
    const client = clientWithTopology({
      read: { [ALERTS_INITIAL_INDEX]: readMember() },
      settings: { [ALERTS_INITIAL_INDEX]: { 'index.blocks.read_only_allow_delete': 'true' } },
    });

    await expect(ensureRolloverFamily(
      client, ALERTS_INITIAL_INDEX, ALERTS_READ_ALIAS, ALERTS_WRITE_ALIAS, {}, logger
    )).rejects.toThrow('write-blocked or retired');
    expect(client.indices.updateAliases).not.toHaveBeenCalled();
  });

  test('fails closed when selected-generation settings are missing', async () => {
    const client = clientWithTopology({ read: { [ALERTS_INITIAL_INDEX]: readMember() } });
    client.indices.getSettings.mockResolvedValue({ body: {} });

    await expect(ensureRolloverFamily(
      client, ALERTS_INITIAL_INDEX, ALERTS_READ_ALIAS, ALERTS_WRITE_ALIAS, {}, logger
    )).rejects.toThrow('no settings are available');
    expect(client.indices.updateAliases).not.toHaveBeenCalled();
  });

  test('fails closed when multiple explicit writers are configured', async () => {
    const latest = 'wazuh-alert-status-v2-000002';
    const client = clientWithTopology({
      read: { [ALERTS_INITIAL_INDEX]: readMember(), [latest]: readMember() },
      write: { [ALERTS_INITIAL_INDEX]: writeMember(true), [latest]: writeMember(true) },
    });

    await expect(ensureRolloverFamily(
      client, ALERTS_INITIAL_INDEX, ALERTS_READ_ALIAS, ALERTS_WRITE_ALIAS, {}, logger
    )).rejects.toThrow('multiple explicit write generations');
    expect(client.indices.getSettings).not.toHaveBeenCalled();
    expect(client.indices.updateAliases).not.toHaveBeenCalled();
  });

  test('fails when read alias membership cannot identify one latest generation', async () => {
    const unsafe = 'wazuh-alert-status-v2-current';
    const client = clientWithTopology({ read: {
      [ALERTS_INITIAL_INDEX]: readMember(),
      [unsafe]: readMember(),
    } });

    await expect(ensureRolloverFamily(
      client,
      ALERTS_INITIAL_INDEX,
      ALERTS_READ_ALIAS,
      ALERTS_WRITE_ALIAS,
      {},
      logger
    )).rejects.toThrow('membership is ambiguous');

    expect(client.indices.getSettings).not.toHaveBeenCalled();
    expect(client.indices.updateAliases).not.toHaveBeenCalled();
  });

  test('fails when the write alias includes an unsafe namespace member', async () => {
    const unsafe = 'wazuh-alert-manager-v2-cases';
    const client = clientWithTopology({
      read: { [ALERTS_INITIAL_INDEX]: readMember() },
      write: { [unsafe]: writeMember() },
    });

    await expect(ensureRolloverFamily(
      client, ALERTS_INITIAL_INDEX, ALERTS_READ_ALIAS, ALERTS_WRITE_ALIAS, {}, logger
    )).rejects.toThrow('rollover membership is ambiguous');
    expect(client.indices.updateAliases).not.toHaveBeenCalled();
  });

  test('fails when two names represent the same numeric generation', async () => {
    const client = clientWithTopology({ read: {
      'wazuh-alert-status-v2-000001': readMember(),
      'wazuh-alert-status-v2-0000001': readMember(),
      'wazuh-alert-status-v2-000002': readMember(),
    } });

    await expect(ensureRolloverFamily(
      client, ALERTS_INITIAL_INDEX, ALERTS_READ_ALIAS, ALERTS_WRITE_ALIAS, {}, logger
    )).rejects.toThrow('rollover membership is ambiguous');
    expect(client.indices.updateAliases).not.toHaveBeenCalled();
  });
});

describe('mapping upgrades', () => {
  beforeEach(() => jest.clearAllMocks());

  test('applies additions through alert and activity read aliases', async () => {
    const client: any = {
      get: jest.fn().mockRejectedValue({ meta: { statusCode: 404 } }),
      index: jest.fn().mockResolvedValue({}),
      indices: {
        exists: jest.fn().mockResolvedValue({ body: true }),
        putMapping: jest.fn().mockResolvedValue({}),
        getMapping: jest.fn(({ index }: any) => {
          const request = client.indices.putMapping.mock.calls.find(([call]: any[]) => call.index === index)?.[0];
          return { body: { physical: { mappings: request.body } } };
        }),
      },
    };

    await ensureMappingAdditions(client, logger);

    const targets = client.indices.putMapping.mock.calls.map(([request]: any[]) => request.index);
    expect(targets).toEqual(expect.arrayContaining([ALERTS_READ_ALIAS, ACTIVITY_READ_ALIAS, ATTACHMENTS_INDEX]));
    expect(client.index).toHaveBeenCalledWith(expect.objectContaining({ index: META_INDEX, id: 'mapping_version' }));
  });

  test('the attachments index is a managed singleton whose file body is stored but never indexed', async () => {
    expect(ATTACHMENTS_INDEX).toBe('wazuh-alert-manager-v2-attachments');
    expect(attachmentsMapping.dynamic).toBe(false);
    expect(attachmentsMapping.properties).toMatchObject({
      case_id: { type: 'keyword' },
      kind: { type: 'keyword' },
      content_type: { type: 'keyword' },
      size: { type: 'long' },
      sha256: { type: 'keyword' },
      data: { type: 'object', enabled: false },
      created_by: { type: 'keyword' },
      created_at: { type: 'date' },
    });
    const client: any = {
      indices: {
        exists: jest.fn().mockResolvedValue({ body: false }),
        create: jest.fn().mockResolvedValue({}),
      },
    };
    await ensureIndex(client, ATTACHMENTS_INDEX, attachmentsMapping, logger);
    expect(client.indices.create).toHaveBeenCalledWith(expect.objectContaining({
      index: ATTACHMENTS_INDEX,
      body: expect.objectContaining({ mappings: attachmentsMapping }),
    }));
  });

  test('fails startup and does not advance the mapping version after a partial failure', async () => {
    const client: any = {
      get: jest.fn().mockRejectedValue({ meta: { statusCode: 404 } }),
      index: jest.fn(),
      indices: {
        exists: jest.fn().mockResolvedValue({ body: true }),
        putMapping: jest.fn().mockRejectedValueOnce(new Error('blocked')).mockResolvedValue({}),
        getMapping: jest.fn(),
      },
    };

    await expect(ensureMappingAdditions(client, logger)).rejects.toThrow('blocked');

    expect(client.index).not.toHaveBeenCalled();
  });

  test('steps 2.1 to 2.4 and 1.4 bumped the mapping version so upgraded installs receive the case task, task list, activity event_uid, disposition and rule notify fields', async () => {
    expect(MAPPING_VERSION).toBe(25);
    const client: any = {
      get: jest.fn().mockResolvedValue({ body: { _source: { version: MAPPING_VERSION - 1 } } }),
      index: jest.fn().mockResolvedValue({}),
      indices: {
        exists: jest.fn().mockResolvedValue({ body: true }),
        putMapping: jest.fn().mockResolvedValue({}),
        getMapping: jest.fn(({ index }: any) => {
          const request = client.indices.putMapping.mock.calls.find(([call]: any[]) => call.index === index)?.[0];
          return { body: { physical: { mappings: request.body } } };
        }),
      },
    };

    await ensureMappingAdditions(client, logger);

    const cases = client.indices.putMapping.mock.calls.find(([call]: any[]) => call.index === CASES_READ_ALIAS)?.[0];
    expect(cases).toBeDefined();
    expect(cases.body.properties.tasks).toMatchObject({ type: 'nested', dynamic: false });
    expect(cases.body.properties.task_counts.properties).toEqual({ open: { type: 'long' }, done: { type: 'long' } });
    expect(cases.body.properties.applied_task_lists).toBeDefined();
    expect(cases.body.properties.disposition).toEqual({ type: 'keyword' });
    expect(cases.body.properties.closure_reason.type).toBe('text');
    const alerts = client.indices.putMapping.mock.calls.find(([call]: any[]) => call.index === ALERTS_READ_ALIAS)?.[0];
    expect(alerts.body.properties.disposition).toEqual({ type: 'keyword' });
    expect(alerts.body.properties.closure_reason.type).toBe('text');
    expect(client.index).toHaveBeenCalledWith(
      expect.objectContaining({ index: META_INDEX, id: 'mapping_version', body: expect.objectContaining({ version: MAPPING_VERSION }) })
    );
  });

  test('accepts an object field whose stored mapping omits the implicit `type: object` (as get-mapping returns it)', async () => {
    // OpenSearch's get-mapping drops `type: "object"` from an object field
    // that has `properties`; the verifier must not read that as a type change
    // (step 2.5 found the cases index failing on `applied_task_lists`).
    const stripObjectTypes = (properties: any): any =>
      Object.fromEntries(
        Object.entries<any>(properties || {}).map(([name, definition]) => {
          const copy: any = { ...definition };
          if (copy.properties) {
            copy.properties = stripObjectTypes(copy.properties);
            if (copy.type === 'object') delete copy.type;
          }
          return [name, copy];
        })
      );
    const client: any = {
      get: jest.fn().mockResolvedValue({ body: { _source: { version: MAPPING_VERSION } } }),
      index: jest.fn(),
      indices: {
        exists: jest.fn().mockResolvedValue({ body: true }),
        putMapping: jest.fn(),
        getMapping: jest.fn(async ({ index }: any) => {
          const expected = ADDITIVE_MAPPING_TARGETS.find(([name]) => name === index)?.[1];
          return { body: { physical: { mappings: { dynamic: expected.dynamic, properties: stripObjectTypes(expected.properties) } } } };
        }),
      },
    };

    await expect(ensureMappingAdditions(client, logger)).resolves.toBeUndefined();
    expect(client.indices.putMapping).not.toHaveBeenCalled();
  });

  test('fails startup when a required mapped field is absent', async () => {
    const client: any = {
      get: jest.fn().mockResolvedValue({ body: { _source: { version: MAPPING_VERSION } } }),
      index: jest.fn(),
      indices: {
        exists: jest.fn().mockResolvedValue({ body: true }),
        putMapping: jest.fn(),
        getMapping: jest.fn().mockResolvedValue({ body: { physical: { mappings: { dynamic: false, properties: {} } } } }),
      },
    };

    await expect(ensureMappingAdditions(client, logger)).rejects.toThrow('required mapping field');
    expect(client.indices.putMapping).not.toHaveBeenCalled();
  });

  test('fails startup when an existing generation allows dynamic fields', async () => {
    const client: any = {
      get: jest.fn().mockResolvedValue({ body: { _source: { version: MAPPING_VERSION } } }),
      index: jest.fn(),
      indices: {
        exists: jest.fn().mockResolvedValue({ body: true }),
        putMapping: jest.fn(),
        getMapping: jest.fn().mockResolvedValue({ body: { physical: { mappings: { dynamic: true, properties: {} } } } }),
      },
    };

    await expect(ensureMappingAdditions(client, logger)).rejects.toThrow('must set dynamic to false');
    expect(client.indices.putMapping).not.toHaveBeenCalled();
  });

  test('only recognizes the exact concurrent-create error', () => {
    expect(isResourceAlreadyExists({
      meta: { statusCode: 400, body: { error: { type: 'resource_already_exists_exception' } } },
    })).toBe(true);
    expect(isResourceAlreadyExists({
      meta: { statusCode: 400, body: { error: { type: 'mapper_parsing_exception' } } },
    })).toBe(false);
    expect(isResourceAlreadyExists({ meta: { statusCode: 400 } })).toBe(false);
  });
});

describe('provisioning when the cluster blocks the create-index API (Wazuh 5.0)', () => {
  const blocked = () => {
    const error: any = new Error('index_create_block_exception: blocked by: [FORBIDDEN/10/cluster create-index blocked (api)];');
    error.meta = { statusCode: 403, body: { error: { type: 'index_create_block_exception' } } };
    return error;
  };

  function blockedClient() {
    const created = new Set<string>();
    return {
      created,
      indices: {
        exists: jest.fn(async ({ index }: any) => ({ body: created.has(index) })),
        existsAlias: jest.fn(async () => ({ body: false })),
        getAlias: jest.fn(async () => ({ body: {} })),
        create: jest.fn(async () => { throw blocked(); }),
        putIndexTemplate: jest.fn(async () => ({ body: { acknowledged: true } })),
        deleteIndexTemplate: jest.fn(async () => ({ body: { acknowledged: true } })),
        updateAliases: jest.fn(async () => ({})),
        getMapping: jest.fn(async ({ index }: any) => ({ body: { [index]: { mappings: { dynamic: false, properties: alertStatusMapping.properties } } } })),
        putMapping: jest.fn(async () => ({})),
      },
      index: jest.fn(async ({ index }: any) => { created.add(index); return { body: { result: 'created' } }; }),
      delete: jest.fn(async () => ({ body: { result: 'deleted' } })),
      get: jest.fn().mockRejectedValue({ meta: { statusCode: 404 } }),
    } as any;
  }

  test('a rollover family is bootstrapped through a temporary plugin-owned template and one deleted write', async () => {
    const client = blockedClient();
    await ensureRolloverFamily(client, 'wazuh-alert-status-v2-000001', 'wazuh-alert-status-v2-read', 'wazuh-alert-status-v2-write', alertStatusMapping, logger);

    expect(client.indices.create).toHaveBeenCalledTimes(1);
    const template = client.indices.putIndexTemplate.mock.calls[0][0];
    expect(template.name).toBe('wazuh-alert-manager-v2-template-wazuh-alert-status-v2-000001');
    expect(template.body.index_patterns).toEqual(['wazuh-alert-status-v2-000001']);
    expect(template.body.template.mappings).toBe(alertStatusMapping);
    expect(template.body.template.aliases).toEqual({
      'wazuh-alert-status-v2-read': {},
      'wazuh-alert-status-v2-write': { is_write_index: true },
    });
    expect(client.index).toHaveBeenCalledWith(expect.objectContaining({ index: 'wazuh-alert-status-v2-000001', id: '_wam_bootstrap', refresh: true }));
    expect(client.delete).toHaveBeenCalledWith(expect.objectContaining({ index: 'wazuh-alert-status-v2-000001', id: '_wam_bootstrap' }));
    expect(client.indices.deleteIndexTemplate).toHaveBeenCalledWith({ name: template.name });
    expect(client.indices.updateAliases).not.toHaveBeenCalled();
  });

  test('a singleton index is bootstrapped the same way and never writes outside plugin prefixes', async () => {
    const client = blockedClient();
    await ensureIndex(client, 'wazuh-alert-manager-v2-meta', metaMapping, logger);
    expect(client.indices.putIndexTemplate.mock.calls[0][0].name).toBe('wazuh-alert-manager-v2-template-wazuh-alert-manager-v2-meta');
    for (const call of [...client.index.mock.calls, ...client.delete.mock.calls]) {
      expect(call[0].index).toMatch(/^wazuh-alert-(status|manager)-v2-/);
    }
  });

  test('any other create failure is still fatal', async () => {
    const client = blockedClient();
    client.indices.create = jest.fn(async () => { const e: any = new Error('boom'); e.meta = { statusCode: 500, body: { error: { type: 'some_other_exception' } } }; throw e; });
    await expect(ensureIndex(client, 'wazuh-alert-manager-v2-meta', metaMapping, logger)).rejects.toThrow('boom');
    expect(client.indices.putIndexTemplate).not.toHaveBeenCalled();
  });
});

describe('task lists index (step 2.2)', () => {
  test('is a managed singleton created like the attachments index and part of the additive mapping targets', async () => {
    expect(TASK_LISTS_INDEX).toBe('wazuh-alert-manager-v2-task-lists');
    const client: any = {
      indices: {
        exists: jest.fn().mockResolvedValue({ body: false }),
        create: jest.fn().mockResolvedValue({}),
      },
    };
    await ensureIndex(client, TASK_LISTS_INDEX, taskListsMapping, logger);
    expect(client.indices.create).toHaveBeenCalledWith(expect.objectContaining({
      index: TASK_LISTS_INDEX,
      body: expect.objectContaining({ mappings: taskListsMapping }),
    }));

    const additive: any = {
      get: jest.fn().mockRejectedValue({ meta: { statusCode: 404 } }),
      index: jest.fn().mockResolvedValue({}),
      indices: {
        exists: jest.fn().mockResolvedValue({ body: true }),
        putMapping: jest.fn().mockResolvedValue({}),
        getMapping: jest.fn(({ index }: any) => {
          const request = additive.indices.putMapping.mock.calls.find(([call]: any[]) => call.index === index)?.[0];
          return { body: { physical: { mappings: request.body } } };
        }),
      },
    };
    await ensureMappingAdditions(additive, logger);
    const targets = additive.indices.putMapping.mock.calls.map(([request]: any[]) => request.index);
    expect(targets).toContain(TASK_LISTS_INDEX);
    const cases = additive.indices.putMapping.mock.calls.find(([request]: any[]) => request.index === CASES_READ_ALIAS)[0];
    expect(cases.body.properties.applied_task_lists).toEqual(casesMapping.properties.applied_task_lists);
  });
});

describe('notification outbox index (step 1.2)', () => {
  test('is a managed singleton under the plugin prefix, created like the task lists index and part of the additive mapping targets', async () => {
    expect(NOTIFICATIONS_INDEX).toBe('wazuh-alert-manager-v2-notifications');
    expect(ADDITIVE_MAPPING_TARGETS.find(([index]) => index === NOTIFICATIONS_INDEX)?.[1]).toBe(notificationsMapping);
    const client: any = {
      indices: {
        exists: jest.fn().mockResolvedValue({ body: false }),
        create: jest.fn().mockResolvedValue({}),
      },
    };
    await ensureIndex(client, NOTIFICATIONS_INDEX, notificationsMapping, logger);
    expect(client.indices.create).toHaveBeenCalledWith(expect.objectContaining({
      index: NOTIFICATIONS_INDEX,
      body: expect.objectContaining({ mappings: notificationsMapping }),
    }));

    const additive: any = {
      get: jest.fn().mockRejectedValue({ meta: { statusCode: 404 } }),
      index: jest.fn().mockResolvedValue({}),
      indices: {
        exists: jest.fn().mockResolvedValue({ body: true }),
        putMapping: jest.fn().mockResolvedValue({}),
        getMapping: jest.fn(({ index }: any) => {
          const request = additive.indices.putMapping.mock.calls.find(([call]: any[]) => call.index === index)?.[0];
          return { body: { physical: { mappings: request.body } } };
        }),
      },
    };
    await ensureMappingAdditions(additive, logger);
    const targets = additive.indices.putMapping.mock.calls.map(([request]: any[]) => request.index);
    expect(targets).toContain(NOTIFICATIONS_INDEX);
    const outbox = additive.indices.putMapping.mock.calls.find(([request]: any[]) => request.index === NOTIFICATIONS_INDEX)[0];
    expect(outbox.body.properties.payload).toEqual({ type: 'object', enabled: false });
  });
});
