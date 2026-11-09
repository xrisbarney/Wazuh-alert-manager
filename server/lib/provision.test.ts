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
} from '../../common';
import { ensureIndex, ensureMappingAdditions, ensureRolloverFamily, isResourceAlreadyExists } from './provision';
import { alertStatusMapping, metaMapping } from './mappings';

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
    expect(targets).toEqual(expect.arrayContaining([ALERTS_READ_ALIAS, ACTIVITY_READ_ALIAS]));
    expect(client.index).toHaveBeenCalledWith(expect.objectContaining({ index: META_INDEX, id: 'mapping_version' }));
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

  test('fails startup when a required mapped field is absent', async () => {
    const client: any = {
      get: jest.fn().mockResolvedValue({ body: { _source: { version: 13 } } }),
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
      get: jest.fn().mockResolvedValue({ body: { _source: { version: 13 } } }),
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
