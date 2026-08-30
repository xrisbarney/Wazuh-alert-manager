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
import { ensureMappingAdditions, ensureRolloverFamily, isResourceAlreadyExists } from './provision';

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
      get: jest.fn().mockResolvedValue({ body: { _source: { version: 12 } } }),
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
      get: jest.fn().mockResolvedValue({ body: { _source: { version: 12 } } }),
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
