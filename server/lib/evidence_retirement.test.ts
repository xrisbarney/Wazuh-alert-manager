import { purgeRetiredEvidenceIndex, retireEvidenceIndex } from './evidence_retirement';
import { EVIDENCE_READ_ALIAS, EVIDENCE_WRITE_ALIAS, META_INDEX } from '../../common';

const oldIndex = 'wazuh-alert-manager-v2-evidence-000001';
const writer = 'wazuh-alert-manager-v2-evidence-000002';

function aliasBody(write = false) {
  return { body: { [oldIndex]: { aliases: { [write ? EVIDENCE_WRITE_ALIAS : EVIDENCE_READ_ALIAS]: write ? { is_write_index: false } : {} } },
    ...(write ? { [writer]: { aliases: { [EVIDENCE_WRITE_ALIAS]: { is_write_index: true } } } } : {}) } };
}

describe('evidence generation retirement', () => {
  test('carries every relationship before detaching and recording the source', async () => {
    const client: any = {
      indices: {
        getAlias: jest.fn(async ({ name }: any) => aliasBody(name === EVIDENCE_WRITE_ALIAS)),
        refresh: jest.fn(async () => ({})), putSettings: jest.fn(async () => ({})),
        updateAliases: jest.fn(async () => ({})),
      },
      search: jest.fn(async () => ({ body: { _scroll_id: 's', hits: { hits: [
        { _id: 'e1', _source: { case_id: 'c', alert_id: 'a', hold_since: '2026-01-01' } },
      ] } } })),
      clearScroll: jest.fn(async () => ({})),
      bulk: jest.fn(async () => ({ body: { items: [{ create: { status: 201 } }] } })),
      index: jest.fn(async () => ({})),
    };
    const result = await retireEvidenceIndex(client, oldIndex, 'admin');
    expect(result).toEqual(expect.objectContaining({ copied: 1, already_current: 0, status: 'completed' }));
    expect(client.bulk).toHaveBeenCalledWith(expect.objectContaining({ body: expect.arrayContaining([
      expect.objectContaining({ create: expect.objectContaining({ _index: EVIDENCE_WRITE_ALIAS, _id: 'e1' }) }),
    ]) }));
    expect(client.indices.updateAliases).toHaveBeenCalledWith({ body: { actions: [
      { remove: { index: oldIndex, alias: EVIDENCE_READ_ALIAS } },
      { remove: { index: oldIndex, alias: EVIDENCE_WRITE_ALIAS } },
    ] } });
    expect(client.index).toHaveBeenCalledWith(expect.objectContaining({ index: META_INDEX, id: `evidence-retirement:${oldIndex}` }));
  });

  test('refuses to retire the current writer', async () => {
    const client: any = { indices: { getAlias: jest.fn(async ({ name }: any) => ({ body: {
      [oldIndex]: { aliases: { [name]: name === EVIDENCE_WRITE_ALIAS ? { is_write_index: true } : {} } },
    } })) } };
    await expect(retireEvidenceIndex(client, oldIndex, 'admin')).rejects.toThrow(/current evidence write/i);
  });

  test('purge requires a detached, write-blocked generation with a completed record', async () => {
    const client: any = {
      indices: {
        getAlias: jest.fn(async () => ({ body: {} })),
        getSettings: jest.fn(async () => ({ body: { [oldIndex]: { settings: { index: { blocks: { write: 'true' } } } } } })),
        delete: jest.fn(async () => ({})),
      },
      get: jest.fn(async () => ({ body: { _source: { status: 'completed', retiring_index: oldIndex } } })),
      index: jest.fn(async () => ({})),
    };
    await expect(purgeRetiredEvidenceIndex(client, oldIndex, 'admin')).resolves.toEqual({ index: oldIndex, purged: true });
    expect(client.indices.delete).toHaveBeenCalledWith({ index: oldIndex });
  });
});
