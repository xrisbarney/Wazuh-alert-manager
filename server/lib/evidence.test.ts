import {
  buildEvidenceDocument,
  buildEvidenceSnapshot,
  archiveEvidenceRelationship,
  backfillCaseEvidence,
  evidenceId,
  getEvidence,
  isActiveCaseStatus,
  listCaseEvidence,
  listCaseEvidenceWithLegacy,
  removeEvidenceRelationship,
  resolveArchivedEvidence,
  shouldCarryAlert,
  setEvidenceHold,
  scanArchiveEvidence,
  upsertEvidenceRelationship,
} from './evidence';
import { resolveCaseAlerts } from './index_resolution';
import { buildAttackGraph } from './attack_graph';
import { CASES_INDEX } from '../../common';

const alert = (overrides: any = {}) => ({
  status: 'open',
  '@timestamp': '2026-08-28T10:00:00.000Z',
  assigned_to: 'analyst',
  agent: { id: '001', name: 'host-1', ip: '10.0.0.2' },
  rule: { id: '5502', level: 7, description: 'brute force', mitre: { id: 'T1110', technique: 'Brute Force', tactic: 'Credential Access' } },
  data: { srcip: '10.0.0.1', dstip: '10.0.0.9', srcuser: 'alice', dstuser: 'root', process: { name: '/bin/sh' } },
  ...overrides,
});

describe('evidenceId', () => {
  test('is stable and collision-safe across case and alert', () => {
    expect(evidenceId('c1', 'a1')).toBe(evidenceId('c1', 'a1'));
    expect(evidenceId('c1', 'a1')).not.toBe(evidenceId('c2', 'a1'));
    expect(evidenceId('c1', 'a1')).not.toBe(evidenceId('c1', 'a2'));
  });
});

describe('buildEvidenceSnapshot', () => {
  test('keeps only the bounded fields needed for case context and attack path', () => {
    const snap = buildEvidenceSnapshot(alert({ full_log: 'secret', history: [], ai_analysis: { text: 'x' } }));
    expect(snap.status).toBe('open');
    expect(snap.agent.name).toBe('host-1');
    expect(snap.rule.mitre.tactic).toEqual(['Credential Access']);
    expect(snap.data.srcuser).toBe('alice');
    expect(snap.data.process.name).toBe('/bin/sh');
    expect(snap).not.toHaveProperty('full_log');
    expect(snap).not.toHaveProperty('history');
    expect(snap).not.toHaveProperty('ai_analysis');
  });

  test('coerces scalar and array MITRE fields without throwing', () => {
    const scalar = buildEvidenceSnapshot(
      alert({ rule: { id: 'x', level: 4, mitre: { id: 'T1003', technique: 'Dump', tactic: 'Credential Access' } } })
    );
    expect(scalar.rule.mitre.id).toEqual(['T1003']);
    const array = buildEvidenceSnapshot(
      alert({ rule: { id: 'x', level: 4, mitre: { id: ['T1003', 'T1021'], technique: ['Dump', 'RS'], tactic: ['Credential Access', 'Lateral Movement'] } } })
    );
    expect(array.rule.mitre.id).toEqual(['T1003', 'T1021']);
  });

  test('tolerates missing or string-shaped data', () => {
    expect(() => buildEvidenceSnapshot({ data: 'plain string' })).not.toThrow();
    expect(buildEvidenceSnapshot({}).status).toBeNull();
  });
});

describe('buildEvidenceDocument', () => {
  test('assembles a bounded relationship with provenance and archive location', () => {
    const doc = buildEvidenceDocument({
      caseId: 'c1',
      alertId: 'a1',
      alertSource: alert(),
      archiveIndex: 'wazuh-alert-status-v2-000001',
      sourceIndex: 'wazuh-alerts-4.x-2026.08.28',
      sourceId: 'abc',
      holdReason: 'legal hold',
    });
    expect(doc.case_id).toBe('c1');
    expect(doc.alert_id).toBe('a1');
    expect(doc.relationship_state).toBe('linked');
    expect(doc.archive_index).toBe('wazuh-alert-status-v2-000001');
    expect(doc.source_index).toBe('wazuh-alerts-4.x-2026.08.28');
    expect(doc.snapshot.rule.description).toBe('brute force');
  });
});

describe('resolveArchivedEvidence', () => {
  test('reads only from a trusted managed archive location', async () => {
    const client = { get: jest.fn(async () => ({ body: { _source: { status: 'closed' } } })) };
    const full = await resolveArchivedEvidence(client, {
      archive_index: 'wazuh-alert-status-v2-000001',
      archive_id: 'a1',
    });
    expect(full.status).toBe('closed');
    expect(client.get).toHaveBeenCalledWith({ index: 'wazuh-alert-status-v2-000001', id: 'a1' });
  });

  test('rejects a missing or non-plugin archive location', async () => {
    await expect(resolveArchivedEvidence({} as any, { archive_index: null })).rejects.toThrow(/no archive location/i);
    await expect(
      resolveArchivedEvidence({} as any, { archive_index: 'wazuh-alerts-4.x-2026.08.28', archive_id: 'a1' })
    ).rejects.toThrow(/untrusted archive location/i);
  });
});

describe('shouldCarryAlert (case-state and hold-aware retirement)', () => {
  test('always carries open and in_progress alerts', () => {
    expect(shouldCarryAlert('open')).toBe(true);
    expect(shouldCarryAlert('in_progress', 'closed')).toBe(true);
  });

  test('carries a closed alert only for an active case or explicit hold', () => {
    expect(shouldCarryAlert('closed', 'open')).toBe(true);
    expect(shouldCarryAlert('closed', 'in_progress')).toBe(true);
    expect(shouldCarryAlert('closed', null, true)).toBe(true);
    expect(shouldCarryAlert('closed', 'closed')).toBe(false);
    expect(shouldCarryAlert('closed', 'closed', false)).toBe(false);
    expect(shouldCarryAlert('closed', undefined)).toBe(false);
  });

  test('fails safe by carrying unclassifiable statuses', () => {
    expect(shouldCarryAlert(null)).toBe(true);
    expect(shouldCarryAlert(undefined)).toBe(true);
    expect(shouldCarryAlert('weird')).toBe(true);
  });

  test('isActiveCaseStatus matches only open or in_progress', () => {
    expect(isActiveCaseStatus('open')).toBe(true);
    expect(isActiveCaseStatus('in_progress')).toBe(true);
    expect(isActiveCaseStatus('closed')).toBe(false);
    expect(isActiveCaseStatus(null)).toBe(false);
  });
});

describe('evidence relationship write helpers', () => {
  test('upsert writes a bounded doc keyed by the derived id', async () => {
    const indexFn = jest.fn(async () => ({}));
    const doc = await upsertEvidenceRelationship(
      { get: jest.fn(async () => { const e: any = new Error('nf'); e.meta = { statusCode: 404 }; throw e; }), index: indexFn } as any,
      { caseId: 'c', alertId: 'a', alertSource: {} }
    );
    expect(doc.case_id).toBe('c');
    expect(indexFn).toHaveBeenCalledWith(expect.objectContaining({ id: evidenceId('c', 'a') }));
  });

  test('archives a relationship while preserving its original link and hold metadata', async () => {
    const snapshot = { status: 'open', nested: { bytes: ['must', 'not', 'change'] } };
    const previous = {
      case_id: 'c', alert_id: 'a', linked_at: '2026-01-01T00:00:00Z',
      hold_reason: 'legal', hold_by: 'admin', hold_since: '2026-02-01T00:00:00Z',
      source_index: 'original-source', source_id: 'original-id', snapshot,
      lifecycle_marker: { retained: true },
    };
    const client = {
      get: jest.fn(async () => ({ body: {
        _index: 'wazuh-alert-manager-v2-evidence-000001', _seq_no: 7, _primary_term: 3, _source: previous,
      } })),
      index: jest.fn(async () => ({ body: { _seq_no: 8, _primary_term: 3 } })),
    };
    const result = await archiveEvidenceRelationship(client, {
      caseId: 'c', alertId: 'a', alertSource: alert({ status: 'closed' }),
      archiveIndex: 'wazuh-alert-status-v2-000001', archiveId: 'a',
      sourceIndex: 'replacement-source', sourceId: 'replacement-id',
      archivedAt: '2026-08-29T00:00:00Z',
    });
    expect(result.current).toEqual(expect.objectContaining({
      relationship_state: 'held', hold_reason: 'legal',
      linked_at: '2026-01-01T00:00:00Z', archive_index: 'wazuh-alert-status-v2-000001',
    }));
    expect(JSON.stringify(result.current.snapshot)).toBe(JSON.stringify(snapshot));
    expect(result.current).toEqual({
      ...previous,
      relationship_state: 'held',
      archive_index: 'wazuh-alert-status-v2-000001',
      archive_id: 'a',
      archived_at: '2026-08-29T00:00:00Z',
    });
    expect(client.index).toHaveBeenCalledWith(expect.objectContaining({
      index: 'wazuh-alert-manager-v2-evidence-000001',
      if_seq_no: 7,
      if_primary_term: 3,
    }));
    expect(result).toEqual(expect.objectContaining({ seqNo: 8, primaryTerm: 3 }));
  });

  test('uses create semantics for a new archive relationship and surfaces conflicts', async () => {
    const missing: any = new Error('missing');
    missing.meta = { statusCode: 404 };
    const conflict: any = new Error('conflict');
    conflict.meta = { statusCode: 409 };
    const client = {
      get: jest.fn(async () => { throw missing; }),
      index: jest.fn(async () => { throw conflict; }),
    };
    await expect(archiveEvidenceRelationship(client, {
      caseId: 'c', alertId: 'a', alertSource: alert(),
      archiveIndex: 'wazuh-alert-status-v2-000001', archiveId: 'a',
    })).rejects.toBe(conflict);
    expect(client.index).toHaveBeenCalledWith(expect.objectContaining({
      id: evidenceId('c', 'a'), op_type: 'create',
    }));
  });

  test('surfaces an existing-document OCC conflict without retrying over a concurrent hold', async () => {
    const conflict: any = new Error('conflict');
    conflict.meta = { statusCode: 409 };
    const client = {
      get: jest.fn(async () => ({ body: {
        _index: 'wazuh-alert-manager-v2-evidence-000001', _seq_no: 4, _primary_term: 2,
        _source: { case_id: 'c', alert_id: 'a', relationship_state: 'linked', snapshot: { exact: true } },
      } })),
      index: jest.fn(async () => { throw conflict; }),
    };
    await expect(archiveEvidenceRelationship(client, {
      caseId: 'c', alertId: 'a', alertSource: alert(),
      archiveIndex: 'wazuh-alert-status-v2-000001', archiveId: 'a',
    })).rejects.toBe(conflict);
    expect(client.index).toHaveBeenCalledTimes(1);
    expect(client.index).toHaveBeenCalledWith(expect.objectContaining({ if_seq_no: 4, if_primary_term: 2 }));
  });

  test('getEvidence returns null on a missing doc', async () => {
    const get = jest.fn(async () => {
      const e: any = new Error('nf');
      e.meta = { statusCode: 404 };
      throw e;
    });
    await expect(getEvidence({ get } as any, 'c', 'a')).resolves.toBeNull();
  });

  test('getEvidence rethrows permission and transport failures', async () => {
    const get = jest.fn(async () => { throw new Error('forbidden'); });
    await expect(getEvidence({ get } as any, 'c', 'a')).rejects.toThrow('forbidden');
  });

  test('lists evidence scoped to one case', async () => {
    const search = jest.fn(async () => ({ body: { hits: { total: { value: 1 }, hits: [{ _id: 'e1', _source: { case_id: 'c' }, sort: [1, 'e1'] }] } } }));
    await expect(listCaseEvidence({ search } as any, 'c')).resolves.toEqual({
      evidence: [{ id: 'e1', case_id: 'c' }], nextCursor: null, total: 1, truncated: false,
    });
    expect(search).toHaveBeenCalledWith(expect.objectContaining({
      index: 'wazuh-alert-manager-v2-evidence-read',
      body: expect.objectContaining({
        query: { term: { case_id: 'c' } },
        sort: [{ linked_at: { order: 'asc' } }, { alert_id: { order: 'asc' } }],
      }),
    }));
    expect(search.mock.calls[0][0].body.sort.some(
      (entry: any) => Object.prototype.hasOwnProperty.call(entry, '_id')
    )).toBe(false);
  });

  test('paginates 1001 evidence records with an exact total and scoped cursor', async () => {
    const hits = Array.from({ length: 1001 }, (_, index) => ({
      _id: `e${index}`, _source: { case_id: 'c', alert_id: `a${index}` }, sort: [index, `e${index}`],
    }));
    const search = jest
      .fn()
      .mockResolvedValueOnce({ body: { hits: { total: { value: 1001, relation: 'eq' }, hits } } })
      .mockResolvedValueOnce({ body: { hits: { total: { value: 1001, relation: 'eq' }, hits: [hits[1000]] } } });
    const first = await listCaseEvidence({ search } as any, 'c');
    expect(first.evidence).toHaveLength(1000);
    expect(first).toEqual(expect.objectContaining({ total: 1001, truncated: true }));
    expect(first.nextCursor).toEqual(expect.any(String));

    const second = await listCaseEvidence({ search } as any, 'c', { cursor: first.nextCursor! });
    expect(second).toEqual({ evidence: [{ id: 'e1000', case_id: 'c', alert_id: 'a1000' }], nextCursor: null, total: 1001, truncated: false });
    expect(search.mock.calls[1][0].body.search_after).toEqual([999, 'e999']);
    await expect(listCaseEvidence({ search } as any, 'other', { cursor: first.nextCursor! })).rejects.toThrow(/mismatched/i);
  });

  test('keeps relationship evidence and adds bounded legacy links before backfill completes', async () => {
    const notFound: any = new Error('not found');
    notFound.meta = { statusCode: 404 };
    const client = {
      search: jest.fn(async () => ({
        body: { hits: { total: { value: 1 }, hits: [{ _id: 'e1', _source: { case_id: 'c', alert_id: 'a1' }, sort: [1, 'e1'] }] } },
      })),
      get: jest.fn(async () => { throw notFound; }),
      mget: jest.fn(async () => ({
        body: { docs: [{ found: true, _source: { alert_id: 'a1' } }, { found: false }] },
      })),
    };
    const page = await listCaseEvidenceWithLegacy(client, 'c', ['a1', 'legacy-a2']);
    expect(page.evidence.map((item) => item.alert_id)).toEqual(['a1', 'legacy-a2']);
    expect(page.evidence[0]).toEqual(expect.objectContaining({ id: 'e1' }));
    expect(page.evidence[1]).toEqual(expect.objectContaining({ relationship_state: 'legacy', legacy_fallback: true }));
    expect(page.total).toBe(2);
  });

  test('does not consult legacy alert_ids after explicit backfill completion', async () => {
    const client = {
      search: jest.fn(async () => ({ body: { hits: { total: { value: 0 }, hits: [] } } })),
      get: jest.fn(async () => ({ body: { _source: { completed: true } } })),
      mget: jest.fn(),
    };
    const page = await listCaseEvidenceWithLegacy(client, 'c', ['legacy']);
    expect(page.evidence).toEqual([]);
    expect(client.mget).not.toHaveBeenCalled();
  });

  test('sets and clears a hold with OCC parameters without replacing archive or snapshot fields', async () => {
    const snapshot = { status: 'closed', immutable: { value: true } };
    const existing = {
      case_id: 'c', alert_id: 'a', relationship_state: 'archived',
      archive_index: 'wazuh-alert-status-v2-000001', archive_id: 'archive-a',
      archived_at: '2026-08-27T00:00:00Z', snapshot,
    };
    const client = {
      get: jest.fn(async () => ({ body: {
        _index: 'wazuh-alert-manager-v2-evidence-000001', _seq_no: 7, _primary_term: 3, _source: existing,
      } })),
      update: jest.fn(async () => ({})),
    };
    const held = await setEvidenceHold(client, 'c', 'a', { reason: 'legal', by: 'admin', since: '2026-08-28T00:00:00Z' });
    expect(held.relationship_state).toBe('held');
    expect(held).toEqual({
      ...existing,
      relationship_state: 'held', hold_reason: 'legal', hold_by: 'admin', hold_since: '2026-08-28T00:00:00Z',
    });
    const released = await setEvidenceHold(client, 'c', 'a', null);
    expect(released).toEqual({
      ...existing,
      relationship_state: 'archived', hold_reason: null, hold_by: null, hold_since: null,
    });
    expect(released.snapshot).toBe(snapshot);
    expect(client.update).toHaveBeenCalledWith(expect.objectContaining({
      index: 'wazuh-alert-manager-v2-evidence-000001',
      id: evidenceId('c', 'a'),
      if_seq_no: 7,
      if_primary_term: 3,
    }));
    const holdRequest = client.update.mock.calls[0][0];
    expect(holdRequest.body).toEqual({ script: expect.objectContaining({
      lang: 'painless',
      params: { held: true, reason: 'legal', by: 'admin', since: '2026-08-28T00:00:00Z' },
    }) });
    expect(holdRequest.body.script).not.toHaveProperty('params.doc');
    expect(holdRequest.body.script.source).not.toMatch(/snapshot\s*=/);
    expect(holdRequest.body.script.source).not.toMatch(/archive_(?:index|id)\s*=|archived_at\s*=/);
    expect(client).not.toHaveProperty('index');
  });

  test('requires OCC metadata before mutating a hold', async () => {
    const client = {
      get: jest.fn(async () => ({ body: {
        _index: 'wazuh-alert-manager-v2-evidence-000001',
        _source: { case_id: 'c', alert_id: 'a', relationship_state: 'linked' },
      } })),
      update: jest.fn(),
    };
    await expect(setEvidenceHold(client, 'c', 'a', null)).rejects.toThrow(/optimistic concurrency metadata/i);
    expect(client.update).not.toHaveBeenCalled();
  });

  test('surfaces a stale hold OCC conflict without retrying over retirement', async () => {
    const conflict: any = new Error('conflict');
    conflict.meta = { statusCode: 409 };
    const client = {
      get: jest.fn(async () => ({ body: {
        _index: 'wazuh-alert-manager-v2-evidence-000001', _seq_no: 12, _primary_term: 4,
        _source: { case_id: 'c', alert_id: 'a', relationship_state: 'linked', snapshot: { original: true } },
      } })),
      update: jest.fn(async () => { throw conflict; }),
    };
    await expect(setEvidenceHold(client, 'c', 'a', { reason: 'legal', by: 'admin' })).rejects.toBe(conflict);
    expect(client.get).toHaveBeenCalledTimes(1);
    expect(client.update).toHaveBeenCalledTimes(1);
    expect(client.update).toHaveBeenCalledWith(expect.objectContaining({ if_seq_no: 12, if_primary_term: 4 }));
  });

  test('removeEvidenceRelationship tolerates 404 and rethrows other errors', async () => {
    const notFound = jest.fn(async () => {
      const e: any = new Error('nf');
      e.meta = { statusCode: 404 };
      throw e;
    });
    await expect(removeEvidenceRelationship({ get: notFound } as any, 'c', 'a')).resolves.toBeUndefined();

    const boom = jest.fn(async () => {
      throw new Error('boom');
    });
    const get = jest.fn(async () => ({
      body: { _index: 'wazuh-alert-manager-v2-evidence-000001', _source: { case_id: 'c', alert_id: 'a' } },
    }));
    await expect(removeEvidenceRelationship({ get, delete: boom } as any, 'c', 'a')).rejects.toThrow('boom');
  });

  test('scrolls every archive reference in bounded 500-document pages', async () => {
    const page = (offset: number, count: number) => Array.from({ length: count }, (_, index) => ({
      _id: `e${offset + index}`,
      _index: 'wazuh-alert-manager-v2-evidence-000001',
      _source: { archive_index: 'wazuh-alert-status-v2-000001' },
    }));
    const client = {
      search: jest.fn(async () => ({ body: { _scroll_id: 'scroll', hits: { hits: page(0, 500) } } })),
      scroll: jest
        .fn()
        .mockResolvedValueOnce({ body: { _scroll_id: 'scroll', hits: { hits: page(500, 500) } } })
        .mockResolvedValueOnce({ body: { _scroll_id: 'scroll', hits: { hits: page(1000, 1) } } })
        .mockResolvedValueOnce({ body: { _scroll_id: 'scroll', hits: { hits: [] } } }),
      clearScroll: jest.fn(async () => ({})),
    };
    const sizes: number[] = [];
    await expect(scanArchiveEvidence(client, 'wazuh-alert-status-v2-000001', (hits) => {
      sizes.push(hits.length);
    })).resolves.toBe(1001);
    expect(sizes).toEqual([500, 500, 1]);
  });
});

describe('case evidence backfill', () => {
  test('resumes from META_INDEX progress and treats deterministic create conflicts as complete', async () => {
    const missing: any = new Error('missing');
    missing.meta = { statusCode: 404 };
    const firstClient = {
      get: jest.fn(async () => { throw missing; }),
      search: jest.fn(async ({ index }: any) => index === CASES_INDEX
        ? { body: { hits: { hits: [{ _id: 'c1', _source: { alert_ids: ['a1'] }, sort: [7] }] } } }
        : { body: { hits: { hits: [{ _id: 'a1', _index: 'wazuh-alert-status-v2-000001', _source: alert() }] } } }),
      bulk: jest.fn(async () => ({ body: { items: [{ create: { status: 409, error: { type: 'version_conflict_engine_exception' } } }] } })),
      index: jest.fn(async () => ({})),
    };
    const first = await backfillCaseEvidence(firstClient, { actor: 'admin', batchSize: 1, timestamp: '2026-08-28T00:00:00Z' });
    expect(first).toEqual(expect.objectContaining({ completed: false, processedCases: 1, createdRelationships: 0, existingRelationships: 1, nextCaseId: 'c1' }));
    expect(firstClient.index).toHaveBeenCalledWith(expect.objectContaining({
      index: 'wazuh-alert-manager-v2-meta', body: expect.objectContaining({ last_case_id: 'c1', last_case_sort: 7, completed: false }),
    }));
    expect(firstClient.search.mock.calls[0][0].body.sort).toEqual([{ _doc: { order: 'asc' } }]);
    expect(JSON.stringify(firstClient.search.mock.calls[0][0].body.sort)).not.toContain('_id');

    const resumedClient = {
      get: jest.fn(async () => ({ body: { _source: { completed: false, last_case_id: 'c1', last_case_sort: 7, processed_cases: 1 } } })),
      search: jest.fn(async () => ({ body: { hits: { hits: [] } } })),
      index: jest.fn(async () => ({})),
    };
    const resumed = await backfillCaseEvidence(resumedClient, { actor: 'admin', batchSize: 1 });
    expect(resumed.completed).toBe(true);
    expect(resumedClient.search.mock.calls[0][0].body.search_after).toEqual([7]);
    expect(resumedClient.index).toHaveBeenCalledWith(expect.objectContaining({
      body: expect.objectContaining({ completed: true, last_case_id: null }),
    }));
  });

  test('does not advance progress when a bulk item fails validation', async () => {
    const missing: any = new Error('missing');
    missing.meta = { statusCode: 404 };
    const client = {
      get: jest.fn(async () => { throw missing; }),
      search: jest.fn(async ({ index }: any) => index === CASES_INDEX
        ? { body: { hits: { hits: [{ _id: 'c1', _source: { alert_ids: ['a1'] }, sort: [7] }] } } }
        : { body: { hits: { hits: [] } } }),
      bulk: jest.fn(async () => ({ body: { items: [{ create: { status: 500, error: { reason: 'disk full' } } }] } })),
      index: jest.fn(),
    };
    await expect(backfillCaseEvidence(client, { actor: 'admin' })).rejects.toThrow('disk full');
    expect(client.index).not.toHaveBeenCalled();
  });
});

describe('case alert source resolution', () => {
  test('uses a managed archive and falls back to snapshots without reading native locators', async () => {
    const offline: any = new Error('offline');
    offline.meta = { statusCode: 404 };
    const client = {
      search: jest.fn(async () => ({ body: { hits: { hits: [] } } })),
      get: jest.fn(async ({ id }: any) => id === 'archived'
        ? { body: { _source: alert({ status: 'closed' }) } }
        : Promise.reject(offline)),
    };
    const resolved = await resolveCaseAlerts(client, [
      { alert_id: 'archived', archive_index: 'wazuh-alert-status-v2-000001' },
      { alert_id: 'snapshot', archive_index: 'wazuh-alert-status-v2-000002', snapshot: alert({ status: 'closed' }) },
    ]);
    expect(resolved.get('archived')?.availability).toBe('archived');
    expect(resolved.get('snapshot')?.availability).toBe('snapshot');
    const graph = buildAttackGraph(Array.from(resolved.values()).map((item) => ({
      _id: item.id,
      _source: item.source,
    })));
    expect(graph.hops.map((hop) => hop.alertId)).toEqual(['archived', 'snapshot']);

    await expect(resolveCaseAlerts(client, [
      { alert_id: 'native', archive_index: 'wazuh-alerts-4.x-2026.08.28', snapshot: alert() },
    ])).rejects.toThrow(/untrusted archive/i);
    expect(client.get).not.toHaveBeenCalledWith(expect.objectContaining({ index: 'wazuh-alerts-4.x-2026.08.28' }));
  });
});
