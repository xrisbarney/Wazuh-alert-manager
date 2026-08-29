import { Logger } from '../../../../src/core/server';
import { CASES_READ_ALIAS, CASES_WRITE_ALIAS, EVIDENCE_READ_ALIAS, META_INDEX } from '../../common';
import { assertManagedWriteTarget, isManagedPhysicalIndex } from './index_namespace';
import { appendActivity } from './activity';

const CASE_RETIREMENT_DOC_PREFIX = 'case-retirement:';
const PAGE_SIZE = 500;

function isActiveStatus(status: string | null | undefined): boolean {
  return status === 'open' || status === 'in_progress';
}

async function readAliasMembers(client: any): Promise<string[]> {
  const res: any = await client.indices.getAlias({ name: CASES_READ_ALIAS });
  return Object.keys(res?.body || {});
}

async function writeAliasMembers(client: any): Promise<string[]> {
  const res: any = await client.indices.getAlias({ name: CASES_WRITE_ALIAS });
  return Object.entries(res?.body || {})
    .filter(([, value]: any) => value?.aliases?.[CASES_WRITE_ALIAS]?.is_write_index === true)
    .map(([index]) => index);
}

async function scrollGeneration(client: any, index: string, visit: (hits: any[]) => Promise<void>) {
  let scrollId: string | undefined;
  try {
    let page: any = await client.search({
      index,
      scroll: '2m',
      size: PAGE_SIZE,
      body: { query: { match_all: {} }, sort: ['_doc'], _source: true },
    });
    for (;;) {
      scrollId = page?.body?._scroll_id || scrollId;
      const hits = page?.body?.hits?.hits || [];
      if (!hits.length) break;
      await visit(hits);
      page = await client.scroll({ scrollId, scroll: '2m' });
    }
  } finally {
    if (scrollId) {
      try {
        await client.clearScroll({ scrollId });
      } catch (e) {
        // Expired scroll contexts are harmless.
      }
    }
  }
}

export interface CaseRetirementPlan {
  retiringIndex: string;
  total: number;
  active: number;
  recentClosed: number;
  expiredClosed: number;
  carryIds: string[];
  archiveIds: string[];
}

/** Classify one case generation: active and recently-closed cases are carried
 * forward; expired closed cases become archive-only. */
export async function planCaseRetirement(
  client: any,
  retiringIndex: string,
  caseRetentionDays = 365
): Promise<CaseRetirementPlan> {
  if (!isManagedPhysicalIndex(retiringIndex, 'wazuh-alert-manager-v2-cases-')) {
    throw new Error(`Refusing to retire non-case index: ${retiringIndex}`);
  }
  const cutoffMs = Date.now() - caseRetentionDays * 86400000;
  const plan: CaseRetirementPlan = {
    retiringIndex,
    total: 0,
    active: 0,
    recentClosed: 0,
    expiredClosed: 0,
    carryIds: [],
    archiveIds: [],
  };
  await scrollGeneration(client, retiringIndex, async (hits) => {
    for (const hit of hits) {
      plan.total += 1;
      const status = hit._source?.status;
      const closedAt = hit._source?.closed_at ? Date.parse(hit._source.closed_at) : NaN;
      if (isActiveStatus(status)) {
        plan.active += 1;
        plan.carryIds.push(hit._id);
      } else if (status === 'closed' && Number.isFinite(closedAt) && closedAt >= cutoffMs) {
        plan.recentClosed += 1;
        plan.carryIds.push(hit._id);
      } else {
        plan.expiredClosed += 1;
        plan.archiveIds.push(hit._id);
      }
    }
  });
  return plan;
}

function insertOnly(index: string, id: string, doc: any): any[] {
  return [
    { update: { _index: assertManagedWriteTarget(index), _id: id } },
    { upsert: doc, script: { lang: 'painless', source: "ctx.op = 'none'" } },
  ];
}

async function assertRetirableGeneration(client: any, retiringIndex: string): Promise<void> {
  if (!isManagedPhysicalIndex(retiringIndex, 'wazuh-alert-manager-v2-cases-')) {
    throw new Error(`Refusing to retire non-case index: ${retiringIndex}`);
  }
  const [readMembers, writeMembers] = await Promise.all([readAliasMembers(client), writeAliasMembers(client)]);
  if (!readMembers.includes(retiringIndex)) {
    throw new Error(`${retiringIndex} is not attached to the cases read alias.`);
  }
  if (writeMembers.includes(retiringIndex)) {
    throw new Error('Cannot retire the current cases write generation; roll it over first.');
  }
}

export interface CaseRetirementResult {
  retiringIndex: string;
  carried: number;
  archived: number;
  failed: number;
}

/**
 * Carry active and recently-closed cases into the current writer, atomically
 * detach the generation from the read alias (it becomes Archived Cases), and
 * record the retirement. Idempotent: carried cases are insert-only, and a
 * repeat execution on an already-detached generation is refused.
 */
export async function executeCaseRetirement(
  client: any,
  retiringIndex: string,
  actor: string,
  caseRetentionDays = 365
): Promise<CaseRetirementResult> {
  await assertRetirableGeneration(client, retiringIndex);
  const plan = await planCaseRetirement(client, retiringIndex, caseRetentionDays);

  const carried = new Set<string>();
  if (plan.carryIds.length) {
    const source = new Map<string, any>();
    await scrollGeneration(client, retiringIndex, async (hits) => {
      for (const hit of hits) source.set(hit._id, hit._source || {});
    });
    const bulk: any[] = [];
    for (const id of plan.carryIds) {
      bulk.push(...insertOnly(CASES_WRITE_ALIAS, id, source.get(id) || {}));
    }
    for (let offset = 0; offset < bulk.length; offset += 1000) {
      const chunk = bulk.slice(offset, offset + 1000);
      // The old generation is detached immediately after carry-forward. Wait
      // until the inserted copies are searchable so resolveCase cannot observe
      // a transient 404 between alias detachment and the next index refresh.
      const result: any = await client.bulk({ body: chunk, refresh: 'wait_for' });
      const items = result?.body?.items || [];
      const failed = items.some((item: any) => {
        const op: any = Object.values(item || {})[0];
        const status = Number(op?.status);
        return !op || op.error || !Number.isInteger(status) || status < 200 || status >= 300;
      });
      if (result?.body?.errors || items.length !== chunk.length / 2 || failed) {
        throw new Error('One or more cases failed to carry forward during retirement');
      }
    }
    for (const id of plan.carryIds) carried.add(id);
  }

  let detached = false;
  await client.indices.putSettings({ index: retiringIndex, body: { 'index.blocks.write': true } });
  try {
    await client.indices.updateAliases({
      body: { actions: [
        { remove: { index: retiringIndex, alias: CASES_READ_ALIAS } },
        { remove: { index: retiringIndex, alias: CASES_WRITE_ALIAS } },
      ] },
    });
    detached = true;
    await client.index({
      index: assertManagedWriteTarget(META_INDEX),
      id: `${CASE_RETIREMENT_DOC_PREFIX}${retiringIndex}`,
      body: {
        retiring_index: retiringIndex,
        status: 'retired',
        carried: carried.size,
        archived: plan.archiveIds.length,
        completed_at: new Date().toISOString(),
        actor,
      },
      refresh: 'wait_for',
    });
  } catch (error) {
    if (detached) {
      try {
        await client.indices.updateAliases({
          body: { actions: [{ add: { index: retiringIndex, alias: CASES_READ_ALIAS } }] },
        });
      } catch (rollbackError: any) {
        throw new Error(
          `Case retirement metadata failed and the read alias could not be restored: ${rollbackError.message}`
        );
      }
    }
    await client.indices.putSettings({ index: retiringIndex, body: { 'index.blocks.write': false } });
    throw error;
  }
  await appendActivity(client, {
    targetType: 'case', targetId: retiringIndex, user: actor,
    action: 'case generation retired', source: 'lifecycle',
  });
  return {
    retiringIndex,
    carried: carried.size,
    archived: plan.archiveIds.length,
    failed: 0,
  };
}

/** Archived case generations: physical generations with a retirement record. */
export async function listArchivedCaseGenerations(client: any): Promise<any[]> {
  const records: any[] = [];
  let scrollId: string | undefined;
  try {
    let page: any = await client.search({
      index: META_INDEX,
      scroll: '2m',
      size: PAGE_SIZE,
      body: {
        // `retired` is unique to case retirement records.
        query: { term: { status: 'retired' } },
        sort: ['_doc'],
        _source: true,
      },
    });
    for (;;) {
      scrollId = page?.body?._scroll_id || scrollId;
      const hits = page?.body?.hits?.hits || [];
      if (!hits.length) break;
      records.push(...hits);
      if (hits.length < PAGE_SIZE) break;
      page = await client.scroll({ scrollId, scroll: '2m' });
    }
  } finally {
    if (scrollId) {
      try { await client.clearScroll({ scrollId }); } catch (e) { /* expired */ }
    }
  }
  const out: any[] = [];
  for (const hit of records) {
    const source = hit._source || {};
    const retiringIndex =
      (typeof source.retiring_index === 'string' && source.retiring_index) ||
      String(hit._id || '').replace(/^case-retirement:/, '');
    if (!isManagedPhysicalIndex(retiringIndex, 'wazuh-alert-manager-v2-cases-')) continue;
    const count: any = await client.count({ index: retiringIndex, body: { query: { match_all: {} } } });
    out.push({
      index: retiringIndex,
      carried: source.carried ?? 0,
      archived: source.archived ?? count?.body?.count ?? 0,
      completed_at: source.completed_at ?? null,
      documents: count?.body?.count ?? 0,
    });
  }
  return out;
}

export interface ArchivedCase {
  _id: string;
  _index: string;
  _source: any;
}

/** Locate an archived case across retained (detached) case generations. */
export async function findArchivedCase(client: any, caseId: string): Promise<ArchivedCase | null> {
  const generations = await listArchivedCaseGenerations(client);
  for (const generation of generations) {
    try {
      const res: any = await client.get({ index: generation.index, id: caseId });
      if (res?.body?.found) {
        return { _id: caseId, _index: generation.index, _source: res.body._source };
      }
    } catch (e: any) {
      if (e?.meta?.statusCode !== 404) throw e;
    }
  }
  return null;
}

/**
 * Reopen an archived case by copying it into the current writer as a fresh
 * active case. The original archived document is retained; the copy is
 * insert-only so a concurrently reopened or already-live case is never
 * overwritten.
 */
export async function reopenArchivedCase(client: any, caseId: string, actor: string): Promise<any> {
  const archived = await findArchivedCase(client, caseId);
  if (!archived) throw new Error(`Archived case ${caseId} was not found.`);
  const now = new Date().toISOString();
  const source = archived._source || {};
  const doc = {
    ...source,
    status: 'open',
    closed_at: null,
    updated_at: now,
    updated_by: actor,
    history: [
      ...(Array.isArray(source.history) ? source.history : []),
      { timestamp: now, user: actor, action: 'case_reopened', from: 'archived', to: 'open' },
    ],
  };
  await client.create({
    index: assertManagedWriteTarget(CASES_WRITE_ALIAS),
    id: caseId,
    body: doc,
    refresh: 'wait_for',
  });
  await appendActivity(client, {
    targetType: 'case', targetId: caseId, user: actor,
    action: 'case reopened from archive', source: 'lifecycle',
  });
  return doc;
}

/** Retained archived generation purge (hold-aware; separate explicit action). */
export async function purgeArchivedCaseGeneration(client: any, index: string, actor: string): Promise<void> {
  if (!isManagedPhysicalIndex(index, 'wazuh-alert-manager-v2-cases-')) {
    throw new Error(`Refusing to purge non-case index: ${index}`);
  }
  const [readMembers, writeAliases, record, settings]: any[] = await Promise.all([
    readAliasMembers(client),
    client.indices.getAlias({ name: CASES_WRITE_ALIAS }),
    client.get({ index: META_INDEX, id: `${CASE_RETIREMENT_DOC_PREFIX}${index}` }),
    client.indices.getSettings({ index }),
  ]);
  if (readMembers.includes(index) || writeAliases?.body?.[index]) {
    throw new Error('Cannot purge a generation still attached to a cases alias.');
  }
  if (record?.body?._source?.status !== 'retired') {
    throw new Error('No completed case retirement record exists.');
  }
  if (settings?.body?.[index]?.settings?.index?.blocks?.write !== 'true') {
    throw new Error('The archived case generation is not write-blocked.');
  }

  let holdCount = 0;
  await scrollGeneration(client, index, async (hits) => {
    const caseIds = hits.map((hit: any) => String(hit._id)).filter(Boolean);
    if (!caseIds.length || holdCount) return;
    const evidenceHolds: any = await client.count({
      index: EVIDENCE_READ_ALIAS,
      body: { query: { bool: { filter: [
        { terms: { case_id: caseIds } },
        { exists: { field: 'hold_since' } },
      ] } } },
    });
    holdCount += evidenceHolds?.body?.count || 0;
  });
  if (holdCount > 0) throw new Error('Case generation purge is blocked by evidence holds.');
  const [freshRead, freshWrite]: any[] = await Promise.all([
    readAliasMembers(client), client.indices.getAlias({ name: CASES_WRITE_ALIAS }),
  ]);
  if (freshRead.includes(index) || freshWrite?.body?.[index]) {
    throw new Error('The case generation became attached to a live alias.');
  }
  await client.indices.delete({ index: assertManagedWriteTarget(index) });
  await appendActivity(client, {
    targetType: 'case', targetId: index, user: actor,
    action: 'case generation purged', source: 'lifecycle',
  });
}
