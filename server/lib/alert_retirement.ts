import crypto from 'crypto';
import { Logger } from '../../../../src/core/server';
import {
  ALERTS_READ_ALIAS, ALERTS_WRITE_ALIAS, CASES_INDEX, EVIDENCE_READ_ALIAS,
  EVIDENCE_WRITE_ALIAS, META_INDEX,
} from '../../common';
import { alertStatusMapping } from './mappings';
import { assertManagedWriteTarget, isManagedPhysicalIndex } from './index_namespace';
import { appendActivity } from './activity';
import {
  archiveEvidenceRelationship, evidenceId, getEvidence, getEvidenceLocation, isEvidenceHeld, scanArchiveEvidence, shouldCarryAlert,
} from './evidence';
import { loadLifecycleSettings } from './lifecycle';
import { resolveCase } from './case_index_resolution';

// Active (open/in_progress) alerts are always carried.
const ACTIVE_QUERY = { terms: { status: ['open', 'in_progress'] } };
// Closed alerts linked to a case are candidates: they are carried only while
// their case is still active or protected by an explicit evidence hold. Closed
// alerts for closed, non-held cases become archive-only.
const CLOSED_CASE_LINKED_QUERY = {
  bool: { must: [{ term: { status: 'closed' } }, { exists: { field: 'case_id' } }] },
};
const RETIRED_ALERT_DOC_PREFIX = 'retired-alert:';
const RETIREMENT_DOC_PREFIX = 'retirement:';
const MAX_PREPARING_RETIREMENTS = 100;
const RETIREMENT_LEASE_TTL_MS = 2 * 60 * 1000;
const RETIREMENT_RECOVERY_INTERVAL_MS = 60 * 1000;

interface RetirementLease {
  record: any;
  seqNo: number;
  primaryTerm: number;
}

class RetirementLeaseLostError extends Error {}

function newHolderId(): string {
  return crypto.randomBytes(16).toString('hex');
}

function leaseExpiry(): string {
  return new Date(Date.now() + RETIREMENT_LEASE_TTL_MS).toISOString();
}

async function aliasIndices(client: any, alias: string): Promise<Record<string, any>> {
  const res: any = await client.indices.getAlias({ name: alias });
  return res?.body || {};
}

async function count(client: any, index: string, query: any): Promise<number> {
  const res: any = await client.count({ index, body: { query } });
  return res?.body?.count || 0;
}

async function safeGet(client: any, index: string, id: string): Promise<any | null> {
  try {
    const res: any = await client.get({ index, id });
    return res?.body?._source || null;
  } catch (e) {
    return null;
  }
}

async function getRetirementRecord(client: any, retiringIndex: string): Promise<any | null> {
  try {
    const result: any = await client.get({ index: META_INDEX, id: `${RETIREMENT_DOC_PREFIX}${retiringIndex}` });
    return result?.body?._source || null;
  } catch (e: any) {
    if (e?.meta?.statusCode === 404) return null;
    throw e;
  }
}

async function loadCaseStatus(client: any, caseId: string): Promise<string | null> {
  try {
    const result: any = await client.get({ index: CASES_INDEX, id: caseId });
    return result?.body?._source?.status ?? null;
  } catch (e: any) {
    const status = e?.meta?.statusCode || e?.statusCode;
    if (status === 404) return null;
    if (status !== 400) throw e;
    // Point GET is invalid once the cases alias spans rollover generations.
    // The shared resolver searches by exact ID and returns a physical index.
    try {
      return (await resolveCase(client, caseId)).source?.status ?? null;
    } catch (resolved: any) {
      if ((resolved?.meta?.statusCode || resolved?.statusCode) === 404) return null;
      throw resolved;
    }
  }
}

function deterministicCarryIndex(retiringIndex: string): string {
  const digest = crypto.createHash('sha256').update(retiringIndex, 'utf8').digest('hex');
  const suffix = digest.slice(0, 17).split('').map((digit) => parseInt(digit, 16) % 10).join('');
  return assertManagedWriteTarget(`wazuh-alert-status-v2-carry-${suffix}`);
}

export interface CaseLinkCarryResolution {
  alertId: string;
  caseId: string;
  caseStatus: string | null;
  held: boolean;
  carry: boolean;
}

/**
 * Resolve the carry decision for every closed, case-linked alert in a
 * generation: carried while its case is active (open/in_progress) or it has an
 * explicit evidence hold; archived otherwise.
 */
export async function resolveCaseLinkedCarry(client: any, index: string): Promise<CaseLinkCarryResolution[]> {
  const resolutions: CaseLinkCarryResolution[] = [];
  const caseStatusCache = new Map<string, string | null>();
  let scrollId: string | undefined;
  try {
    let page: any = await client.search({
      index,
      scroll: '2m',
      size: 500,
      body: { query: CLOSED_CASE_LINKED_QUERY, sort: ['_doc'] },
    });
    while (true) {
      scrollId = page?.body?._scroll_id;
      const hits = page?.body?.hits?.hits || [];
      if (!hits.length) break;
      for (const hit of hits) {
        const caseId = hit._source?.case_id;
        if (!caseId) continue;
        if (!caseStatusCache.has(caseId)) {
          caseStatusCache.set(caseId, await loadCaseStatus(client, caseId));
        }
        const caseStatus = caseStatusCache.get(caseId) ?? null;
        const evidence = await getEvidence(client, caseId, hit._id);
        const held = isEvidenceHeld(evidence);
        resolutions.push({
          alertId: hit._id,
          caseId,
          caseStatus,
          held,
          carry: shouldCarryAlert('closed', caseStatus, held),
        });
      }
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
  return resolutions;
}

export interface RetirementPlan {
  retiringIndex: string;
  writeIndex: string;
  totalDocuments: number;
  activeDocuments: number;
  caseLinkedClosedDocuments: number;
  carriedCaseLinkedDocuments: number;
  archivedCaseLinkedDocuments: number;
  preservedDocuments: number;
  archiveOnlyDocuments: number;
  carriedCaseLinkedIds: string[];
  archivedCaseLinks: Array<{ alertId: string; caseId: string }>;
  hasWriteAlias: boolean;
}

/** Validate that a generation can be retired without touching Wazuh-owned storage. */
export async function planAlertRetirement(client: any, retiringIndex: string): Promise<RetirementPlan> {
  if (!isManagedPhysicalIndex(retiringIndex, 'wazuh-alert-status-v2-')) {
    throw new Error('Only a physical wazuh-alert-status-v2-* generation can be retired.');
  }
  const [readMembers, writeMembers] = await Promise.all([
    aliasIndices(client, ALERTS_READ_ALIAS),
    aliasIndices(client, ALERTS_WRITE_ALIAS),
  ]);
  if (!readMembers[retiringIndex]) throw new Error(`${retiringIndex} is not a member of ${ALERTS_READ_ALIAS}.`);
  const writeIndex = Object.keys(writeMembers).find(
    (index) => writeMembers[index]?.aliases?.[ALERTS_WRITE_ALIAS]?.is_write_index === true
  );
  if (!writeIndex) throw new Error(`No write generation is configured for ${ALERTS_WRITE_ALIAS}.`);
  if (writeIndex === retiringIndex) throw new Error('Roll over before retiring the current write generation.');
  const [totalDocuments, activeDocuments, caseLinkedClosedDocuments] = await Promise.all([
    count(client, retiringIndex, { match_all: {} }),
    count(client, retiringIndex, ACTIVE_QUERY),
    count(client, retiringIndex, CLOSED_CASE_LINKED_QUERY),
  ]);
  const resolutions = await resolveCaseLinkedCarry(client, retiringIndex);
  const carriedCaseLinkedIds = resolutions.filter((r) => r.carry).map((r) => r.alertId);
  const archivedCaseLinks = resolutions
    .filter((r) => !r.carry)
    .map((r) => ({ alertId: r.alertId, caseId: r.caseId }));
  const carriedCaseLinkedDocuments = carriedCaseLinkedIds.length;
  const archivedCaseLinkedDocuments = Math.max(0, caseLinkedClosedDocuments - carriedCaseLinkedDocuments);
  const preservedDocuments = activeDocuments + carriedCaseLinkedDocuments;
  return {
    retiringIndex,
    writeIndex,
    totalDocuments,
    activeDocuments,
    caseLinkedClosedDocuments,
    carriedCaseLinkedDocuments,
    archivedCaseLinkedDocuments,
    preservedDocuments,
    archiveOnlyDocuments: Math.max(0, totalDocuments - preservedDocuments),
    carriedCaseLinkedIds,
    archivedCaseLinks,
    hasWriteAlias: Boolean(writeMembers[retiringIndex]),
  };
}

/** Scroll + bulk copy all documents matching `query` (optionally restricted to `idFilter`). */
async function copyByQuery(
  client: any,
  source: string,
  target: string,
  query: any,
  idFilter: Set<string> | undefined,
  renew: () => Promise<void>
): Promise<number> {
  let copied = 0;
  let scrollId: string | undefined;
  try {
    await renew();
    let page: any = await client.search({
      index: source,
      scroll: '2m',
      size: 500,
      body: { query, sort: ['_doc'] },
    });
    while (true) {
      scrollId = page?.body?._scroll_id;
      const rawHits = page?.body?.hits?.hits || [];
      if (!rawHits.length) break;
      const hits = idFilter ? rawHits.filter((h: any) => idFilter.has(h._id)) : rawHits;
      if (hits.length) {
        await renew();
        const bulk: any[] = [];
        for (const hit of hits) {
          bulk.push({ index: { _index: target, _id: hit._id } }, hit._source);
        }
        const result: any = await client.bulk({ body: bulk, refresh: false });
        if (result?.body?.errors) {
          const first = (result.body.items || []).find((item: any) => item.index?.error);
          throw new Error(`Carry-forward bulk failed: ${JSON.stringify(first?.index?.error || 'unknown error')}`);
        }
        copied += hits.length;
      }
      await renew();
      page = await client.scroll({ scrollId, scroll: '2m' });
    }
  } finally {
    if (scrollId) {
      try {
        await client.clearScroll({ scrollId });
      } catch (e) {
        // Expired scroll contexts are harmless after a completed copy.
      }
    }
  }
  return copied;
}

async function createPurgeTombstones(client: any, index: string, purgeStartedAt: string): Promise<number> {
  let created = 0;
  let scrollId: string | undefined;
  try {
    let page: any = await client.search({
      index,
      scroll: '2m',
      size: 500,
      body: { query: { match_all: {} }, sort: ['_doc'], _source: false },
    });
    while (true) {
      scrollId = page?.body?._scroll_id || scrollId;
      const hits = page?.body?.hits?.hits;
      if (!Array.isArray(hits)) throw new Error('Archive tombstone scan returned incomplete identity evidence.');
      if (!hits.length) break;
      const ids: string[] = [];
      const body: any[] = [];
      for (const hit of hits) {
        if (typeof hit?._id !== 'string' || !hit._id) {
          throw new Error('Archive tombstone scan returned malformed identity evidence.');
        }
        const tombstoneId = `${RETIRED_ALERT_DOC_PREFIX}${hit._id}`;
        ids.push(tombstoneId);
        body.push({ create: { _index: assertManagedWriteTarget(META_INDEX), _id: tombstoneId } });
        body.push({
          document_type: 'retired_alert',
          alert_uid: hit._id,
          retiring_index: index,
          purge_started_at: purgeStartedAt,
        });
      }
      const result: any = await client.bulk({ body, refresh: 'wait_for' });
      const items = result?.body?.items;
      if (!Array.isArray(items) || items.length !== hits.length) {
        throw new Error('Archive tombstone bulk returned an incomplete item response.');
      }
      for (const item of items) {
        const detail = item?.create;
        const status = Number(detail?.status || 0);
        if (!detail || (status !== 409 && (detail.error || status < 200 || status >= 300))) {
          throw new Error(`Archive tombstone bulk failed: ${JSON.stringify(detail?.error || detail)}`);
        }
      }
      const verification: any = await client.mget({
        index: META_INDEX,
        body: { ids },
        _source: ['document_type', 'alert_uid', 'retiring_index'],
      });
      const docs = verification?.body?.docs;
      if (!Array.isArray(docs) || docs.length !== hits.length) {
        throw new Error('Archive tombstone verification returned incomplete identity evidence.');
      }
      const expected = new Map(ids.map((id, position) => [id, hits[position]._id]));
      const verified = new Set<string>();
      for (const doc of docs) {
        const tombstoneId = typeof doc?._id === 'string' ? doc._id : '';
        const alertId = expected.get(tombstoneId);
        if (!alertId || verified.has(tombstoneId) || doc?.found !== true ||
            doc?._source?.document_type !== 'retired_alert' || doc._source.alert_uid !== alertId ||
            !isManagedPhysicalIndex(doc?._source?.retiring_index, 'wazuh-alert-status-v2-')) {
          throw new Error('Archive tombstone verification returned malformed identity evidence.');
        }
        verified.add(tombstoneId);
      }
      created += hits.length;
      page = await client.scroll({ scrollId, scroll: '2m' });
    }
  } finally {
    if (scrollId) {
      try {
        await client.clearScroll({ scrollId });
      } catch (e) {
        // Expired scroll contexts are harmless after durable tombstone creation.
      }
    }
  }
  return created;
}

/**
 * Preserve unresolved alerts in a compact carry index, then atomically remove
 * the retired generation from the read alias. The source index is retained and
 * write-blocked: this operation never deletes evidence and permits manual
 * recovery. A short maintenance window begins when the source write block is
 * applied; status updates resume against the carry copy after alias cutover.
 */
function validateRetirementTransaction(
  record: any,
  statuses: string[] = ['preparing']
): { plan: RetirementPlan; retiringIndex: string; actor: string; target: string } {
  const plan = record?.plan as RetirementPlan;
  const retiringIndex = record?.retiring_index;
  const actor = record?.actor;
  const target = record?.carry_index;
  if (
    !statuses.includes(record?.status) ||
    typeof retiringIndex !== 'string' ||
    !isManagedPhysicalIndex(retiringIndex, 'wazuh-alert-status-v2-') ||
    target !== deterministicCarryIndex(retiringIndex) ||
    typeof actor !== 'string' || !actor ||
    typeof record?.holder_id !== 'string' || !record.holder_id ||
    !Number.isFinite(Date.parse(record?.expires_at)) ||
    !plan || plan.retiringIndex !== retiringIndex ||
    plan.writeIndex === retiringIndex ||
    !isManagedPhysicalIndex(plan.writeIndex, 'wazuh-alert-status-v2-') ||
    !Number.isFinite(plan.totalDocuments) ||
    !Number.isFinite(plan.activeDocuments) ||
    !Number.isFinite(plan.caseLinkedClosedDocuments) ||
    !Number.isFinite(plan.carriedCaseLinkedDocuments) ||
    !Number.isFinite(plan.archivedCaseLinkedDocuments) ||
    !Number.isFinite(plan.archiveOnlyDocuments) ||
    !Array.isArray(plan.carriedCaseLinkedIds) ||
    plan.carriedCaseLinkedIds.some((id) => typeof id !== 'string' || !id) ||
    !Array.isArray(plan.archivedCaseLinks) ||
    plan.archivedCaseLinks.some((link) =>
      typeof link?.alertId !== 'string' || !link.alertId || typeof link?.caseId !== 'string' || !link.caseId
    )
  ) {
    throw new Error(`Preparing retirement record for ${retiringIndex || '<unknown>'} is incomplete or unsafe.`);
  }
  return { plan, retiringIndex, actor, target };
}

async function renewRetirementLease(client: any, lease: RetirementLease): Promise<void> {
  const { retiringIndex } = validateRetirementTransaction(lease.record, ['preparing', 'recovering']);
  lease.record = { ...lease.record, expires_at: leaseExpiry() };
  try {
    const result: any = await client.index({
      index: assertManagedWriteTarget(META_INDEX),
      id: `${RETIREMENT_DOC_PREFIX}${retiringIndex}`,
      if_seq_no: lease.seqNo,
      if_primary_term: lease.primaryTerm,
      refresh: 'wait_for',
      body: lease.record,
    });
    const seqNo = result?.body?._seq_no;
    const primaryTerm = result?.body?._primary_term;
    if (!Number.isInteger(seqNo) || !Number.isInteger(primaryTerm)) {
      throw new RetirementLeaseLostError(`Retirement lease renewal for ${retiringIndex} returned no OCC metadata.`);
    }
    lease.seqNo = seqNo;
    lease.primaryTerm = primaryTerm;
  } catch (e: any) {
    if (e instanceof RetirementLeaseLostError) throw e;
    if ((e?.meta?.statusCode || e?.statusCode) === 409 || (e?.meta?.statusCode || e?.statusCode) === 404) {
      throw new RetirementLeaseLostError(`Retirement lease ownership for ${retiringIndex} was lost.`);
    }
    throw e;
  }
}

function assertPlannedWriter(writeMembers: Record<string, any>, plan: RetirementPlan): void {
  const members = Object.keys(writeMembers).filter(
    (index) => writeMembers[index]?.aliases?.[ALERTS_WRITE_ALIAS]?.is_write_index === true
  );
  if (
    members.length !== 1 ||
    members[0] !== plan.writeIndex ||
    writeMembers[plan.writeIndex]?.aliases?.[ALERTS_WRITE_ALIAS]?.is_write_index !== true
  ) {
    throw new Error(`The planned writer ${plan.writeIndex} is no longer the sole explicit write generation.`);
  }
}

function assertCurrentRolloverWriter(
  readMembers: Record<string, any>,
  writeMembers: Record<string, any>,
  retiringIndex: string,
  target: string
): string {
  const members = Object.keys(writeMembers).filter(
    (index) => writeMembers[index]?.aliases?.[ALERTS_WRITE_ALIAS]?.is_write_index === true
  );
  const writer = members[0];
  const numericGeneration = (writer || '').match(/^wazuh-alert-status-v2-(\d{6,})$/)?.[1];
  if (
    members.length !== 1 ||
    !numericGeneration || !/[1-9]/.test(numericGeneration) ||
    !isManagedPhysicalIndex(writer, 'wazuh-alert-status-v2-') ||
    writeMembers[writer]?.aliases?.[ALERTS_WRITE_ALIAS]?.is_write_index !== true ||
    !readMembers[writer] ||
    writer === retiringIndex ||
    writer === target
  ) {
    throw new Error('Post-cutover retirement has no sole safe numeric rollover writer.');
  }
  return writer;
}

async function deleteUnattachedCarryTarget(
  client: any,
  target: string,
  renew?: () => Promise<void>
): Promise<void> {
  assertManagedWriteTarget(target);
  if (renew) await renew();
  const exists: any = await client.indices.exists({ index: target });
  if (!exists?.body) return;
  let aliases: any;
  try {
    if (renew) await renew();
    aliases = await client.indices.getAlias({ index: target });
  } catch (e: any) {
    if ((e?.meta?.statusCode || e?.statusCode) === 404) {
      const stillExists: any = await client.indices.exists({ index: target });
      if (!stillExists?.body) return;
    }
    throw e;
  }
  const targetAliases = aliases?.body?.[target]?.aliases;
  if (!targetAliases || Object.keys(targetAliases).length) {
    throw new Error(`Refusing to delete carry target ${target}: alias state is not provably empty.`);
  }
  try {
    if (renew) await renew();
    await client.indices.delete({ index: target });
  } catch (e: any) {
    if ((e?.meta?.statusCode || e?.statusCode) !== 404) throw e;
  }
}

async function assertReadOnlyCarryTarget(
  client: any,
  target: string,
  renew?: () => Promise<void>
): Promise<void> {
  if (renew) await renew();
  const result: any = await client.indices.getAlias({ index: target });
  const aliases = result?.body?.[target]?.aliases;
  if (!aliases || Object.keys(aliases).length !== 1 || !aliases[ALERTS_READ_ALIAS]) {
    throw new Error(`Carry target ${target} is not attached exclusively to the read alias.`);
  }
}

async function deletePreparingClaim(
  client: any,
  retiringIndex: string,
  seqNo: number,
  primaryTerm: number
): Promise<void> {
  try {
    await client.delete({
      index: assertManagedWriteTarget(META_INDEX),
      id: `${RETIREMENT_DOC_PREFIX}${retiringIndex}`,
      if_seq_no: seqNo,
      if_primary_term: primaryTerm,
      refresh: 'wait_for',
    });
  } catch (e: any) {
    if ((e?.meta?.statusCode || e?.statusCode) !== 404) throw e;
  }
}

async function completeRetirement(
  client: any,
  lease: RetirementLease,
  logger: Logger
) {
  const { plan, retiringIndex, actor, target } = validateRetirementTransaction(
    lease.record,
    ['preparing', 'recovering']
  );
  const copied = plan.activeDocuments + plan.carriedCaseLinkedDocuments;
  try {
    await client.index({
      index: assertManagedWriteTarget(META_INDEX),
      id: `${RETIREMENT_DOC_PREFIX}${retiringIndex}`,
      if_seq_no: lease.seqNo,
      if_primary_term: lease.primaryTerm,
      refresh: 'wait_for',
      body: {
        status: 'completed',
        retiring_index: retiringIndex,
        carry_index: target,
        active_documents: plan.activeDocuments,
        case_linked_closed_documents: plan.caseLinkedClosedDocuments,
        carried_case_linked_documents: plan.carriedCaseLinkedDocuments,
        archived_case_linked_documents: plan.archivedCaseLinkedDocuments,
        preserved_documents: copied,
        retired_documents: plan.archiveOnlyDocuments,
        actor,
        completed_at: new Date().toISOString(),
        source_retained: true,
      },
    });
  } catch (e: any) {
    if ((e?.meta?.statusCode || e?.statusCode) !== 409) throw e;
    const current = await getRetirementRecord(client, retiringIndex);
    if (current?.status === 'completed' && current?.carry_index === target) {
      return { ...plan, carryIndex: target, carriedDocuments: copied, sourceRetained: true };
    }
    throw e;
  }
  logger.info(
    `wazuh-alert-manager lifecycle: retired ${retiringIndex}; carried ${copied} active or active-case/held alerts to ${target}`
  );
  await appendActivity(client, {
    targetType: 'system',
    targetId: retiringIndex,
    user: actor,
    action: 'retired alert generation',
    from: `${plan.totalDocuments} documents`,
    to: `${copied} active or active-case/held documents carried`,
    source: 'lifecycle',
  });
  return { ...plan, carryIndex: target, carriedDocuments: copied, sourceRetained: true };
}

async function runClaimedAlertRetirement(
  client: any,
  lease: RetirementLease,
  logger: Logger
) {
  const { plan, retiringIndex, target } = validateRetirementTransaction(lease.record);
  const renew = () => renewRetirementLease(client, lease);
  let sourceBlocked = false;
  let cutover = false;
  const evidenceRollback: Array<{
    caseId: string;
    alertId: string;
    index: string;
    previous: any | null;
    seqNo: number;
    primaryTerm: number;
  }> = [];
  try {
    await renew();
    const [initialReadMembers, initialWriteMembers] = await Promise.all([
      aliasIndices(client, ALERTS_READ_ALIAS),
      aliasIndices(client, ALERTS_WRITE_ALIAS),
    ]);
    const sourceIsLive = Boolean(initialReadMembers[retiringIndex]);
    const targetIsLive = Boolean(initialReadMembers[target]);
    assertPlannedWriter(initialWriteMembers, plan);
    if (
      !sourceIsLive || !initialReadMembers[plan.writeIndex] || targetIsLive ||
      initialWriteMembers[retiringIndex]?.aliases?.[ALERTS_WRITE_ALIAS]?.is_write_index === true ||
      initialWriteMembers[target]?.aliases?.[ALERTS_WRITE_ALIAS]?.is_write_index === true
    ) {
      throw new Error(`Retirement topology for ${retiringIndex} changed after planning; refusing cutover.`);
    }
      await renew();
      await client.indices.putSettings({ index: retiringIndex, body: { 'index.blocks.write': true } });
      sourceBlocked = true;
      await renew();
      await client.indices.create({ index: target, body: { mappings: alertStatusMapping } });
      const carriedCaseLinkedIds = new Set(plan.carriedCaseLinkedIds);
      const activeCopied = await copyByQuery(client, retiringIndex, target, ACTIVE_QUERY, undefined, renew);
      const caseLinkedCopied = await copyByQuery(
        client,
        retiringIndex,
        target,
        CLOSED_CASE_LINKED_QUERY,
        carriedCaseLinkedIds,
        renew
      );
      await renew();
      await client.indices.refresh({ index: target });
      const copied = activeCopied + caseLinkedCopied;
      const expected = plan.activeDocuments + plan.carriedCaseLinkedDocuments;
      if (copied !== expected) {
        throw new Error(
          `Carry-forward validation failed (copied=${copied}, expected=${expected} active + carried case-linked).`
        );
      }
      for (const link of plan.archivedCaseLinks) {
        await renew();
        const source: any = await client.get({ index: retiringIndex, id: link.alertId });
        const archiveInput = {
          caseId: link.caseId,
          alertId: link.alertId,
          alertSource: source?.body?._source || {},
          archiveIndex: retiringIndex,
          archiveId: link.alertId,
          sourceIndex: source?.body?._source?.source_index ?? null,
          sourceId: source?.body?._source?.source_id ?? null,
        };
        await renew();
        let archived;
        try {
          archived = await archiveEvidenceRelationship(client, archiveInput, renew);
        } catch (e: any) {
          if ((e?.meta?.statusCode || e?.statusCode) !== 409) throw e;
          archived = await archiveEvidenceRelationship(client, archiveInput, renew);
        }
        evidenceRollback.push({
          caseId: link.caseId,
          alertId: link.alertId,
          index: archived.index,
          previous: archived.previous,
          seqNo: archived.seqNo,
          primaryTerm: archived.primaryTerm,
        });
      }
      if (plan.archivedCaseLinks.length) {
        await renew();
        await client.indices.refresh({ index: EVIDENCE_WRITE_ALIAS });
      }
      await renew();
      try {
        await client.indices.updateAliases({
          body: {
            actions: [
              { remove: { index: retiringIndex, alias: ALERTS_READ_ALIAS } },
              { remove: { index: retiringIndex, alias: ALERTS_WRITE_ALIAS } },
              { add: { index: target, alias: ALERTS_READ_ALIAS } },
            ],
          },
        });
      } catch (e) {
        const [readMembers, writeMembers] = await Promise.all([
          aliasIndices(client, ALERTS_READ_ALIAS),
          aliasIndices(client, ALERTS_WRITE_ALIAS),
        ]);
        assertPlannedWriter(writeMembers, plan);
        if (
          readMembers[retiringIndex] || !readMembers[target] || !readMembers[plan.writeIndex] ||
          writeMembers[retiringIndex] ||
          writeMembers[target]?.aliases?.[ALERTS_WRITE_ALIAS]?.is_write_index === true
        ) {
          throw e;
        }
      }
      cutover = true;
    return completeRetirement(client, lease, logger);
  } catch (e: any) {
    if (e instanceof RetirementLeaseLostError) throw e;
    if (!cutover) {
      let cleanupError: any = null;
      for (const item of evidenceRollback.reverse()) {
        try {
          await renew();
          if (item.previous) {
            await client.index({
              index: assertManagedWriteTarget(item.index),
              id: evidenceId(item.caseId, item.alertId),
              body: item.previous,
              refresh: false,
              if_seq_no: item.seqNo,
              if_primary_term: item.primaryTerm,
            });
          } else {
            await client.delete({
              index: assertManagedWriteTarget(item.index),
              id: evidenceId(item.caseId, item.alertId),
              refresh: false,
              if_seq_no: item.seqNo,
              if_primary_term: item.primaryTerm,
            });
          }
        } catch (rollbackError: any) {
          logger.error(`wazuh-alert-manager lifecycle: failed to roll back evidence state: ${rollbackError.message}`);
          cleanupError = cleanupError || rollbackError;
        }
      }
      if (sourceBlocked) {
        try {
          await renew();
          await client.indices.putSettings({ index: retiringIndex, body: { 'index.blocks.write': false } });
        } catch (unblockError: any) {
          logger.error(
            `wazuh-alert-manager lifecycle: failed to unblock ${retiringIndex} after carry failure: ${unblockError.message}`
          );
          cleanupError = cleanupError || unblockError;
        }
      }
      if (!cleanupError) {
        try {
          await renew();
          const [readMembers, writeMembers] = await Promise.all([
            aliasIndices(client, ALERTS_READ_ALIAS),
            aliasIndices(client, ALERTS_WRITE_ALIAS),
          ]);
          if (
            !readMembers[retiringIndex] || readMembers[target] || writeMembers[target]
          ) {
            throw new Error('Retirement cleanup alias topology is ambiguous.');
          }
          await renew();
          await deleteUnattachedCarryTarget(client, target, renew);
          await renew();
          await deletePreparingClaim(client, retiringIndex, lease.seqNo, lease.primaryTerm);
        } catch (failure: any) {
          cleanupError = failure;
        }
      }
      if (cleanupError) {
        throw new Error(`${e.message}; retirement cleanup failed closed: ${cleanupError.message}`);
      }
    }
    throw e;
  }
}

export async function executeAlertRetirement(
  client: any,
  retiringIndex: string,
  actor: string,
  logger: Logger
) {
  if (!isManagedPhysicalIndex(retiringIndex, 'wazuh-alert-status-v2-')) {
    throw new Error('Only a physical wazuh-alert-status-v2-* generation can be retired.');
  }
  const existing = await getRetirementRecord(client, retiringIndex);
  let record: any;
  if (existing) {
    throw new Error(
      existing.status === 'preparing'
        ? `Retirement transaction for ${retiringIndex} is already in progress.`
        : `Retirement transaction for ${retiringIndex} is already ${existing.status || 'invalid'}.`
    );
  }

  const plan = await planAlertRetirement(client, retiringIndex);
  record = {
    status: 'preparing',
    retiring_index: retiringIndex,
    carry_index: deterministicCarryIndex(retiringIndex),
    holder_id: newHolderId(),
    expires_at: leaseExpiry(),
    actor,
    started_at: new Date().toISOString(),
    plan,
  };
  let claim: any;
  try {
    claim = await client.index({
      index: assertManagedWriteTarget(META_INDEX),
      id: `${RETIREMENT_DOC_PREFIX}${retiringIndex}`,
      op_type: 'create',
      refresh: 'wait_for',
      body: record,
    });
  } catch (e: any) {
    if ((e?.meta?.statusCode || e?.statusCode) === 409) {
      throw new Error(`Retirement transaction for ${retiringIndex} is already in progress.`);
    }
    throw e;
  }
  const seqNo = claim?.body?._seq_no;
  const primaryTerm = claim?.body?._primary_term;
  if (!Number.isInteger(seqNo) || !Number.isInteger(primaryTerm)) {
    throw new Error('Retirement claim did not return optimistic concurrency metadata.');
  }
  return runClaimedAlertRetirement(client, { record, seqNo, primaryTerm }, logger);
}

async function clearTransactionEvidenceArchive(
  client: any,
  retiringIndex: string,
  link: { caseId: string; alertId: string },
  renew: () => Promise<void>
): Promise<void> {
  const id = evidenceId(link.caseId, link.alertId);
  for (let attempt = 0; attempt < 3; attempt += 1) {
    let location: any;
    try {
      await renew();
      location = await getEvidenceLocation(client, link.caseId, link.alertId);
    } catch (e: any) {
      if ((e?.meta?.statusCode || e?.statusCode) === 404) return;
      throw e;
    }
    if (!location) return;
    const source = location.source;
    if (!source || typeof location.seqNo !== 'number' || typeof location.primaryTerm !== 'number') {
      throw new Error(`Evidence cleanup for ${link.caseId}/${link.alertId} lacks OCC metadata.`);
    }
    const physicalIndex = location.index;
    if (!isManagedPhysicalIndex(physicalIndex, 'wazuh-alert-manager-v2-evidence-')) {
      throw new Error(`Evidence cleanup resolved outside the managed evidence family: ${physicalIndex || '<unknown>'}.`);
    }
    if (source.archive_index == null) return;
    if (source.archive_index !== retiringIndex || source.archive_id !== link.alertId) {
      throw new Error(`Evidence cleanup for ${link.caseId}/${link.alertId} found an ambiguous archive locator.`);
    }
    try {
      await renew();
      await client.update({
        index: assertManagedWriteTarget(physicalIndex),
        id,
        if_seq_no: location.seqNo,
        if_primary_term: location.primaryTerm,
        refresh: 'wait_for',
        body: {
          script: {
            lang: 'painless',
            source:
              'if (ctx._source.archive_index == params.archive_index && ctx._source.archive_id == params.archive_id) { ' +
              'ctx._source.archive_index = null; ctx._source.archive_id = null; ctx._source.archived_at = null; ' +
              'ctx._source.relationship_state = (ctx._source.hold_reason != null || ctx._source.hold_since != null || ctx._source.relationship_state == "held") ? "held" : "linked"; ' +
              '} else { ctx.op = "none"; }',
            params: { archive_index: retiringIndex, archive_id: link.alertId },
          },
        },
      });
      return;
    } catch (e: any) {
      const status = e?.meta?.statusCode || e?.statusCode;
      if (status === 404) return;
      if (status !== 409 || attempt === 2) throw e;
    }
  }
}

async function abortPreparingRetirement(
  client: any,
  lease: RetirementLease
): Promise<void> {
  const { plan, retiringIndex, target } = validateRetirementTransaction(lease.record, ['recovering']);
  const renew = () => renewRetirementLease(client, lease);
  await renew();
  await client.indices.putSettings({ index: retiringIndex, body: { 'index.blocks.write': false } });
  for (const link of plan.archivedCaseLinks) {
    await clearTransactionEvidenceArchive(client, retiringIndex, link, renew);
  }
  await renew();
  const [readMembers, writeMembers] = await Promise.all([
    aliasIndices(client, ALERTS_READ_ALIAS),
    aliasIndices(client, ALERTS_WRITE_ALIAS),
  ]);
  if (
    !readMembers[retiringIndex] || readMembers[target] || writeMembers[target]
  ) {
    throw new Error(`Preparing retirement cleanup topology for ${retiringIndex} became ambiguous.`);
  }
  await deleteUnattachedCarryTarget(client, target, renew);
  await renew();
  await deletePreparingClaim(client, retiringIndex, lease.seqNo, lease.primaryTerm);
}

async function takeRecoveryLease(
  client: any,
  hit: any
): Promise<{ lease: RetirementLease; quiescing: boolean } | null> {
  const source = hit?._source;
  const { retiringIndex } = validateRetirementTransaction(source, ['preparing', 'recovering']);
  const expiresAt = Date.parse(source.expires_at);
  if (expiresAt > Date.now()) return null;
  const seqNo = hit?._seq_no;
  const primaryTerm = hit?._primary_term;
  if (!Number.isInteger(seqNo) || !Number.isInteger(primaryTerm)) {
    throw new Error(`Retirement metadata ${hit?._id || '<unknown>'} lacks OCC metadata.`);
  }
  const record = {
    ...source,
    status: 'recovering',
    holder_id: newHolderId(),
    expires_at: leaseExpiry(),
  };
  try {
    const result: any = await client.index({
      index: assertManagedWriteTarget(META_INDEX),
      id: `${RETIREMENT_DOC_PREFIX}${retiringIndex}`,
      if_seq_no: seqNo,
      if_primary_term: primaryTerm,
      refresh: 'wait_for',
      body: record,
    });
    const nextSeqNo = result?.body?._seq_no;
    const nextPrimaryTerm = result?.body?._primary_term;
    if (!Number.isInteger(nextSeqNo) || !Number.isInteger(nextPrimaryTerm)) {
      throw new Error(`Recovery claim for ${retiringIndex} returned no OCC metadata.`);
    }
    return {
      lease: { record, seqNo: nextSeqNo, primaryTerm: nextPrimaryTerm },
      quiescing: source.status === 'preparing',
    };
  } catch (e: any) {
    if ((e?.meta?.statusCode || e?.statusCode) === 409 || (e?.meta?.statusCode || e?.statusCode) === 404) {
      return null;
    }
    throw e;
  }
}

/** First fence expired API work for one TTL; only stale recovering leases may mutate retirement state. */
export async function recoverPreparingAlertRetirements(client: any, logger: Logger): Promise<number> {
  const result: any = await client.search({
    index: META_INDEX,
    body: {
      size: MAX_PREPARING_RETIREMENTS,
      track_total_hits: true,
      query: {
        bool: {
          filter: [
            { terms: { status: ['preparing', 'recovering'] } },
          ],
        },
      },
      _source: true,
    },
  });
  const hits = result?.body?.hits?.hits;
  if (!Array.isArray(hits)) throw new Error('Preparing retirement recovery scan returned no hits.');
  const rawTotal = result?.body?.hits?.total;
  const total = typeof rawTotal === 'number' ? rawTotal : Number(rawTotal?.value ?? hits.length);
  if (total > hits.length) {
    throw new Error(`Retirement recovery exceeds safe scan limit (${MAX_PREPARING_RETIREMENTS}).`);
  }
  let recovered = 0;
  for (const hit of hits) {
    const record = hit?._source;
    if (!['preparing', 'recovering'].includes(record?.status)) continue;
    if (hit?._id !== `${RETIREMENT_DOC_PREFIX}${record?.retiring_index || ''}`) {
      throw new Error(`Preparing retirement metadata ${hit?._id || '<unknown>'} is inconsistent.`);
    }
    const takeover = await takeRecoveryLease(client, hit);
    if (!takeover) continue;
    if (takeover.quiescing) {
      recovered += 1;
      continue;
    }
    const lease = takeover.lease;
    const renew = () => renewRetirementLease(client, lease);
    const { retiringIndex, target } = validateRetirementTransaction(lease.record, ['recovering']);
    await renew();
    const [readMembers, writeMembers] = await Promise.all([
      aliasIndices(client, ALERTS_READ_ALIAS),
      aliasIndices(client, ALERTS_WRITE_ALIAS),
    ]);
    const sourceAttached = Boolean(readMembers[retiringIndex]);
    const targetAttached = Boolean(readMembers[target]);
    if (!sourceAttached && targetAttached) {
      assertCurrentRolloverWriter(readMembers, writeMembers, retiringIndex, target);
      await assertReadOnlyCarryTarget(client, target, renew);
      await renew();
      await completeRetirement(client, lease, logger);
    } else if (sourceAttached && !targetAttached) {
      if (writeMembers[target]) {
        throw new Error(`Preparing retirement carry target ${target} is attached to the write alias.`);
      }
      await abortPreparingRetirement(client, lease);
    } else {
      throw new Error(`Preparing retirement aliases for ${retiringIndex} are ambiguous.`);
    }
    recovered += 1;
  }
  return recovered;
}

export function startRetirementRecoveryJob(client: any, logger: Logger): () => void {
  const run = () => recoverPreparingAlertRetirements(client, logger).catch((e) =>
    logger.warn(`wazuh-alert-manager lifecycle: retirement recovery failed: ${e.message}`)
  );
  run();
  const timer = setInterval(run, RETIREMENT_RECOVERY_INTERVAL_MS);
  return () => clearInterval(timer);
}

/**
 * Restore archive-only alerts into the current live write generation.
 *
 * Existing live IDs always win, which is critical because carried alerts may
 * have been updated after retirement. The archive remains immutable and
 * retained, making the operation idempotent and reversible by normal triage.
 */
export async function restoreRetiredAlertIndex(client: any, index: string, actor: string) {
  if (!isManagedPhysicalIndex(index, 'wazuh-alert-status-v2-')) {
    throw new Error('Only a physical wazuh-alert-status-v2-* generation can be restored.');
  }
  const [readMembers, writeMembers, retirement]: any[] = await Promise.all([
    aliasIndices(client, ALERTS_READ_ALIAS),
    aliasIndices(client, ALERTS_WRITE_ALIAS),
    safeGet(client, META_INDEX, `retirement:${index}`),
  ]);
  if (readMembers[index] || writeMembers[index]) {
    throw new Error('The generation is already attached to a live alias.');
  }
  if (!retirement || retirement.retiring_index !== index || !['completed', 'restored'].includes(retirement.status)) {
    throw new Error('No completed retirement record exists for this index.');
  }

  let examined = 0;
  let restored = 0;
  let alreadyLive = 0;
  let scrollId: string | undefined;
  try {
    let page: any = await client.search({
      index,
      scroll: '2m',
      size: 500,
      body: { query: { match_all: {} }, sort: ['_doc'] },
    });
    while (true) {
      scrollId = page?.body?._scroll_id;
      const hits = page?.body?.hits?.hits || [];
      if (!hits.length) break;
      examined += hits.length;
      const ids = hits.map((hit: any) => hit._id);
      const live: any = await client.search({
        index: ALERTS_READ_ALIAS,
        size: ids.length,
        body: { query: { ids: { values: ids } }, _source: false },
      });
      const liveIds = new Set((live?.body?.hits?.hits || []).map((hit: any) => hit._id));
      const missing = hits.filter((hit: any) => !liveIds.has(hit._id));
      alreadyLive += hits.length - missing.length;
      if (missing.length) {
        const bulk: any[] = [];
        for (const hit of missing) {
          bulk.push({ create: { _index: assertManagedWriteTarget(ALERTS_WRITE_ALIAS), _id: hit._id } }, hit._source);
        }
        const result: any = await client.bulk({ body: bulk, refresh: false });
        for (const item of result?.body?.items || []) {
          const operation = item.create;
          if (operation?.status === 409) {
            alreadyLive += 1;
          } else if (operation?.error) {
            throw new Error(`Restore bulk failed: ${JSON.stringify(operation.error)}`);
          } else {
            restored += 1;
          }
        }
      }
      page = await client.scroll({ scrollId, scroll: '2m' });
    }
  } finally {
    if (scrollId) {
      try {
        await client.clearScroll({ scrollId });
      } catch (e) {
        // Expired scroll contexts are harmless after a completed restore.
      }
    }
  }
  await client.indices.refresh({ index: ALERTS_WRITE_ALIAS });
  const restoredAt = new Date().toISOString();
  await client.index({
    index: assertManagedWriteTarget(META_INDEX),
    id: `retirement:${index}`,
    body: {
      ...retirement,
      status: 'restored',
      restored_at: restoredAt,
      restored_by: actor,
      restored_documents: restored,
      already_live_documents: alreadyLive,
      source_retained: true,
    },
    refresh: 'wait_for',
  });
  await appendActivity(client, {
    targetType: 'system',
    targetId: index,
    user: actor,
    action: 'restored retired alert generation',
    from: `${examined} archived documents examined`,
    to: `${restored} missing documents restored; ${alreadyLive} existing live versions preserved`,
    source: 'lifecycle',
  });
  return { index, examined, restored, alreadyLive, archiveRetained: true };
}

/** Permanently remove a previously retired source generation after explicit confirmation. */
export async function purgeRetiredAlertIndex(client: any, index: string, actor: string) {
  if (!isManagedPhysicalIndex(index, 'wazuh-alert-status-v2-')) {
    throw new Error('Only a physical wazuh-alert-status-v2-* generation can be purged.');
  }
  const [readMembers, writeMembers, record]: any[] = await Promise.all([
    aliasIndices(client, ALERTS_READ_ALIAS),
    aliasIndices(client, ALERTS_WRITE_ALIAS),
    safeGet(client, META_INDEX, `retirement:${index}`),
  ]);
  if (readMembers[index] || writeMembers[index]) {
    throw new Error('The index is still attached to a live alias and cannot be purged.');
  }
  if (!['completed', 'restored', 'purging', 'purged'].includes(record?.status) || record?.retiring_index !== index) {
    throw new Error('No completed carry-forward retirement record exists for this index.');
  }
  if (record.status === 'purged') return { index, purged: true, evidenceUpdated: record.evidence_updated || 0 };

  const validateProtections = async () => {
    let references = 0;
    let held = 0;
    const caseIds = new Set<string>();
    await scanArchiveEvidence(client, index, async (hits) => {
      references += hits.length;
      for (const hit of hits) {
        if (isEvidenceHeld(hit._source)) held += 1;
        if (hit._source?.case_id) caseIds.add(hit._source.case_id);
      }
      if (held) throw new Error('The archive has evidence holds and cannot be purged.');
    });
    for (const caseId of caseIds) {
      let caseStatus: string | null = null;
      try { caseStatus = await loadCaseStatus(client, caseId); } catch (e) { /* fail closed */ }
      if (caseStatus !== 'closed') {
        throw new Error('The archive is referenced by an active or unavailable case and cannot be purged.');
      }
    }
    if (references) {
      const lifecycle = await loadLifecycleSettings(client);
      const completedAt = Date.parse(record.completed_at || '');
      if (!lifecycle || !Number.isFinite(completedAt)) {
        throw new Error('Full-evidence retention cannot be verified, so the archive cannot be purged.');
      }
      const ageDays = (Date.now() - completedAt) / 86400000;
      if (ageDays < lifecycle.evidenceRetentionDays) {
        throw new Error(
          `Full-evidence retention requires ${lifecycle.evidenceRetentionDays} days; this archive is ${Math.floor(ageDays)} days old.`
        );
      }
    }
    return references;
  };

  let archiveExists = true;
  let tombstones = record.tombstones || 0;
  const purgeStartedAt = record.purge_started_at || new Date().toISOString();
  const purgeStartedBy = record.purge_started_by || actor;
  try {
    const settings: any = await client.indices.getSettings({ index });
    if (settings?.body?.[index]?.settings?.index?.blocks?.write !== 'true') {
      throw new Error('The retired source index is not write-blocked.');
    }
  } catch (e: any) {
    if (e?.meta?.statusCode !== 404 || record.status !== 'purging') throw e;
    archiveExists = false;
  }

  let referenceCount = record.evidence_references || 0;
  if (archiveExists) {
    referenceCount = await validateProtections();
    const purgingRecord = {
      ...record,
      status: 'purging',
      purge_started_at: purgeStartedAt,
      purge_started_by: purgeStartedBy,
      evidence_references: referenceCount,
    };
    await client.index({
      index: assertManagedWriteTarget(META_INDEX),
      id: `retirement:${index}`,
      body: purgingRecord,
      refresh: 'wait_for',
    });

    const [freshRead, freshWrite, freshSettings]: any[] = await Promise.all([
      aliasIndices(client, ALERTS_READ_ALIAS),
      aliasIndices(client, ALERTS_WRITE_ALIAS),
      client.indices.getSettings({ index }),
    ]);
    if (freshRead[index] || freshWrite[index]) {
      throw new Error('The index became attached to a live alias and cannot be purged.');
    }
    if (freshSettings?.body?.[index]?.settings?.index?.blocks?.write !== 'true') {
      throw new Error('The retired source index is not write-blocked.');
    }
    await validateProtections();
    tombstones = await createPurgeTombstones(client, index, purgeStartedAt);
    await client.index({
      index: assertManagedWriteTarget(META_INDEX),
      id: `retirement:${index}`,
      body: { ...purgingRecord, tombstones },
      refresh: 'wait_for',
    });
    await client.indices.delete({ index: assertManagedWriteTarget(index) });
  }

  const purgedAt = new Date().toISOString();
  let evidenceUpdated = 0;
  await scanArchiveEvidence(client, index, async (hits) => {
    const body: any[] = [];
    for (const hit of hits) {
      body.push({ index: { _index: assertManagedWriteTarget(hit._index), _id: hit._id } });
      body.push({ ...hit._source, relationship_state: 'purged', purged_at: purgedAt });
    }
    const result: any = await client.bulk({ body, refresh: false });
    const items = result?.body?.items;
    if (!Array.isArray(items) || items.length !== hits.length) {
      throw new Error('Evidence purge bulk returned an incomplete item response.');
    }
    for (const item of items) {
      const detail = item?.index;
      const status = Number(detail?.status || 0);
      if (!detail || detail.error || status < 200 || status >= 300) {
        throw new Error(`Evidence purge bulk failed: ${JSON.stringify(detail?.error || detail)}`);
      }
    }
    evidenceUpdated += hits.length;
  });
  if (evidenceUpdated) await client.indices.refresh({ index: EVIDENCE_READ_ALIAS });
  await client.index({
    index: assertManagedWriteTarget(META_INDEX),
    id: `retirement:${index}`,
    body: {
      ...record,
      status: 'purged',
      purge_started_at: purgeStartedAt,
      purge_started_by: purgeStartedBy,
      purged_at: purgedAt,
      purged_by: actor,
      evidence_references: referenceCount,
      evidence_updated: evidenceUpdated,
      tombstones,
    },
    refresh: 'wait_for',
  });
  return { index, purged: true, evidenceUpdated };
}
