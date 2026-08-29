import crypto from 'crypto';
import { CASES_INDEX, EVIDENCE_READ_ALIAS, EVIDENCE_WRITE_ALIAS, META_INDEX } from '../../common';
import { EvidenceListResponse } from '../../common';
import { assertManagedWriteTarget, isManagedPhysicalIndex } from './index_namespace';
import { resolveAlerts } from './index_resolution';

export const CASE_EVIDENCE_BACKFILL_DOC_ID = 'case_evidence_backfill_v1';
const LEGACY_FALLBACK_LIMIT = 1000;

// Multi-valued MITRE fields arrive as an array from most decoders but as a bare
// scalar from some; coerce both without throwing.
function asArray<T>(v: T | T[] | null | undefined): T[] {
  if (v == null) return [];
  return Array.isArray(v) ? v.filter((x) => x != null) : [v];
}

/** Stable relationship ID derived from case + alert, so the same link always
 * maps to the same document regardless of which code path created it. */
export function evidenceId(caseId: string, alertId: string): string {
  return crypto.createHash('sha256').update(`${caseId}\u0000${alertId}`, 'utf8').digest('hex');
}

/** Bounded snapshot: exactly the fields case display and attack-path
 * reconstruction need. Deliberately NOT a second full alert copy — raw payload,
 * comments, AI output, and mutable triage history stay in their own stores. */
export function buildEvidenceSnapshot(alertSource: any): any {
  const s = alertSource || {};
  const data = s.data && typeof s.data === 'object' ? s.data : {};
  const processValue = data.process;
  const processName =
    processValue && typeof processValue === 'object'
      ? processValue.name
      : data.process_name ?? processValue;
  return {
    status: s.status || null,
    '@timestamp': s['@timestamp'] || null,
    assigned_to: s.assigned_to ?? null,
    agent: s.agent
      ? { id: s.agent.id ?? null, name: s.agent.name ?? null, ip: s.agent.ip ?? null }
      : null,
    rule: s.rule
      ? {
          id: s.rule.id ?? null,
          level: typeof s.rule.level === 'number' ? s.rule.level : Number(s.rule.level || 0),
          description: s.rule.description ?? null,
          mitre: s.rule.mitre
            ? {
                id: asArray<string>(s.rule.mitre.id),
                technique: asArray<string>(s.rule.mitre.technique),
                tactic: asArray<string>(s.rule.mitre.tactic),
              }
            : null,
        }
      : null,
    data: {
      srcip: data.srcip ?? null,
      dstip: data.dstip ?? null,
      srcuser: data.srcuser ?? null,
      dstuser: data.dstuser ?? null,
      process: processName ? { name: processName } : null,
    },
  };
}

export interface EvidenceInput {
  caseId: string;
  alertId: string;
  alertSource: any;
  /** Trusted plugin-owned physical index holding the full alert (set at retirement). */
  archiveIndex?: string | null;
  archiveId?: string | null;
  /** Read-only native provenance (never written back to wazuh-alerts-*). */
  sourceIndex?: string | null;
  sourceId?: string | null;
  relationshipState?: string;
  holdReason?: string | null;
  holdBy?: string | null;
  holdSince?: string | null;
  linkedAt?: string;
  archivedAt?: string | null;
}

/** Assemble one bounded case-alert relationship document. */
export function buildEvidenceDocument(input: EvidenceInput): any {
  const now = input.linkedAt || new Date().toISOString();
  return {
    case_id: input.caseId,
    alert_id: input.alertId,
    relationship_state: input.relationshipState || 'linked',
    hold_reason: input.holdReason ?? null,
    hold_by: input.holdBy ?? null,
    hold_since: input.holdSince ?? null,
    archive_index: input.archiveIndex ?? null,
    archive_id: input.archiveId ?? input.alertId,
    source_index: input.sourceIndex ?? null,
    source_id: input.sourceId ?? null,
    linked_at: now,
    archived_at: input.archivedAt ?? null,
    snapshot: buildEvidenceSnapshot(input.alertSource),
  };
}

/** Fail-closed write targets for the evidence family. */
export const evidenceReadTarget = () => assertManagedWriteTarget(EVIDENCE_READ_ALIAS);
export const evidenceWriteTarget = () => assertManagedWriteTarget(EVIDENCE_WRITE_ALIAS);

export interface EvidenceLocation {
  index: string;
  id: string;
  source: any;
  seqNo?: number;
  primaryTerm?: number;
}

type CursorSortValue = string | number;

export function encodePageCursor(scope: string, sort: CursorSortValue[]): string {
  return Buffer.from(JSON.stringify({ v: 1, scope, sort }), 'utf8').toString('base64');
}

export function decodePageCursor(cursor: string | undefined, scope: string): CursorSortValue[] | undefined {
  if (!cursor) return undefined;
  try {
    const parsed = JSON.parse(Buffer.from(cursor, 'base64').toString('utf8'));
    if (
      parsed?.v !== 1 ||
      parsed?.scope !== scope ||
      !Array.isArray(parsed.sort) ||
      parsed.sort.length !== 2 ||
      !parsed.sort.every((value: any) => typeof value === 'string' || typeof value === 'number')
    ) {
      throw new Error();
    }
    return parsed.sort;
  } catch (e) {
    const error: any = new Error('Invalid or mismatched pagination cursor.');
    error.statusCode = 400;
    throw error;
  }
}

export function exactHitTotal(hits: any): number {
  const total = hits?.total;
  return typeof total === 'number' ? total : Number(total?.value || 0);
}

export function isEvidenceHeld(evidence: any): boolean {
  return Boolean(
    evidence?.hold_reason || evidence?.hold_since || evidence?.relationship_state === 'held'
  );
}

export async function getEvidenceLocation(client: any, caseId: string, alertId: string): Promise<EvidenceLocation | null> {
  const id = evidenceId(caseId, alertId);
  try {
    const res: any = await client.get({ index: EVIDENCE_READ_ALIAS, id });
    const index = res?.body?._index || EVIDENCE_WRITE_ALIAS;
    if (index !== EVIDENCE_WRITE_ALIAS && !isManagedPhysicalIndex(index, 'wazuh-alert-manager-v2-evidence-')) {
      throw new Error(`Evidence alias resolved outside its managed family: ${index}`);
    }
    const seqNo = res?.body?._seq_no;
    const primaryTerm = res?.body?._primary_term;
    return { index, id, source: res?.body?._source ?? null, seqNo, primaryTerm };
  } catch (e: any) {
    if (e?.meta?.statusCode === 404) return null;
    // Point GET rejects an alias after rollover once it resolves to multiple
    // physical indices. Resolve the exact ID by search and retain the physical
    // target plus OCC metadata for the subsequent mutation.
    if (e?.meta?.statusCode !== 400) throw e;
    const result: any = await client.search({
      index: EVIDENCE_READ_ALIAS,
      body: {
        size: 10,
        seq_no_primary_term: true,
        track_total_hits: true,
        query: { ids: { values: [id] } },
        sort: [{ _index: { order: 'desc' } }],
      },
    });
    const hits = result?.body?.hits?.hits || [];
    if (!hits.length) return null;
    const hit = hits[0];
    if (!isManagedPhysicalIndex(hit._index, 'wazuh-alert-manager-v2-evidence-')) {
      throw new Error(`Evidence alias resolved outside its managed family: ${hit._index}`);
    }
    return {
      index: hit._index,
      id,
      source: hit._source ?? null,
      seqNo: hit._seq_no,
      primaryTerm: hit._primary_term,
    };
  }
}

/** Visit every relationship for an archive in bounded 500-document pages. */
export async function scanArchiveEvidence(
  client: any,
  archiveIndex: string,
  visit: (hits: any[]) => Promise<void> | void
): Promise<number> {
  let total = 0;
  let scrollId: string | undefined;
  try {
    let page: any = await client.search({
      index: EVIDENCE_READ_ALIAS,
      scroll: '2m',
      size: 500,
      body: { query: { term: { archive_index: archiveIndex } }, sort: ['_doc'] },
    });
    while (true) {
      scrollId = page?.body?._scroll_id || scrollId;
      const hits = page?.body?.hits?.hits || [];
      if (!hits.length) break;
      for (const hit of hits) {
        if (!isManagedPhysicalIndex(hit._index, 'wazuh-alert-manager-v2-evidence-')) {
          throw new Error(`Evidence alias resolved outside its managed family: ${hit._index}`);
        }
      }
      await visit(hits);
      total += hits.length;
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
  return total;
}

/** Read one case-alert relationship, if it exists. */
export async function getEvidence(client: any, caseId: string, alertId: string): Promise<any | null> {
  return (await getEvidenceLocation(client, caseId, alertId))?.source ?? null;
}

export async function listCaseEvidence(
  client: any,
  caseId: string,
  options: { size?: number; cursor?: string } = {}
): Promise<EvidenceListResponse> {
  const size = Math.min(Math.max(options.size ?? 1000, 1), 1000);
  const searchAfter = decodePageCursor(options.cursor, `evidence:${caseId}`);
  const res: any = await client.search({
    index: EVIDENCE_READ_ALIAS,
    body: {
      size: size + 1,
      track_total_hits: true,
      sort: [{ linked_at: { order: 'asc' } }, { alert_id: { order: 'asc' } }],
      query: { term: { case_id: caseId } },
      ...(searchAfter ? { search_after: searchAfter } : {}),
    },
  });
  const hits = res?.body?.hits;
  const visible = (hits?.hits || []).slice(0, size);
  const truncated = (hits?.hits || []).length > size;
  return {
    evidence: visible.map((hit: any) => ({ id: hit._id, ...hit._source })),
    nextCursor: truncated && visible.length
      ? encodePageCursor(`evidence:${caseId}`, visible[visible.length - 1].sort)
      : null,
    total: exactHitTotal(hits),
    truncated,
  };
}

async function caseEvidenceBackfillComplete(client: any): Promise<boolean> {
  try {
    const result: any = await client.get({ index: META_INDEX, id: CASE_EVIDENCE_BACKFILL_DOC_ID });
    return result?.body?._source?.completed === true;
  } catch (e: any) {
    if (e?.meta?.statusCode === 404) return false;
    throw e;
  }
}

/**
 * Relationship documents are authoritative. Until the explicit backfill marker
 * is complete, append bounded synthetic relationships for legacy alert_ids that
 * do not yet have evidence. Existing evidence is never replaced or hidden.
 */
export async function listCaseEvidenceWithLegacy(
  client: any,
  caseId: string,
  legacyAlertIds: any,
  options: { size?: number; cursor?: string } = {}
): Promise<EvidenceListResponse> {
  const page = await listCaseEvidence(client, caseId, options);
  if (options.cursor || await caseEvidenceBackfillComplete(client)) return page;

  const legacyIds = Array.from(new Set(
    (Array.isArray(legacyAlertIds) ? legacyAlertIds : [])
      .filter((id: any) => typeof id === 'string' && id.length > 0)
      .slice(0, LEGACY_FALLBACK_LIMIT)
  )) as string[];
  if (!legacyIds.length) return page;

  const existing: any = await client.search({
    index: EVIDENCE_READ_ALIAS,
    body: {
      size: legacyIds.length,
      _source: ['alert_id'],
      query: { ids: { values: legacyIds.map((alertId) => evidenceId(caseId, alertId)) } },
    },
  });
  const represented = new Set(
    (existing?.body?.hits?.hits || []).map((doc: any) => doc?._source?.alert_id)
  );
  const fallback = legacyIds
    .filter((alertId) => !represented.has(alertId))
    .map((alertId) => ({
      id: evidenceId(caseId, alertId),
      case_id: caseId,
      alert_id: alertId,
      relationship_state: 'legacy',
      snapshot: null,
      legacy_fallback: true,
    }));
  return {
    ...page,
    evidence: [...page.evidence, ...fallback],
    total: page.total + fallback.length,
  };
}

export interface CaseEvidenceBackfillResult {
  completed: boolean;
  processedCases: number;
  attemptedRelationships: number;
  createdRelationships: number;
  existingRelationships: number;
  nextCaseId: string | null;
}

function bulkFailure(item: any): string | null {
  const detail = item?.create;
  const status = Number(detail?.status || 0);
  if (!detail) return 'Bulk response item did not contain a create result.';
  if (status === 409 || (!detail.error && status >= 200 && status < 300)) return null;
  return detail?.error?.reason || `Evidence create returned status ${status || 'unknown'}.`;
}

/** Resume the deterministic case alert_ids -> evidence migration. */
export async function backfillCaseEvidence(
  client: any,
  input: { actor: string; batchSize?: number; timestamp?: string }
): Promise<CaseEvidenceBackfillResult> {
  const batchSize = Math.min(Math.max(input.batchSize ?? 50, 1), 200);
  let progress: any = null;
  try {
    const result: any = await client.get({ index: META_INDEX, id: CASE_EVIDENCE_BACKFILL_DOC_ID });
    progress = result?.body?._source || null;
  } catch (e: any) {
    if (e?.meta?.statusCode !== 404) throw e;
  }
  if (progress?.completed === true) {
    return {
      completed: true,
      processedCases: 0,
      attemptedRelationships: 0,
      createdRelationships: 0,
      existingRelationships: 0,
      nextCaseId: null,
    };
  }

  const response: any = await client.search({
    index: CASES_INDEX,
    body: {
      size: batchSize,
      sort: [{ _doc: { order: 'asc' } }],
      _source: ['alert_ids'],
      ...(progress?.last_case_sort != null ? { search_after: [progress.last_case_sort] } : {}),
      query: { match_all: {} },
    },
  });
  const cases = response?.body?.hits?.hits || [];
  const operations: any[] = [];
  for (const caseHit of cases) {
    const rawIds = caseHit?._source?.alert_ids;
    if (rawIds != null && !Array.isArray(rawIds)) {
      throw new Error(`Case ${caseHit._id} has invalid alert_ids; expected an array.`);
    }
    const ids = Array.from(new Set(rawIds || []));
    if (ids.length > LEGACY_FALLBACK_LIMIT || ids.some((id: any) => typeof id !== 'string' || !id)) {
      throw new Error(`Case ${caseHit._id} has invalid alert_ids items.`);
    }
    const locations = await resolveAlerts(client, ids as string[], true);
    for (const alertId of ids as string[]) {
      const location = locations.get(alertId);
      operations.push(
        { create: { _index: evidenceWriteTarget(), _id: evidenceId(caseHit._id, alertId) } },
        buildEvidenceDocument({
          caseId: caseHit._id,
          alertId,
          alertSource: location?.source || {},
          sourceIndex: location?.source?.source_index ?? null,
          sourceId: location?.source?.source_id ?? null,
          relationshipState: location ? 'linked' : 'legacy',
          linkedAt: input.timestamp,
        })
      );
    }
  }

  let createdRelationships = 0;
  let existingRelationships = 0;
  const relationshipCount = operations.length / 2;
  for (let offset = 0; offset < relationshipCount; offset += 500) {
    const count = Math.min(500, relationshipCount - offset);
    const bulk: any = await client.bulk({
      refresh: 'wait_for',
      body: operations.slice(offset * 2, (offset + count) * 2),
    });
    const items = bulk?.body?.items;
    if (!Array.isArray(items) || items.length !== count) {
      throw new Error(`Evidence backfill bulk returned ${Array.isArray(items) ? items.length : 0} item(s) for ${count} relationship(s).`);
    }
    const failures = items.map(bulkFailure).filter(Boolean);
    if (failures.length) throw new Error(`Evidence backfill failed: ${failures[0]}`);
    const conflicts = items.filter((item: any) => Number(item?.create?.status) === 409).length;
    existingRelationships += conflicts;
    createdRelationships += items.length - conflicts;
  }

  const now = input.timestamp || new Date().toISOString();
  const lastCaseId = cases.length ? cases[cases.length - 1]._id : progress?.last_case_id || null;
  const lastCaseSort = cases.length ? cases[cases.length - 1].sort?.[0] : progress?.last_case_sort;
  const completed = cases.length === 0;
  await client.index({
    index: assertManagedWriteTarget(META_INDEX),
    id: CASE_EVIDENCE_BACKFILL_DOC_ID,
    refresh: 'wait_for',
    body: {
      completed,
      last_case_id: completed ? null : lastCaseId,
      last_case_sort: completed ? null : lastCaseSort,
      processed_cases: Number(progress?.processed_cases || 0) + cases.length,
      processed_relationships: Number(progress?.processed_relationships || 0) + relationshipCount,
      updated_at: now,
      updated_by: input.actor,
      ...(completed ? { completed_at: now } : {}),
    },
  });
  return {
    completed,
    processedCases: cases.length,
    attemptedRelationships: relationshipCount,
    createdRelationships,
    existingRelationships,
    nextCaseId: completed ? null : lastCaseId,
  };
}

/** Mutate only hold fields so snapshots and trusted archive locators survive. */
export async function setEvidenceHold(
  client: any,
  caseId: string,
  alertId: string,
  hold: { reason: string; by: string; since?: string } | null
): Promise<any> {
  const location = await getEvidenceLocation(client, caseId, alertId);
  if (!location?.source) throw new Error('Evidence relationship was not found.');
  if (
    typeof location.seqNo !== 'number' || !Number.isInteger(location.seqNo) || location.seqNo < 0 ||
    typeof location.primaryTerm !== 'number' || !Number.isInteger(location.primaryTerm) || location.primaryTerm < 1
  ) {
    throw new Error('Evidence read did not return optimistic concurrency metadata.');
  }
  const existing = location.source;
  const holdSince = hold ? existing.hold_since || hold.since || new Date().toISOString() : null;
  const next = {
    ...existing,
    relationship_state: hold ? 'held' : existing.archive_index ? 'archived' : 'linked',
    hold_reason: hold?.reason ?? null,
    hold_by: hold?.by ?? null,
    hold_since: holdSince,
  };
  await client.update({
    index: assertManagedWriteTarget(location.index),
    id: location.id,
    if_seq_no: location.seqNo,
    if_primary_term: location.primaryTerm,
    body: {
      script: {
        lang: 'painless',
        source:
          'if (params.held) { ctx._source.relationship_state = "held"; ctx._source.hold_reason = params.reason; ctx._source.hold_by = params.by; if (ctx._source.hold_since == null) { ctx._source.hold_since = params.since; } } ' +
          'else { ctx._source.relationship_state = ctx._source.archive_index != null ? "archived" : "linked"; ctx._source.hold_reason = null; ctx._source.hold_by = null; ctx._source.hold_since = null; }',
        params: {
          held: Boolean(hold),
          reason: hold?.reason ?? null,
          by: hold?.by ?? null,
          since: holdSince,
        },
      },
    },
    refresh: 'wait_for',
  });
  return next;
}

/** Create or replace the bounded relationship document for one case-alert link. */
export async function upsertEvidenceRelationship(client: any, input: EvidenceInput): Promise<any> {
  const doc = buildEvidenceDocument(input);
  const existing = await getEvidenceLocation(client, input.caseId, input.alertId);
  await client.index({
    index: assertManagedWriteTarget(existing?.index || EVIDENCE_WRITE_ALIAS),
    id: existing?.id || evidenceId(input.caseId, input.alertId),
    body: doc,
    refresh: false,
  });
  return doc;
}

/** Record a trusted full-alert archive while preserving prior hold/provenance metadata. */
export async function archiveEvidenceRelationship(
  client: any,
  input: EvidenceInput & { archiveIndex: string; archiveId: string },
  beforeWrite?: () => Promise<void>
): Promise<{
  previous: any | null;
  current: any;
  index: string;
  seqNo: number;
  primaryTerm: number;
}> {
  if (!isManagedPhysicalIndex(input.archiveIndex, 'wazuh-alert-status-v2-')) {
    throw new Error(`Refusing untrusted evidence archive location: ${input.archiveIndex}`);
  }
  const location = await getEvidenceLocation(client, input.caseId, input.alertId);
  if (location && (location.seqNo === undefined || location.primaryTerm === undefined)) {
    throw new Error('Evidence read did not return optimistic concurrency metadata.');
  }
  const previous = location?.source ?? null;
  const archivedAt = input.archivedAt || new Date().toISOString();
  const current = previous
    ? {
        ...previous,
        relationship_state: isEvidenceHeld(previous) ? 'held' : 'archived',
        archive_index: input.archiveIndex,
        archive_id: input.archiveId,
        archived_at: archivedAt,
      }
    : buildEvidenceDocument({
        ...input,
        relationshipState: input.holdReason || input.holdSince ? 'held' : 'archived',
        archivedAt,
      });
  const index = assertManagedWriteTarget(location?.index || EVIDENCE_WRITE_ALIAS);
  if (beforeWrite) await beforeWrite();
  const result: any = await client.index({
    index,
    id: evidenceId(input.caseId, input.alertId),
    body: current,
    refresh: false,
    ...(location
      ? { if_seq_no: location.seqNo!, if_primary_term: location.primaryTerm! }
      : { op_type: 'create' }),
  });
  const seqNo = result?.body?._seq_no;
  const primaryTerm = result?.body?._primary_term;
  if (seqNo === undefined || primaryTerm === undefined) {
    throw new Error('Evidence archive write did not return optimistic concurrency metadata.');
  }
  return { previous, current, index, seqNo, primaryTerm };
}

/** Remove the relationship document when an alert is unlinked from a case. */
export async function removeEvidenceRelationship(client: any, caseId: string, alertId: string): Promise<void> {
  const location = await getEvidenceLocation(client, caseId, alertId);
  if (!location) return;
  if (isEvidenceHeld(location.source)) throw new Error('Held evidence cannot be unlinked.');
  try {
    await client.delete({ index: assertManagedWriteTarget(location.index), id: location.id });
  } catch (e: any) {
    if (e?.meta?.statusCode !== 404) throw e;
  }
}

/**
 * Resolve the full alert for one piece of case evidence directly from its
 * trusted plugin archive location. The location must already be recorded in the
 * evidence document and pass the managed-namespace check — a browser can never
 * supply an arbitrary index name here. Reads are allowed on a write-blocked
 * retained generation.
 */
export async function resolveArchivedEvidence(client: any, evidence: any): Promise<any> {
  const archiveIndex = evidence?.archive_index;
  const archiveId = evidence?.archive_id || evidence?.alert_id;
  if (!archiveIndex || !archiveId) {
    throw new Error('Evidence record has no archive location.');
  }
  if (!isManagedPhysicalIndex(archiveIndex, 'wazuh-alert-status-v2-')) {
    throw new Error(`Refusing to read untrusted archive location: ${archiveIndex}`);
  }
  const res: any = await client.get({ index: archiveIndex, id: archiveId });
  return res?.body?._source ?? null;
}

/** Whether a case status means the case is still active (not closed). */
export function isActiveCaseStatus(status: string | null | undefined): boolean {
  return status === 'open' || status === 'in_progress';
}

/**
 * Case-state and hold-aware carry decision for retirement. This replaces the
 * transitional "carry every case-linked alert" rule:
 *
 * - open/in_progress alerts are always carried;
 * - a closed alert is carried only while linked to an active case or protected
 *   by an explicit evidence hold;
 * - a closed alert for a closed, non-held case becomes archive-only;
 * - an unclassifiable status is carried to fail safe.
 */
export function shouldCarryAlert(
  status: string | null | undefined,
  caseStatus?: string | null | undefined,
  held: boolean = false
): boolean {
  if (status == null) return true;
  if (status === 'open' || status === 'in_progress') return true;
  if (status === 'closed') {
    if (held) return true;
    return isActiveCaseStatus(caseStatus);
  }
  return true;
}
