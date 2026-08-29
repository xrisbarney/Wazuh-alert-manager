import { EVIDENCE_READ_ALIAS } from '../../common';
import { buildEvidenceDocument, evidenceId, evidenceWriteTarget, isEvidenceHeld } from './evidence';
import { buildHistoryEntry } from './history';
import { resolveAlerts } from './index_resolution';
import { assertManagedWriteTarget } from './index_namespace';
import { resolveCase } from './case_index_resolution';

const DEFAULT_COMPATIBILITY_LIMIT = 1000;

export type CaseEvidenceStageName =
  | 'resolve'
  | 'assign_alerts'
  | 'rollback_assignments'
  | 'write_evidence'
  | 'remove_evidence'
  | 'unlink_alerts'
  | 'sync_case_metadata';

export interface CaseEvidenceStageError {
  stage: CaseEvidenceStageName;
  alertId?: string;
  caseId?: string;
  statusCode?: number;
  message: string;
}

export interface CaseEvidenceStageResult {
  stage: CaseEvidenceStageName;
  attempted: number;
  succeeded: number;
  failed: number;
}

export interface CaseEvidenceMutationResult {
  ok: boolean;
  requested: number;
  resolved: number;
  linked: number;
  newlyLinked: number;
  unlinked: number;
  moved: number;
  staleUnlinks: number;
  unknownAlertIds: string[];
  linkedAlertIds: string[];
  unlinkedAlertIds: string[];
  retryAlertIds: string[];
  retryCaseIds: string[];
  conflictedAlertIds: string[];
  stages: CaseEvidenceStageResult[];
  errors: CaseEvidenceStageError[];
}

export interface ReconcileCaseEvidenceInput {
  caseId: string;
  linkAlertIds?: string[];
  unlinkAlertIds?: string[];
  actor: string;
  action?: string;
  timestamp?: string;
  compatibilityLimit?: number;
  /** Automation uses false so existing analyst/closed-case evidence is never reassigned. */
  allowMove?: boolean;
  fence?: () => Promise<void>;
}

interface ExistingRelationship {
  id: string;
  index: string;
  source: any;
  seqNo?: number;
  primaryTerm?: number;
}

function uniqueIds(ids: string[] = []): string[] {
  return Array.from(new Set(ids.map(String).filter(Boolean))).sort();
}

function errorMessage(value: any): string {
  return value?.reason || value?.caused_by?.reason || value?.message || String(value || 'Bulk item failed');
}

async function runBulkStage(
  client: any,
  stage: CaseEvidenceStageName,
  operations: Array<{ id: string; alertId?: string; caseId?: string; action: any; payload?: any }>,
  errors: CaseEvidenceStageError[]
): Promise<Set<string>> {
  if (!operations.length) return new Set();
  let response: any;
  try {
    response = await client.bulk({
      refresh: 'wait_for',
      body: operations.flatMap((operation) =>
        operation.payload === undefined ? [operation.action] : [operation.action, operation.payload]
      ),
    });
  } catch (error: any) {
    for (const operation of operations) {
      errors.push({ stage, alertId: operation.alertId || operation.id, caseId: operation.caseId, message: errorMessage(error) });
    }
    return new Set();
  }

  const items = response?.body?.items;
  if (!Array.isArray(items) || items.length !== operations.length) {
    for (const operation of operations) {
      errors.push({
        stage,
        alertId: operation.alertId || operation.id,
        caseId: operation.caseId,
        message: `Bulk response contained ${Array.isArray(items) ? items.length : 0} item(s) for ${operations.length} operation(s)`,
      });
    }
    return new Set();
  }

  const succeeded = new Set<string>();
  items.forEach((item: any, index: number) => {
    const operation = operations[index];
    const detail = item?.index || item?.update || item?.delete || item?.create;
    const status = Number(detail?.status || 0);
    const deleteMissing = stage === 'remove_evidence' && status === 404;
    const idempotentCreate = stage === 'write_evidence' && status === 409 && !!item?.create;
    if ((!detail?.error && status >= 200 && status < 300) || deleteMissing || idempotentCreate) {
      succeeded.add(operation.id);
      return;
    }
    errors.push({
      stage,
      alertId: operation.alertId || operation.id,
      caseId: operation.caseId,
      statusCode: status || undefined,
      message: errorMessage(detail?.error || `Bulk item returned status ${status || 'unknown'}`),
    });
  });
  return succeeded;
}

async function findRelationships(client: any, alertIds: string[]): Promise<Map<string, ExistingRelationship[]>> {
  const found = new Map<string, ExistingRelationship[]>();
  for (let offset = 0; offset < alertIds.length; offset += 500) {
    const chunk = alertIds.slice(offset, offset + 500);
    const response: any = await client.search({
      index: EVIDENCE_READ_ALIAS,
      body: { size: chunk.length * 20, track_total_hits: true, query: { terms: { alert_id: chunk } } },
    });
    const hits = response?.body?.hits?.hits || [];
    const total = response?.body?.hits?.total?.value ?? hits.length;
    if (total > hits.length) {
      throw new Error(`Evidence lookup returned ${hits.length} of ${total} relationship(s)`);
    }
    for (const hit of hits) {
      const alertId = hit?._source?.alert_id;
      if (!alertId) continue;
      const relationships = found.get(alertId) || [];
      relationships.push({
        id: hit._id,
        index: assertManagedWriteTarget(hit._index || evidenceWriteTarget()),
        source: hit._source,
        seqNo: hit._seq_no,
        primaryTerm: hit._primary_term,
      });
      found.set(alertId, relationships);
    }
  }
  return found;
}

async function caseIsActive(client: any, caseId: string, unknownIsActive = true): Promise<boolean> {
  try {
    const response = await resolveCase(client, caseId);
    return response.source?.status === 'open' || response.source?.status === 'in_progress';
  } catch (error: any) {
    if ((error?.meta?.statusCode || error?.statusCode) === 404) return false;
    // Unknown status must fail closed so an unavailable case store cannot steal ownership.
    return unknownIsActive;
  }
}

async function rebuildCompatibilityMetadata(
  client: any,
  caseId: string,
  alertIds: string[],
  now: string,
  actor: string,
  fence?: () => Promise<void>
): Promise<void> {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const current = await resolveCase(client, caseId);
    try {
      await fence?.();
      await client.update({
        index: current.index,
        id: caseId,
        refresh: 'wait_for',
        if_seq_no: current.seqNo,
        if_primary_term: current.primaryTerm,
        body: { doc: { alert_ids: alertIds, updated_at: now, updated_by: actor } },
      });
      return;
    } catch (error: any) {
      if ((error?.meta?.statusCode || error?.statusCode) !== 409 || attempt === 2) throw error;
    }
  }
}

function stageResult(
  stage: CaseEvidenceStageName,
  attempted: number,
  succeeded: number
): CaseEvidenceStageResult {
  return { stage, attempted, succeeded, failed: attempted - succeeded };
}

/**
 * Reconcile case-alert ownership. Evidence relationships are authoritative;
 * case.alert_ids is rebuilt after mutation as a bounded compatibility view.
 * The result is intentionally non-throwing once validation begins so callers
 * can report and retry only failed alert IDs. Fence failures remain abortive.
 */
export async function reconcileCaseEvidence(
  client: any,
  input: ReconcileCaseEvidenceInput
): Promise<CaseEvidenceMutationResult> {
  const fenceErrors = new Set<any>();
  const checkFence = async () => {
    try {
      await input.fence?.();
    } catch (error) {
      fenceErrors.add(error);
      throw error;
    }
  };
  const links = uniqueIds(input.linkAlertIds);
  const linkSet = new Set(links);
  const unlinks = uniqueIds(input.unlinkAlertIds).filter((id) => !linkSet.has(id));
  const requestedIds = uniqueIds([...links, ...unlinks]);
  const errors: CaseEvidenceStageError[] = [];
  const stages: CaseEvidenceStageResult[] = [];
  const result: CaseEvidenceMutationResult = {
    ok: false,
    requested: requestedIds.length,
    resolved: 0,
    linked: 0,
    newlyLinked: 0,
    unlinked: 0,
    moved: 0,
    staleUnlinks: 0,
    unknownAlertIds: [],
    linkedAlertIds: [],
    unlinkedAlertIds: [],
    retryAlertIds: [],
    retryCaseIds: [],
    conflictedAlertIds: [],
    stages,
    errors,
  };

  let locations: Map<string, any>;
  let relationships: Map<string, ExistingRelationship[]>;
  try {
    locations = await resolveAlerts(client, requestedIds, true);
    relationships = await findRelationships(client, requestedIds);
  } catch (error: any) {
    errors.push({ stage: 'resolve', message: errorMessage(error) });
    stages.push(stageResult('resolve', requestedIds.length, 0));
    result.retryAlertIds = requestedIds;
    return result;
  }

  result.resolved = locations.size;
  result.unknownAlertIds = requestedIds.filter((id) => !locations.has(id));
  for (const id of result.unknownAlertIds) {
    errors.push({ stage: 'resolve', alertId: id, message: 'Alert was not found in managed storage' });
  }
  stages.push(stageResult('resolve', requestedIds.length, requestedIds.length - result.unknownAlertIds.length));

  const now = input.timestamp || new Date().toISOString();
  const affectedCases = new Set<string>([input.caseId]);
  const targetIsActive = await caseIsActive(client, input.caseId, false);
  const terminalLinkIds = new Set(targetIsActive ? [] : links.filter((id) => locations.has(id)));
  const terminalUnlinkIds = new Set(targetIsActive ? [] : unlinks.filter((id) => locations.has(id)));
  for (const id of [...terminalLinkIds, ...terminalUnlinkIds]) {
    errors.push({
      stage: 'resolve',
      alertId: id,
      caseId: input.caseId,
      message: 'Terminal case evidence cannot be linked, moved, or unlinked.',
    });
  }
  const ownerIds = uniqueIds(links.flatMap((id) => [
    locations.get(id)?.source?.case_id || '',
    ...(relationships.get(id) || []).map((relationship) => relationship.source?.case_id || ''),
  ]).filter((id) => id !== input.caseId));
  const activeOwners = new Set<string>();
  for (const ownerId of ownerIds) {
    if (await caseIsActive(client, ownerId)) activeOwners.add(ownerId);
  }
  const activeEvidenceOwners = (id: string) => new Set(
    (relationships.get(id) || [])
      .map((relationship) => relationship.source?.case_id)
      .filter((caseId) => caseId && (caseId === input.caseId ? targetIsActive : activeOwners.has(caseId)))
  );
  const heldMoveIds = new Set(
    links.filter((id) => {
      return (relationships.get(id) || []).some(
        (relationship) => activeOwners.has(relationship.source?.case_id) && isEvidenceHeld(relationship.source)
      );
    })
  );
  const ownedMoveIds = new Set(
    input.allowMove === false
      ? links.filter((id) => {
          const alertOwner = locations.get(id)?.source?.case_id;
          const evidenceOwners = activeEvidenceOwners(id);
          return evidenceOwners.size
            ? Array.from(evidenceOwners).some((caseId) => caseId !== input.caseId)
            : !!alertOwner && alertOwner !== input.caseId && activeOwners.has(alertOwner);
        })
      : []
  );
  result.conflictedAlertIds = Array.from(new Set([...ownedMoveIds, ...(input.allowMove === false ? heldMoveIds : [])])).sort();
  const heldUnlinkIds = new Set(
    unlinks.filter((id) =>
      (relationships.get(id) || []).some(
        (relationship) => relationship.source?.case_id === input.caseId && isEvidenceHeld(relationship.source)
      )
    )
  );
  for (const id of heldMoveIds) {
    if (input.allowMove !== false) {
      errors.push({ stage: 'resolve', alertId: id, caseId: input.caseId, message: 'Held evidence cannot be moved.' });
    }
  }
  for (const id of heldUnlinkIds) {
    errors.push({ stage: 'resolve', alertId: id, caseId: input.caseId, message: 'Held evidence cannot be unlinked.' });
  }
  const validLinks = links.filter(
    (id) => locations.has(id) && !terminalLinkIds.has(id) && !heldMoveIds.has(id) && !ownedMoveIds.has(id)
  );
  const assignmentOperations = validLinks.map((id) => {
    const location = locations.get(id);
    const priorCaseId = location.source?.case_id || null;
    if (priorCaseId && priorCaseId !== input.caseId) affectedCases.add(priorCaseId);
    for (const relationship of relationships.get(id) || []) {
      if (relationship.source?.case_id && relationship.source.case_id !== input.caseId) {
        affectedCases.add(relationship.source.case_id);
      }
    }
    const entry = buildHistoryEntry({
      user: input.actor,
      action: input.action || 'case_link',
      from: priorCaseId,
      to: input.caseId,
    });
    entry.timestamp = now;
    return {
      id,
      caseId: input.caseId,
      action: { update: { _index: location.index, _id: id } },
      payload: {
        script: {
          lang: 'painless',
          source:
            'if (ctx._source.case_id != params.expected_case_id) { throw new IllegalStateException("Alert case ownership changed concurrently"); } ' +
            'if (params.allow_move == false && ctx._source.case_id != null && ctx._source.case_id != params.case_id) { throw new IllegalStateException("Alert evidence is already owned by another active case"); } ' +
            'if (ctx._source.case_id != params.case_id) { ' +
            'if (ctx._source.history == null) { ctx._source.history = []; } ctx._source.history.add(params.entry); ' +
            'ctx._source.case_id = params.case_id; ctx._source.updated_at = params.now; ctx._source.updated_by = params.actor; }',
          params: {
            case_id: input.caseId,
            expected_case_id: priorCaseId,
            entry,
            now,
            actor: input.actor,
            allow_move:
              input.allowMove !== false || activeEvidenceOwners(id).has(input.caseId) ||
              !priorCaseId || !activeOwners.has(priorCaseId),
          },
        },
      },
    };
  });
  if (assignmentOperations.length) await checkFence();
  const assigned = await runBulkStage(client, 'assign_alerts', assignmentOperations, errors);
  stages.push(stageResult('assign_alerts', assignmentOperations.length, assigned.size));

  const evidenceOperations = validLinks.filter((id) => assigned.has(id)).map((id) => {
    const location = locations.get(id);
    const existingRelationship = (relationships.get(id) || []).find(
      (relationship) => relationship.source?.case_id === input.caseId
    );
    const existing = existingRelationship?.source;
    const document = buildEvidenceDocument({
      caseId: input.caseId,
      alertId: id,
      alertSource: location.source,
      sourceIndex: location.source?.source_index ?? existing?.source_index ?? null,
      sourceId: location.source?.source_id ?? existing?.source_id ?? null,
      archiveIndex: existing?.archive_index ?? null,
      archiveId: existing?.archive_id ?? id,
      holdReason: existing?.hold_reason ?? null,
      holdBy: existing?.hold_by ?? null,
      holdSince: existing?.hold_since ?? null,
      linkedAt: existing?.linked_at || now,
      relationshipState: isEvidenceHeld(existing) ? 'held' : 'linked',
    });
    return {
      id,
      caseId: input.caseId,
      action: existingRelationship
        ? {
            update: {
              _index: existingRelationship.index,
              _id: existingRelationship.id,
              ...(existingRelationship.seqNo === undefined ? {} : {
                if_seq_no: existingRelationship.seqNo,
                if_primary_term: existingRelationship.primaryTerm,
              }),
            },
          }
        : { create: { _index: evidenceWriteTarget(), _id: evidenceId(input.caseId, id) } },
      payload: existingRelationship
        ? {
            script: {
              lang: 'painless',
              source:
                'if (ctx._source.hold_reason != null || ctx._source.hold_since != null || ctx._source.relationship_state == "held" || ctx._source.relationship_state == "archived") { ctx.op = "none"; } ' +
                'else { if (ctx._source.source_index == null) { ctx._source.source_index = params.doc.source_index; } if (ctx._source.source_id == null) { ctx._source.source_id = params.doc.source_id; } }',
              params: { doc: document },
            },
          }
        : document,
    };
  });
  if (evidenceOperations.length) await checkFence();
  const evidenced = await runBulkStage(client, 'write_evidence', evidenceOperations, errors);
  stages.push(stageResult('write_evidence', evidenceOperations.length, evidenced.size));
  const failedEvidence = validLinks.filter((id) => assigned.has(id) && !evidenced.has(id));
  if (failedEvidence.length) await checkFence();
  const rolledBack = await runBulkStage(
    client,
    'rollback_assignments',
    failedEvidence.map((id) => {
      const location = locations.get(id);
      return {
        id,
        alertId: id,
        caseId: input.caseId,
        action: { update: { _index: location.index, _id: id } },
        payload: {
          script: {
            lang: 'painless',
            source:
              'if (ctx._source.case_id == params.case_id) { ctx._source.case_id = params.prior_case_id; ctx._source.updated_at = params.now; ctx._source.updated_by = params.actor; } else { throw new IllegalStateException("Alert case ownership changed concurrently"); }',
            params: {
              case_id: input.caseId,
              prior_case_id: location.source?.case_id || null,
              now,
              actor: input.actor,
            },
          },
        },
      };
    }),
    errors
  );
  stages.push(stageResult('rollback_assignments', failedEvidence.length, rolledBack.size));
  result.linkedAlertIds = validLinks.filter((id) => evidenced.has(id));
  result.linked = result.linkedAlertIds.length;
  result.newlyLinked = result.linkedAlertIds.filter((id) => {
    const targetRelationship = (relationships.get(id) || []).some(
      (relationship) => relationship.source?.case_id === input.caseId
    );
    return !targetRelationship || locations.get(id)?.source?.case_id !== input.caseId;
  }).length;

  const explicitUnlinks = unlinks
    .filter((id) => locations.has(id) && !terminalUnlinkIds.has(id) && !heldUnlinkIds.has(id))
    .map((id) => {
      const relationship = (relationships.get(id) || []).find(
        (item) => item.source?.case_id === input.caseId
      );
      return relationship
        ? { id, caseId: input.caseId, relationshipId: relationship.id, index: relationship.index }
        : null;
    })
    .filter(Boolean) as Array<{ id: string; caseId: string; relationshipId: string; index: string }>;
  const unlinkOperations = explicitUnlinks
    .map((id) => {
      const location = locations.get(id.id);
      if (location.source?.case_id !== input.caseId) result.staleUnlinks += 1;
      return {
        id: id.id,
        caseId: input.caseId,
        action: { update: { _index: location.index, _id: id.id } },
        payload: {
          script: {
            lang: 'painless',
            source:
              'if (ctx._source.case_id == params.case_id) { ctx._source.case_id = null; ' +
              'ctx._source.updated_at = params.now; ctx._source.updated_by = params.actor; ' +
              'if (ctx._source.history == null) { ctx._source.history = []; } ctx._source.history.add(params.entry); }',
            params: {
              case_id: input.caseId,
              now,
              actor: input.actor,
              entry: { timestamp: now, user: input.actor, action: 'case_unlink', from: input.caseId, to: null },
            },
          },
        },
      };
    });
  if (unlinkOperations.length) await checkFence();
  const unlinked = await runBulkStage(client, 'unlink_alerts', unlinkOperations, errors);
  stages.push(stageResult('unlink_alerts', unlinkOperations.length, unlinked.size));

  // Evidence remains authoritative until the operational assignment has been
  // cleared. If deletion fails, a retry can discover the intact relationship.
  const removals = explicitUnlinks.filter((item) => unlinked.has(item.id));
  if (removals.length) await checkFence();
  const removedEvidence = await runBulkStage(
    client,
    'remove_evidence',
    removals.map((item) => ({
      id: item.id,
      alertId: item.id,
      caseId: item.caseId,
      action: (() => {
        const relationship = (relationships.get(item.id) || []).find((entry) => entry.id === item.relationshipId);
        return {
          delete: {
            _index: item.index,
            _id: item.relationshipId,
            ...(relationship?.seqNo === undefined ? {} : {
              if_seq_no: relationship.seqNo,
              if_primary_term: relationship.primaryTerm,
            }),
          },
        };
      })(),
    })),
    errors
  );
  stages.push(stageResult('remove_evidence', removals.length, removedEvidence.size));
  result.unlinkedAlertIds = unlinks.filter((id) => unlinked.has(id) && removedEvidence.has(id));
  result.unlinked = result.unlinkedAlertIds.length;
  result.moved = result.linkedAlertIds.filter((id) => {
    const oldAlertCase = locations.get(id)?.source?.case_id;
    const oldEvidenceCase = (relationships.get(id) || []).some((relationship) => relationship.source?.case_id !== input.caseId);
    return (oldAlertCase && oldAlertCase !== input.caseId) || oldEvidenceCase;
  }).length;

  const compatibilityLimit = Math.max(0, Math.min(input.compatibilityLimit ?? DEFAULT_COMPATIBILITY_LIMIT, 1000));
  let metadataSucceeded = 0;
  for (const caseId of Array.from(affectedCases).sort()) {
    try {
      const evidence: any = await client.search({
        index: EVIDENCE_READ_ALIAS,
        body: {
          size: compatibilityLimit,
          _source: ['alert_id'],
          sort: [{ alert_id: { order: 'asc' } }],
          query: { term: { case_id: caseId } },
        },
      });
      const alertIds = (evidence?.body?.hits?.hits || []).map((hit: any) => hit._source?.alert_id).filter(Boolean);
      await rebuildCompatibilityMetadata(client, caseId, alertIds, now, input.actor, checkFence);
      metadataSucceeded += 1;
    } catch (error: any) {
      if (fenceErrors.has(error)) throw error;
      errors.push({ stage: 'sync_case_metadata', caseId, message: errorMessage(error), statusCode: error?.meta?.statusCode });
    }
  }
  stages.push(stageResult('sync_case_metadata', affectedCases.size, metadataSucceeded));

  result.retryAlertIds = uniqueIds(errors.map((error) => error.alertId || ''));
  result.retryCaseIds = uniqueIds(errors.map((error) => error.caseId || ''));
  result.ok = errors.length === 0;
  return result;
}
