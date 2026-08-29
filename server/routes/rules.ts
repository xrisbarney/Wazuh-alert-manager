import { createHash, randomBytes } from 'crypto';
import { schema } from '@osd/config-schema';
import { IRouter } from '../../../../src/core/server';
import {
  API_ROOT,
  RULES_INDEX,
  META_INDEX,
  CASE_SEVERITIES,
  CORRELATION_ENTITIES,
  ALERT_STATUSES,
  AUTOMATION_MAX_ENABLED_RULES,
} from '../../common';
import { getCurrentUsername } from '../lib/opensearch';
import { requirePluginAdmin } from '../lib/authorization';
import { appendActivity, appendActivityOnce, reportActivityFailure } from '../lib/activity';
import { mergeRulePatch, normalizeAndValidateRule, ruleDefinitionFingerprint } from '../lib/rule_validation';
import { runAutomationPreview } from '../lib/automation_preview';

const modeSchema = schema.maybe(schema.oneOf([schema.literal('any'), schema.literal('all')]));
const matchSchema = schema.object({
  ruleGroups: schema.maybe(schema.arrayOf(schema.string(), { maxSize: 50 })),
  ruleGroupsMode: modeSchema,
  ruleIds: schema.maybe(schema.arrayOf(schema.string(), { maxSize: 50 })),
  ruleIdsMode: modeSchema,
  agentNames: schema.maybe(schema.arrayOf(schema.string(), { maxSize: 50 })),
  agentNamesMode: modeSchema,
  minLevel: schema.maybe(schema.number({ min: 0, max: 16 })),
});
const entitySchema = schema.oneOf(CORRELATION_ENTITIES.map((value) => schema.literal(value)) as any);
const predicateSchema = schema.object({
  id: schema.string({ minLength: 1, maxLength: 256 }),
  order: schema.number({ min: 0 }),
  entity: entitySchema,
  operator: schema.oneOf([schema.literal('exists'), schema.literal('equals')]),
  value: schema.maybe(schema.string({ maxLength: 1024 })),
});
const entityExpressionSchema = schema.object({
  version: schema.literal(1),
  groups: schema.arrayOf(schema.object({
    id: schema.string({ minLength: 1, maxLength: 256 }),
    order: schema.number({ min: 0 }),
    predicates: schema.arrayOf(predicateSchema, { minSize: 1, maxSize: 5 }),
  }), { maxSize: 5 }),
});
const routingSchema = schema.oneOf([
  schema.literal('separate_by_group'),
  schema.literal('consolidate_overlapping'),
  schema.literal('one_per_rule'),
]);
const cooldownSchema = schema.object({ durationMinutes: schema.number({ min: 0, max: 10080 }) });
const rearmSchema = schema.object({
  type: schema.oneOf([schema.literal('immediate'), schema.literal('after_quiet_period')]),
  quietPeriodMinutes: schema.number({ min: 0, max: 10080 }),
});
export const canonicalTriggerSchema = schema.object({
  type: schema.oneOf([schema.literal('per_alert'), schema.literal('burst')]),
  entityExpression: entityExpressionSchema,
  routing: routingSchema,
  cooldown: cooldownSchema,
  rearm: rearmSchema,
  windowMinutes: schema.maybe(schema.number({ min: 1, max: 1440 })),
  threshold: schema.maybe(schema.number({ min: 2, max: 1000 })),
});
const triggerPatchSchema = schema.object({
  type: schema.maybe(schema.oneOf([schema.literal('per_alert'), schema.literal('burst')])),
  entityExpression: schema.maybe(entityExpressionSchema),
  routing: schema.maybe(routingSchema),
  cooldown: schema.maybe(cooldownSchema),
  rearm: schema.maybe(rearmSchema),
  windowMinutes: schema.maybe(schema.number({ min: 1, max: 1440 })),
  threshold: schema.maybe(schema.number({ min: 2, max: 1000 })),
});
const actionsSchema = schema.object({
  createCase: schema.maybe(schema.boolean()),
  caseSeverity: schema.maybe(schema.oneOf(CASE_SEVERITIES.map((value) => schema.literal(value)) as any)),
  setStatus: schema.maybe(schema.nullable(schema.oneOf(ALERT_STATUSES.map((value) => schema.literal(value)) as any))),
  assignTo: schema.maybe(schema.nullable(schema.string({ maxLength: 256 }))),
});
const preconditionsSchema = schema.object({
  statuses: schema.maybe(
    schema.arrayOf(schema.oneOf(ALERT_STATUSES.map((value) => schema.literal(value)) as any), { maxSize: 3 })
  ),
  assignment: schema.maybe(schema.oneOf([schema.literal('any'), schema.literal('unassigned')])),
});
const rateLimitSchema = schema.object({
  maxExecutions: schema.number({ min: 1, max: 100000 }),
  windowMinutes: schema.number({ min: 1, max: 10080 }),
});
const safetySchema = schema.object({
  acknowledgeMatchAll: schema.maybe(schema.boolean()),
  maxActionsPerRun: schema.maybe(schema.number({ min: 1, max: 10000 })),
  maxCasesPerRun: schema.maybe(schema.number({ min: 1, max: 10000 })),
  rateLimit: schema.maybe(schema.nullable(rateLimitSchema)),
});
const policyBody = {
  priority: schema.maybe(schema.number({ min: 0, max: 1000 })),
  sortOrder: schema.maybe(schema.number({ min: 0, max: 1000000 })),
  processingMode: schema.maybe(schema.oneOf([schema.literal('continue'), schema.literal('stop')])),
  preconditions: schema.maybe(preconditionsSchema),
  safety: schema.maybe(safetySchema),
};
const createBody = {
  name: schema.string({ minLength: 1, maxLength: 200 }),
  enabled: schema.maybe(schema.boolean()),
  match: matchSchema,
  trigger: canonicalTriggerSchema,
  actions: actionsSchema,
  ...policyBody,
};
const patchBody = {
  name: schema.maybe(schema.string({ minLength: 1, maxLength: 200 })),
  enabled: schema.maybe(schema.boolean()),
  match: schema.maybe(matchSchema),
  trigger: schema.maybe(triggerPatchSchema),
  actions: schema.maybe(actionsSchema),
  ...policyBody,
};
const concurrencyBody = {
  revision: schema.number({ min: 1 }),
  if_seq_no: schema.number({ min: 0 }),
  if_primary_term: schema.number({ min: 1 }),
};

export const revisionId = (ruleId: string, revision: number) =>
  `rule-revision:${ruleId}:${String(revision).padStart(12, '0')}`;
export const previewApprovalId = (ruleId: string, revision: number) =>
  `automation-preview:${ruleId}:${String(revision).padStart(12, '0')}`;

export const previewToken = (ruleId: string, revision: number, fingerprint: string) =>
  createHash('sha256').update(`${ruleId}:${revision}:${fingerprint}`).digest('hex');

const operationId = (ruleId: string, revision: number) =>
  `rule-operation:${ruleId}:${String(revision).padStart(12, '0')}`;
const auditId = (ruleId: string, revision: number) =>
  `rule-audit:${ruleId}:${String(revision).padStart(12, '0')}`;
const isInternalRuleId = (id: string) =>
  id.startsWith('rule-revision:') || id.startsWith('rule-operation:') || id.startsWith('rule-execution:');

interface RulesCursor {
  v: 1;
  pit: string;
  sort: [number];
  includeDeleted: boolean;
}

export const decodeRulesCursor = (cursor?: string): RulesCursor | undefined => {
  if (!cursor) return undefined;
  try {
    const parsed = JSON.parse(Buffer.from(cursor, 'base64').toString('utf8'));
    if (
      parsed?.v !== 1 ||
      typeof parsed.pit !== 'string' ||
      !parsed.pit ||
      !Array.isArray(parsed.sort) ||
      parsed.sort.length !== 1 ||
      !Number.isFinite(parsed.sort[0]) ||
      typeof parsed.includeDeleted !== 'boolean'
    ) {
      throw new Error();
    }
    return parsed;
  } catch (e) {
    const error: any = new Error('Invalid rules cursor.');
    error.statusCode = 400;
    throw error;
  }
};
const encodeCursor = (cursor: RulesCursor) => Buffer.from(JSON.stringify(cursor), 'utf8').toString('base64');
const EDITABLE_FIELDS = [
  'name',
  'enabled',
  'priority',
  'sortOrder',
  'processingMode',
  'match',
  'trigger',
  'actions',
  'preconditions',
  'safety',
] as const;

export const editableRuleSnapshot = (rule: any) =>
  EDITABLE_FIELDS.reduce((snapshot: any, field) => {
    if (rule[field] !== undefined) snapshot[field] = rule[field];
    return snapshot;
  }, {});

export const entityGroupsChanged = (current: any, next: any): boolean =>
  JSON.stringify(current?.trigger?.entityExpression?.groups || []) !==
  JSON.stringify(next?.trigger?.entityExpression?.groups || []);

export function requireDisabledEntityGroupEdit(current: any, next: any): void {
  if (current.enabled && entityGroupsChanged(current, next)) {
    const error: any = new Error(
      'Disable and save the rule before changing entity groups, then save, preview, and enable the new definition.'
    );
    error.statusCode = 409;
    throw error;
  }
}

export function applyRuleActivationMetadata(current: any, next: any, now: string): any {
  const changed = entityGroupsChanged(current, next);
  return {
    ...next,
    state_epoch: changed || !current?.state_epoch ? randomBytes(16).toString('hex') : current.state_epoch,
    effective_from: !current?.enabled && next.enabled ? now : current?.effective_from ?? null,
  };
}

export async function requireEnabledRuleCapacity(client: any, current: any, next: any): Promise<void> {
  if (current?.enabled || !next?.enabled) return;
  const result: any = await client.count({ index: RULES_INDEX, body: { query: { term: { enabled: true } } } });
  if (Number(result?.body?.count || 0) >= AUTOMATION_MAX_ENABLED_RULES) {
    const error: any = new Error(`At most ${AUTOMATION_MAX_ENABLED_RULES} automation rules may be enabled.`);
    error.statusCode = 409;
    throw error;
  }
}

const publicRuleSource = (source: any) => {
  const { pending_operation: pendingOperation, ...rule } = source || {};
  return { ...rule, revision: Number(rule.revision || 1) };
};
export const ruleResponse = (hit: any) => ({
  id: hit._id,
  ...publicRuleSource(hit._source),
  if_seq_no: hit._seq_no,
  if_primary_term: hit._primary_term,
});
const withConcurrency = ruleResponse;

export const buildRollbackRule = (current: any, definition: any, revision: number, updatedAt: string) => ({
  ...current,
  ...definition,
  enabled: false,
  revision,
  created_by: current.created_by,
  created_at: current.created_at,
  updated_at: updatedAt,
  deleted_at: null,
  deleted_by: null,
});

export const deletedRuleResponse = (hit: any) => ({
  deleted: true as true,
  tombstone: true as true,
  revision: Number(hit._source?.revision || 1),
  if_seq_no: hit._seq_no,
  if_primary_term: hit._primary_term,
});
const isPrimaryRule = (hit: any) => hit._source?.document_type !== 'rule_revision';

const buildPendingOperation = (ruleId: string, rule: any, user: string, changeType: string, audit: any) => {
  const revision = Number(rule.revision || 1);
  return {
    operation_id: operationId(ruleId, revision),
    revision: {
      document_type: 'rule_revision',
      rule_id: ruleId,
      revision,
      changed_at: rule.updated_at || rule.created_at,
      changed_by: user,
      change_type: changeType,
      operation_id: operationId(ruleId, revision),
      snapshot: editableRuleSnapshot(rule),
    },
    audit: {
      targetType: 'rule',
      source: 'rules_api',
      targetId: ruleId,
      user,
      timestamp: rule.updated_at || rule.created_at,
      operationId: auditId(ruleId, revision),
      ruleRevision: revision,
      ...audit,
    },
  };
};

async function createRevisionOnce(client: any, revision: any) {
  try {
    await client.index({
      index: RULES_INDEX,
      id: revisionId(revision.rule_id, revision.revision),
      op_type: 'create',
      refresh: 'wait_for',
      body: revision,
    });
  } catch (error: any) {
    if ((error?.meta?.statusCode || error?.statusCode) !== 409) throw error;
  }
}

export async function repairRuleOperation(client: any, hit: any, observer: any = console): Promise<any> {
  const pending = hit._source?.pending_operation;
  if (!pending) return hit;
  try {
    await createRevisionOnce(client, pending.revision);
  } catch (error: any) {
    observer.increment?.('automation_revision_write_failures');
    observer.error(
      `wazuh-alert-manager rule revision ${pending.operation_id} remains in the durable outbox: ${
        error?.message || String(error)
      }`
    );
    return hit;
  }
  const { operationId: activityOperationId, ruleRevision, ...audit } = pending.audit;
  try {
    await appendActivityOnce(client, activityOperationId, {
      ...audit,
      operationId: activityOperationId,
      ruleRevision,
    });
  } catch (error) {
    reportActivityFailure(observer, pending.operation_id, error);
    return hit;
  }
  try {
    const result: any = await client.update({
      index: RULES_INDEX,
      id: hit._id,
      if_seq_no: hit._seq_no,
      if_primary_term: hit._primary_term,
      refresh: 'wait_for',
      body: { script: { source: 'ctx._source.remove("pending_operation")' } },
    });
    return {
      ...hit,
      _seq_no: result.body._seq_no,
      _primary_term: result.body._primary_term,
      _source: publicRuleSource(hit._source),
    };
  } catch (error: any) {
    // A concurrent writer or transient cleanup failure leaves a harmless,
    // retryable outbox record. Both immutable writes are deterministic.
    return hit;
  }
}

async function ensureLegacyRevision(client: any, ruleId: string, rule: any, user: string) {
  if (rule.pending_operation) return;
  const revision = Number(rule.revision || 1);
  await createRevisionOnce(
    client,
    buildPendingOperation(
      ruleId,
      { ...rule, revision: Number(rule.revision || 1), updated_at: rule.updated_at || rule.created_at },
      rule.created_by || user,
      revision === 1 ? 'create' : 'update',
      { action: 'legacy_rule_revision_synthesized' }
    ).revision
  );
}

// Preview events are observational rather than part of a primary rule commit.
async function auditRule(client: any, input: any) {
  try {
    await appendActivity(client, { targetType: 'rule', source: 'rules_api', ...input });
  } catch (error) {
    // Preview availability does not depend on activity-index availability.
  }
}

async function openRulesPit(client: any): Promise<string> {
  const result: any =
    typeof client.createPit === 'function'
      ? await client.createPit({ index: RULES_INDEX, keep_alive: '2m' })
      : await client.transport.request({
          method: 'POST',
          path: `/${RULES_INDEX}/_search/point_in_time`,
          querystring: { keep_alive: '2m' },
        });
  const id = result?.body?.pit_id || result?.body?.id;
  if (!id) throw new Error('OpenSearch returned no rules PIT id.');
  return id;
}

async function closeRulesPit(client: any, id: string) {
  const body = { pit_id: [id] };
  if (typeof client.deletePit === 'function') await client.deletePit({ body });
  else if (typeof client.transport?.request === 'function') {
    await client.transport.request({ method: 'DELETE', path: '/_search/point_in_time', body });
  }
}

export async function requireCurrentPreview(
  client: any,
  ruleId: string,
  revision: number,
  current: any,
  next: any
): Promise<void> {
  if (current.enabled || !next.enabled) return;
  const fingerprint = ruleDefinitionFingerprint(next);
  let source: any;
  try {
    const result: any = await client.get({ index: META_INDEX, id: previewApprovalId(ruleId, revision) });
    source = result?.body?._source;
  } catch (error: any) {
    const status = error?.meta?.statusCode || error?.statusCode;
    if (status !== 404) throw error;
  }
  if (
    source?.status !== 'success' ||
    source?.rule_id !== ruleId ||
    Number(source?.revision) !== revision ||
    source?.fingerprint !== fingerprint ||
    source?.token !== previewToken(ruleId, revision, fingerprint)
  ) {
    const error: any = new Error('Preview the current saved rule definition successfully before enabling it.');
    error.statusCode = 409;
    throw error;
  }
}

export function defineRuleRoutes(router: IRouter) {
  router.get(
    {
      path: `${API_ROOT}/rules`,
      validate: {
        query: schema.object({
          size: schema.maybe(schema.number({ min: 1, max: 100 })),
          cursor: schema.maybe(schema.string({ maxLength: 4096 })),
          includeDeleted: schema.maybe(schema.boolean()),
        }),
      },
    },
    async (context, request, response) => {
      const client = context.core.opensearch.client.asCurrentUser;
      try {
        const { size = 50, cursor, includeDeleted = false } = request.query as any;
        const decoded = decodeRulesCursor(cursor);
        if (decoded && decoded.includeDeleted !== includeDeleted) {
          const error: any = new Error('Rules cursor does not match includeDeleted.');
          error.statusCode = 400;
          throw error;
        }
        const pit = decoded?.pit || (await openRulesPit(client));
        const result: any = await client.search({
          size: size + 1,
          body: {
            pit: { id: pit, keep_alive: '2m' },
            seq_no_primary_term: true,
            sort: [{ _doc: { order: 'asc' } }],
            ...(decoded ? { search_after: decoded.sort } : {}),
            query: {
              bool: {
                must_not: [
                  { exists: { field: 'document_type' } },
                  ...(includeDeleted ? [] : [{ exists: { field: 'deleted_at' } }]),
                ],
              },
            },
          },
        });
        const hits = (result.body.hits.hits || []).filter(isPrimaryRule);
        const page = hits.slice(0, size);
        const observer: any = (context as any).wazuhAlertManager?.logger || console;
        const repaired = [];
        for (const hit of page) {
          await ensureLegacyRevision(client, hit._id, hit._source, hit._source?.created_by || 'unknown');
          repaired.push(await repairRuleOperation(client, hit, observer));
        }
        const hasMore = hits.length > size;
        if (!hasMore) await closeRulesPit(client, pit).catch(() => undefined);
        return response.ok({
          body: {
            rules: repaired.map(withConcurrency),
            nextCursor:
              hasMore && page.length
                ? encodeCursor({ v: 1, pit, sort: page[page.length - 1].sort as [number], includeDeleted })
                : null,
          },
        });
      } catch (e: any) {
        return response.customError({ statusCode: e.statusCode || e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );

  router.post(
    { path: `${API_ROOT}/rules`, validate: { body: schema.object(createBody) } },
    async (context, request, response) => {
      try {
        await requirePluginAdmin(context, request);
      } catch (e: any) {
        return response.forbidden({ body: { message: e.message } });
      }
      const validation = normalizeAndValidateRule(request.body);
      if (validation.errors.length) return response.badRequest({ body: { message: validation.errors[0], errors: validation.errors } });
      if (validation.rule.enabled) {
        return response.badRequest({ body: { message: 'New rules must be created disabled, then previewed before activation.' } });
      }
      const client = context.core.opensearch.client.asCurrentUser;
      const user = await getCurrentUsername(context, request);
      const now = new Date().toISOString();
      const id = randomBytes(16).toString('hex');
      const doc = {
        ...validation.rule,
        effective_from: null,
        state_epoch: randomBytes(16).toString('hex'),
        revision: 1,
        created_by: user,
        created_at: now,
        updated_at: now,
      };
      try {
        const committed = {
          ...doc,
          pending_operation: buildPendingOperation(id, doc, user, 'create', {
            action: 'rule_created',
            to: 'revision:1',
          }),
        };
        const result: any = await client.index({ index: RULES_INDEX, id, op_type: 'create', body: committed, refresh: 'wait_for' });
        const repaired = await repairRuleOperation(
          client,
          {
            _id: id,
            _source: committed,
            _seq_no: result.body._seq_no,
            _primary_term: result.body._primary_term,
          },
          (context as any).wazuhAlertManager?.logger || console
        );
        return response.ok({ body: withConcurrency(repaired) });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );

  router.post(
    {
      path: `${API_ROOT}/rules/preview`,
      validate: {
        body: schema.object({
          ...createBody,
          id: schema.string({ minLength: 1, maxLength: 256 }),
          revision: schema.number({ min: 1 }),
          lookbackHours: schema.maybe(schema.number({ min: 1, max: 168 })),
        }),
      },
    },
    async (context, request, response) => {
      try {
        await requirePluginAdmin(context, request);
      } catch (e: any) {
        return response.forbidden({ body: { message: e.message } });
      }
      const { id, revision, lookbackHours = 24, ...input } = request.body as any;
      const validation = normalizeAndValidateRule(input);
      if (validation.errors.length) return response.badRequest({ body: { message: validation.errors[0], errors: validation.errors } });
      const client = context.core.opensearch.client.asCurrentUser;
      const user = await getCurrentUsername(context, request);
      try {
        if (isInternalRuleId(id)) return response.notFound({ body: { message: 'Rule not found.' } });
        const currentResult: any = await client.get({ index: RULES_INDEX, id });
        const current = currentResult?.body?._source;
        if (current?.document_type || current?.deleted_at) return response.notFound({ body: { message: 'Rule not found.' } });
        if (current?.pending_operation) {
          return response.customError({ statusCode: 503, body: { message: 'Rule persistence repair is pending; retry the request.' } });
        }
        if (Number(current?.revision || 1) !== revision) {
          return response.customError({ statusCode: 409, body: { message: 'Rule revision is stale.' } });
        }
        const fingerprint = ruleDefinitionFingerprint(validation.rule);
        if (fingerprint !== ruleDefinitionFingerprint(current)) {
          return response.customError({ statusCode: 409, body: { message: 'Save the current rule definition before previewing it.' } });
        }
        const result = await runAutomationPreview(
          client,
          { ...current, ...validation.rule, id, revision },
          { lookbackHours }
        );
        const labeledResult = { ...result, mode: 'historical_read_only' };
        const token = previewToken(id, revision, fingerprint);
        await client.index({
          index: META_INDEX,
          id: previewApprovalId(id, revision),
          refresh: 'wait_for',
          body: {
            status: 'success',
            rule_id: id,
            revision,
            fingerprint,
            token,
            result: labeledResult,
            previewed_at: new Date().toISOString(),
            previewed_by: user,
          },
        });
        await auditRule(client, { targetId: id, user, action: 'rule_previewed', to: `revision:${revision}` });
        return response.ok({ body: { ...labeledResult, token, fingerprint } });
      } catch (e: any) {
        await auditRule(client, { targetId: id, user, action: 'rule_preview_failed', to: e.message });
        return response.customError({ statusCode: e.statusCode || e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );

  router.get(
    {
      path: `${API_ROOT}/rules/{id}/revisions`,
      validate: {
        params: schema.object({ id: schema.string() }),
        query: schema.object({ page: schema.maybe(schema.number({ min: 1 })), size: schema.maybe(schema.number({ min: 1, max: 100 })) }),
      },
    },
    async (context, request, response) => {
      const client = context.core.opensearch.client.asCurrentUser;
      const { id } = request.params as any;
      const { page = 1, size = 20 } = request.query as any;
      if (isInternalRuleId(id)) return response.notFound({ body: { message: 'Rule not found.' } });
      try {
        const currentResult: any = await client.get({ index: RULES_INDEX, id });
        if (currentResult.body._source?.document_type) return response.notFound({ body: { message: 'Rule not found.' } });
        const current = await repairRuleOperation(
          client,
          {
            _id: id,
            _source: currentResult.body._source,
            _seq_no: currentResult.body._seq_no,
            _primary_term: currentResult.body._primary_term,
          },
          (context as any).wazuhAlertManager?.logger || console
        );
        const latest = Number(current._source?.revision || 1);
        await ensureLegacyRevision(client, id, current._source, current._source?.created_by || 'unknown');
        const start = latest - (page - 1) * size;
        const revisions = Array.from({ length: Math.min(size, Math.max(0, start)) }, (_, index) => start - index);
        const result: any = revisions.length
          ? await client.mget({ index: RULES_INDEX, body: { ids: revisions.map((revision) => revisionId(id, revision)) } })
          : { body: { docs: [] } };
        return response.ok({
          body: {
            revisions: result.body.docs.filter((doc: any) => doc.found).map((doc: any) => doc._source),
            page,
            size,
            total: latest,
            nextPage: start - size > 0 ? page + 1 : null,
          },
        });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );

  router.post(
    {
      path: `${API_ROOT}/rules/{id}/rollback/{targetRevision}`,
      validate: {
        params: schema.object({ id: schema.string(), targetRevision: schema.string() }),
        body: schema.object(concurrencyBody),
      },
    },
    async (context, request, response) => {
      try {
        await requirePluginAdmin(context, request);
      } catch (e: any) {
        return response.forbidden({ body: { message: e.message } });
      }
      const client = context.core.opensearch.client.asCurrentUser;
      const user = await getCurrentUsername(context, request);
      const { id, targetRevision: targetRevisionValue } = request.params as any;
      if (isInternalRuleId(id)) return response.notFound({ body: { message: 'Rule not found.' } });
      const targetRevision = Number(targetRevisionValue);
      if (!Number.isInteger(targetRevision) || targetRevision < 1) {
        return response.badRequest({ body: { message: 'Target revision must be a positive integer.' } });
      }
      const control = request.body as any;
      try {
        const currentResult: any = await client.get({ index: RULES_INDEX, id });
        if (currentResult.body._source?.document_type) return response.notFound({ body: { message: 'Rule not found.' } });
        const original = currentResult.body._source;
        await ensureLegacyRevision(client, id, original, original.created_by || user);
        const repaired = await repairRuleOperation(
          client,
          { _id: id, _source: original, _seq_no: currentResult.body._seq_no, _primary_term: currentResult.body._primary_term },
          (context as any).wazuhAlertManager?.logger || console
        );
        if (currentResult.body._seq_no !== control.if_seq_no || currentResult.body._primary_term !== control.if_primary_term) {
          return response.customError({ statusCode: 409, body: { message: 'Rule concurrency token is stale.' } });
        }
        if (repaired._source?.pending_operation) {
          return response.customError({ statusCode: 503, body: { message: 'Rule persistence repair is pending; retry the request.' } });
        }
        const current = repaired._source;
        if (Number(current.revision || 1) !== control.revision) {
          return response.customError({ statusCode: 409, body: { message: 'Rule revision is stale.' } });
        }
        const revisionResult: any = await client.get({ index: RULES_INDEX, id: revisionId(id, targetRevision) });
        const validation = normalizeAndValidateRule(revisionResult.body._source.snapshot);
        if (validation.errors.length) return response.badRequest({ body: { message: validation.errors[0], errors: validation.errors } });
        const now = new Date().toISOString();
        const doc: any = applyRuleActivationMetadata(
          current,
          buildRollbackRule(current, editableRuleSnapshot(validation.rule), control.revision + 1, now),
          now
        );
        doc.pending_operation = buildPendingOperation(id, doc, user, 'rollback', {
          action: 'rule_rolled_back',
          from: `revision:${control.revision}`,
          to: `revision:${doc.revision}`,
        });
        const result: any = await client.index({
          index: RULES_INDEX,
          id,
          if_seq_no: repaired._seq_no,
          if_primary_term: repaired._primary_term,
          body: doc,
          refresh: 'wait_for',
        });
        const finalized = await repairRuleOperation(
          client,
          { _id: id, _source: doc, _seq_no: result.body._seq_no, _primary_term: result.body._primary_term },
          (context as any).wazuhAlertManager?.logger || console
        );
        return response.ok({ body: withConcurrency(finalized) });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );

  router.get(
    { path: `${API_ROOT}/rules/{id}`, validate: { params: schema.object({ id: schema.string() }) } },
    async (context, request, response) => {
      const client = context.core.opensearch.client.asCurrentUser;
      const id = (request.params as any).id;
      if (isInternalRuleId(id)) return response.notFound({ body: { message: 'Rule not found.' } });
      try {
        const result: any = await client.get({ index: RULES_INDEX, id });
        if (result.body._source?.document_type) return response.notFound({ body: { message: 'Rule not found.' } });
        await ensureLegacyRevision(client, id, result.body._source, result.body._source?.created_by || 'unknown');
        const repaired = await repairRuleOperation(
          client,
          { _id: id, _source: result.body._source, _seq_no: result.body._seq_no, _primary_term: result.body._primary_term },
          (context as any).wazuhAlertManager?.logger || console
        );
        return response.ok({ body: withConcurrency(repaired) });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );

  router.put(
    {
      path: `${API_ROOT}/rules/{id}`,
      validate: { params: schema.object({ id: schema.string() }), body: schema.object({ ...patchBody, ...concurrencyBody }) },
    },
    async (context, request, response) => {
      try {
        await requirePluginAdmin(context, request);
      } catch (e: any) {
        return response.forbidden({ body: { message: e.message } });
      }
      const client = context.core.opensearch.client.asCurrentUser;
      const user = await getCurrentUsername(context, request);
      const { id } = request.params as any;
      if (isInternalRuleId(id)) return response.notFound({ body: { message: 'Rule not found.' } });
      const { revision, if_seq_no, if_primary_term, ...patch } = request.body as any;
      try {
        const existing: any = await client.get({ index: RULES_INDEX, id });
        if (existing.body._source?.document_type) return response.notFound({ body: { message: 'Rule not found.' } });
        await ensureLegacyRevision(client, id, existing.body._source, existing.body._source.created_by || user);
        const repaired = await repairRuleOperation(
          client,
          { _id: id, _source: existing.body._source, _seq_no: existing.body._seq_no, _primary_term: existing.body._primary_term },
          (context as any).wazuhAlertManager?.logger || console
        );
        if (existing.body._seq_no !== if_seq_no || existing.body._primary_term !== if_primary_term) {
          return response.customError({ statusCode: 409, body: { message: 'Rule concurrency token is stale.' } });
        }
        if (repaired._source?.pending_operation) {
          return response.customError({ statusCode: 503, body: { message: 'Rule persistence repair is pending; retry the request.' } });
        }
        const current = repaired._source;
        if (Number(current.revision || 1) !== revision) {
          return response.customError({ statusCode: 409, body: { message: 'Rule revision is stale.' } });
        }
        if (current.deleted_at) {
          return response.customError({ statusCode: 409, body: { message: 'Deleted rules must be restored through rollback.' } });
        }
        const validation = normalizeAndValidateRule(mergeRulePatch(current, patch));
        if (validation.errors.length) return response.badRequest({ body: { message: validation.errors[0], errors: validation.errors } });
        requireDisabledEntityGroupEdit(current, validation.rule);
        const now = new Date().toISOString();
        let doc: any = {
          ...current,
          ...validation.rule,
          revision: revision + 1,
          created_by: current.created_by,
          created_at: current.created_at,
          updated_at: now,
        };
        doc = applyRuleActivationMetadata(current, doc, now);
        await requireCurrentPreview(client, id, revision, current, doc);
        await requireEnabledRuleCapacity(client, current, doc);
        const action = current.enabled !== doc.enabled ? (doc.enabled ? 'rule_enabled' : 'rule_disabled') : 'rule_updated';
        doc.pending_operation = buildPendingOperation(id, doc, user, 'update', {
          action,
          from: `revision:${revision}`,
          to: `revision:${doc.revision}`,
        });
        const result: any = await client.index({
          index: RULES_INDEX,
          id,
          if_seq_no: repaired._seq_no,
          if_primary_term: repaired._primary_term,
          body: doc,
          refresh: 'wait_for',
        });
        const finalized = await repairRuleOperation(
          client,
          { _id: id, _source: doc, _seq_no: result.body._seq_no, _primary_term: result.body._primary_term },
          (context as any).wazuhAlertManager?.logger || console
        );
        return response.ok({ body: withConcurrency(finalized) });
      } catch (e: any) {
        return response.customError({ statusCode: e.statusCode || e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );

  router.delete(
    {
      path: `${API_ROOT}/rules/{id}`,
      validate: { params: schema.object({ id: schema.string() }), query: schema.object(concurrencyBody) },
    },
    async (context, request, response) => {
      try {
        await requirePluginAdmin(context, request);
      } catch (e: any) {
        return response.forbidden({ body: { message: e.message } });
      }
      const client = context.core.opensearch.client.asCurrentUser;
      const user = await getCurrentUsername(context, request);
      const { id } = request.params as any;
      if (isInternalRuleId(id)) return response.notFound({ body: { message: 'Rule not found.' } });
      const { revision, if_seq_no, if_primary_term } = request.query as any;
      try {
        const existing: any = await client.get({ index: RULES_INDEX, id });
        if (existing.body._source?.document_type) return response.notFound({ body: { message: 'Rule not found.' } });
        await ensureLegacyRevision(client, id, existing.body._source, existing.body._source.created_by || user);
        const repaired = await repairRuleOperation(
          client,
          { _id: id, _source: existing.body._source, _seq_no: existing.body._seq_no, _primary_term: existing.body._primary_term },
          (context as any).wazuhAlertManager?.logger || console
        );
        const current = repaired._source;
        if (current.deleted_at) {
          return response.ok({ body: deletedRuleResponse(repaired) });
        }
        if (existing.body._seq_no !== if_seq_no || existing.body._primary_term !== if_primary_term) {
          return response.customError({ statusCode: 409, body: { message: 'Rule concurrency token is stale.' } });
        }
        if (repaired._source?.pending_operation) {
          return response.customError({ statusCode: 503, body: { message: 'Rule persistence repair is pending; retry the request.' } });
        }
        if (Number(current.revision || 1) !== revision) {
          return response.customError({ statusCode: 409, body: { message: 'Rule revision is stale.' } });
        }
        const now = new Date().toISOString();
        const doc: any = { ...current, enabled: false, revision: revision + 1, updated_at: now, deleted_at: now, deleted_by: user };
        doc.pending_operation = buildPendingOperation(id, doc, user, 'delete', {
          action: 'rule_deleted',
          from: `revision:${revision}`,
          to: `revision:${doc.revision}`,
        });
        const result: any = await client.index({
          index: RULES_INDEX,
          id,
          if_seq_no: repaired._seq_no,
          if_primary_term: repaired._primary_term,
          body: doc,
          refresh: 'wait_for',
        });
        const finalized = await repairRuleOperation(
          client,
          { _id: id, _source: doc, _seq_no: result.body._seq_no, _primary_term: result.body._primary_term },
          (context as any).wazuhAlertManager?.logger || console
        );
        return response.ok({
          body: {
            deleted: true,
            tombstone: true,
            revision: doc.revision,
            if_seq_no: finalized._seq_no,
            if_primary_term: finalized._primary_term,
          },
        });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );
}
