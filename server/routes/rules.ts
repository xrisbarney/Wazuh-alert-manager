import { schema } from '@osd/config-schema';
import { IRouter } from '../../../../src/core/server';
import {
  API_ROOT,
  RULES_INDEX,
  ALERT_STATUS_INDEX,
  CASE_SEVERITIES,
  CORRELATION_ENTITIES,
  ALERT_STATUSES,
} from '../../common';
import { getCurrentUsername } from '../lib/opensearch';
import { buildMatchFilters, entityField } from '../lib/correlation';

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

const triggerSchema = schema.object({
  type: schema.oneOf([schema.literal('per_alert'), schema.literal('burst')]),
  entity: schema.maybe(schema.oneOf(CORRELATION_ENTITIES.map((e) => schema.literal(e)) as any)),
  windowMinutes: schema.maybe(schema.number({ min: 1, max: 1440 })),
  threshold: schema.maybe(schema.number({ min: 2, max: 1000 })),
});

const actionsSchema = schema.object({
  createCase: schema.boolean({ defaultValue: false }),
  caseSeverity: schema.maybe(schema.oneOf(CASE_SEVERITIES.map((s) => schema.literal(s)) as any)),
  setStatus: schema.maybe(schema.nullable(schema.oneOf(ALERT_STATUSES.map((s) => schema.literal(s)) as any))),
  assignTo: schema.maybe(schema.nullable(schema.string({ maxLength: 256 }))),
});

const ruleBody = {
  name: schema.string({ minLength: 1, maxLength: 200 }),
  enabled: schema.boolean({ defaultValue: true }),
  match: matchSchema,
  trigger: triggerSchema,
  actions: actionsSchema,
};

/**
 * Cross-field rule validation the flat schema can't express: a rule needs at
 * least one action; the burst trigger needs its grouping fields; and create-case
 * requires the burst trigger (a single alert is not a burst).
 * Returns an error message, or null when the rule is valid.
 */
function validateRule(r: any): string | null {
  const a = r.actions || {};
  const t = r.trigger || {};
  const hasAction = !!a.createCase || !!a.setStatus || !!(a.assignTo && String(a.assignTo).trim());
  if (!hasAction) return 'Select at least one action: create case, set status, or assign to an analyst.';
  if (t.type === 'burst') {
    if (!t.entity) return 'The burst trigger needs an entity to group by (host, IP, user…).';
    if (t.threshold == null) return 'The burst trigger needs an alert threshold.';
    if (t.windowMinutes == null) return 'The burst trigger needs a time window.';
  }
  if (a.createCase) {
    if (t.type !== 'burst') return 'The "create case" action requires the burst trigger.';
    if (!a.caseSeverity) return 'The "create case" action needs a case severity.';
  }
  return null;
}

/**
 * Runs a rule's match predicate over a lookback window and reports how many
 * entity values would have crossed the threshold - the mandatory dry-run an
 * operator sees before enabling a rule. Read-only: it never writes a case.
 */
async function previewRule(client: any, rule: any, lookbackHours: number) {
  const from = `now-${lookbackHours}h`;
  const query = {
    bool: {
      must: [{ range: { '@timestamp': { gte: from, lte: 'now' } } }],
      filter: buildMatchFilters(rule.match),
    },
  };
  const trigger = rule.trigger || { type: 'per_alert' };
  const wantsBurst = trigger.type === 'burst' && !!trigger.entity;
  const threshold = trigger.threshold || 2;
  const match = rule.match || {};
  const covIds: string[] = match.ruleIdsMode === 'all' ? (match.ruleIds || []).map(String) : [];
  const covGroups: string[] = match.ruleGroupsMode === 'all' ? match.ruleGroups || [] : [];
  const covAgents: string[] = match.agentNamesMode === 'all' ? match.agentNames || [] : [];
  const needCoverage = covIds.length > 0 || covGroups.length > 0 || covAgents.length > 0;

  // Per-entity coverage sub-aggregations: one named filter per required value so
  // we can confirm each is present (doc_count > 0) on the entity.
  const covAggs: any = {};
  if (covIds.length) {
    covAggs.cov_ids = { filters: { filters: Object.fromEntries(covIds.map((id) => [id, { term: { 'rule.id': id } }])) } };
  }
  if (covGroups.length) {
    covAggs.cov_grps = { filters: { filters: Object.fromEntries(covGroups.map((g) => [g, { term: { 'rule.groups': g } }])) } };
  }
  if (covAgents.length) {
    covAggs.cov_agts = { filters: { filters: Object.fromEntries(covAgents.map((a) => [a, { term: { 'agent.name': a } }])) } };
  }

  const run = async (aggField: string | null) =>
    client.search({
      index: ALERT_STATUS_INDEX,
      body: {
        size: 0,
        query,
        aggs: aggField
          ? { by_entity: { terms: { field: aggField, size: 1000, min_doc_count: threshold }, aggs: covAggs } }
          : {},
        track_total_hits: true,
      },
    });

  let res: any;
  if (wantsBurst) {
    const field = entityField(trigger.entity);
    try {
      res = await run(field);
    } catch (e) {
      // Older indices map the opportunistic entity field as text; fall back to
      // its .keyword subfield so the preview still works.
      res = await run(`${field}.keyword`);
    }
  } else {
    res = await run(null);
  }

  let buckets = res.body.aggregations?.by_entity?.buckets || [];
  if (needCoverage) {
    buckets = buckets.filter((b: any) => {
      const idsOk = !covIds.length || covIds.every((id) => (b.cov_ids?.buckets?.[id]?.doc_count || 0) > 0);
      const grpsOk = !covGroups.length || covGroups.every((g) => (b.cov_grps?.buckets?.[g]?.doc_count || 0) > 0);
      const agtsOk = !covAgents.length || covAgents.every((a) => (b.cov_agts?.buckets?.[a]?.doc_count || 0) > 0);
      return idsOk && grpsOk && agtsOk;
    });
  }
  return {
    triggerType: trigger.type,
    windowMinutes: trigger.windowMinutes || 0,
    lookbackHours,
    matchingAlerts: res.body.hits.total?.value ?? 0,
    triggeringEntities: buckets.map((b: any) => ({ entity: b.key, count: b.doc_count })),
    wouldOpenCases: wantsBurst && rule.actions?.createCase ? buckets.length : 0,
  };
}

export function defineRuleRoutes(router: IRouter) {
  router.get({ path: `${API_ROOT}/rules`, validate: false }, async (context, request, response) => {
    try {
      const client = context.core.opensearch.client.asCurrentUser;
      const res: any = await client.search({
        index: RULES_INDEX,
        body: { size: 200, sort: [{ created_at: { order: 'desc' } }], query: { match_all: {} } },
      });
      const rules = res.body.hits.hits.map((h: any) => ({ id: h._id, ...h._source }));
      return response.ok({ body: { rules } });
    } catch (e: any) {
      return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
    }
  });

  router.post(
    { path: `${API_ROOT}/rules`, validate: { body: schema.object(ruleBody) } },
    async (context, request, response) => {
      const client = context.core.opensearch.client.asCurrentUser;
      const err = validateRule(request.body as any);
      if (err) return response.badRequest({ body: { message: err } });
      const user = await getCurrentUsername(context, request);
      const now = new Date().toISOString();
      const doc = { ...(request.body as any), created_by: user, created_at: now, updated_at: now, matchCount: 0, lastFired: null };
      try {
        const res: any = await client.index({ index: RULES_INDEX, body: doc, refresh: 'wait_for' });
        return response.ok({ body: { id: res.body._id, ...doc } });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );

  router.put(
    {
      path: `${API_ROOT}/rules/{id}`,
      validate: {
        params: schema.object({ id: schema.string() }),
        // Every field optional - a PUT is a partial update (e.g. just toggling
        // `enabled` from the rules list).
        body: schema.object({
          name: schema.maybe(schema.string({ minLength: 1, maxLength: 200 })),
          enabled: schema.maybe(schema.boolean()),
          match: schema.maybe(matchSchema),
          trigger: schema.maybe(triggerSchema),
          actions: schema.maybe(actionsSchema),
        }),
      },
    },
    async (context, request, response) => {
      const { id } = request.params as any;
      const client = context.core.opensearch.client.asCurrentUser;
      const body = request.body as any;
      // A full edit (the flyout sends `actions`) is validated; a partial patch
      // such as toggling `enabled` from the list is not.
      if (body.actions !== undefined) {
        const err = validateRule(body);
        if (err) return response.badRequest({ body: { message: err } });
      }
      const fields: any = { ...body, updated_at: new Date().toISOString() };
      try {
        await client.update({ index: RULES_INDEX, id, body: { doc: fields }, refresh: 'wait_for' });
        const updated: any = await client.get({ index: RULES_INDEX, id });
        return response.ok({ body: { id, ...updated.body._source } });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );

  router.delete(
    { path: `${API_ROOT}/rules/{id}`, validate: { params: schema.object({ id: schema.string() }) } },
    async (context, request, response) => {
      const { id } = request.params as any;
      const client = context.core.opensearch.client.asCurrentUser;
      try {
        await client.delete({ index: RULES_INDEX, id, refresh: 'wait_for' });
        return response.ok({ body: { deleted: true } });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );

  // Dry-run: accepts a full rule body (unsaved) plus an optional lookback.
  router.post(
    {
      path: `${API_ROOT}/rules/preview`,
      validate: {
        body: schema.object({ ...ruleBody, lookbackHours: schema.maybe(schema.number({ min: 1, max: 168 })) }),
      },
    },
    async (context, request, response) => {
      const client = context.core.opensearch.client.asCurrentUser;
      const { lookbackHours, ...rule } = request.body as any;
      try {
        const result = await previewRule(client, rule, lookbackHours || 24);
        return response.ok({ body: result });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );
}
