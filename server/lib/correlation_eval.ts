import { Logger } from '../../../../src/core/server';
import { RULES_INDEX, ALERT_STATUS_INDEX, CASES_INDEX, MAX_AUTO_CASES_PER_RUN } from '../../common';
import {
  alertMatchesRule,
  entityValueFromAlert,
  entityField,
  buildMatchFilters,
  correlationKey,
  coverageRequirements,
} from './correlation';
import { APPEND_HISTORY_SCRIPT_SOURCE, buildHistoryEntry } from './history';

const RULE_ACTOR = 'correlation-rule';
const MAX_LINKED = 200;

/**
 * Normalise a stored rule into the trigger/actions shape, filling in a trigger
 * for rules created before that model (they carried entity/window/threshold at
 * the top level and always created cases).
 */
function normalizeRule(src: any): any {
  const trigger =
    src.trigger && src.trigger.type
      ? src.trigger
      : src.entity
      ? { type: 'burst', entity: src.entity, windowMinutes: src.windowMinutes, threshold: src.threshold }
      : { type: 'per_alert' };
  const actions = src.actions || { createCase: true, setStatus: null, assignTo: null };
  if (actions.caseSeverity == null && src.caseSeverity) actions.caseSeverity = src.caseSeverity;
  return { ...src, trigger, actions };
}

/**
 * Alert ids on one entity within the burst window that satisfy the trigger:
 * at least `threshold` matching alerts AND, for any 'all'-mode section, every
 * listed rule id / group / agent present at least once (co-occurrence). Returns
 * [] when not met, so a non-empty result means "this entity fired".
 */
async function windowMatches(client: any, rule: any, entityValue: string): Promise<string[]> {
  const t = rule.trigger;
  const windowFrom = new Date(Date.now() - t.windowMinutes * 60000).toISOString();
  const field = entityField(t.entity);
  const cov = coverageRequirements(rule.match);
  const needCoverage = cov.ids.length > 0 || cov.groups.length > 0 || cov.agents.length > 0;
  const body = (f: string) => ({
    size: MAX_LINKED,
    _source: false,
    track_total_hits: true,
    query: {
      bool: {
        must: [{ range: { '@timestamp': { gte: windowFrom } } }, { term: { [f]: entityValue } }],
        filter: buildMatchFilters(rule.match),
      },
    },
    // Only aggregate when a coverage check is actually needed.
    aggs: needCoverage
      ? {
          ...(cov.ids.length ? { ids: { terms: { field: 'rule.id', size: 500 } } } : {}),
          ...(cov.groups.length ? { grps: { terms: { field: 'rule.groups', size: 500 } } } : {}),
          ...(cov.agents.length ? { agts: { terms: { field: 'agent.name', size: 500 } } } : {}),
        }
      : {},
  });

  const run = async (f: string) => client.search({ index: ALERT_STATUS_INDEX, body: body(f) });
  let res: any;
  try {
    res = await run(field);
  } catch (e) {
    try {
      res = await run(`${field}.keyword`);
    } catch (e2) {
      return [];
    }
  }

  const total = res.body.hits.total?.value ?? res.body.hits.hits.length;
  if (total < t.threshold) return [];

  if (needCoverage) {
    const seen = (name: string) => new Set((res.body.aggregations?.[name]?.buckets || []).map((b: any) => String(b.key)));
    const seenIds = seen('ids');
    const seenGroups = seen('grps');
    const seenAgents = seen('agts');
    if (cov.ids.length && !cov.ids.every((id) => seenIds.has(String(id)))) return [];
    if (cov.groups.length && !cov.groups.every((g) => seenGroups.has(g))) return [];
    if (cov.agents.length && !cov.agents.every((a) => seenAgents.has(a))) return [];
  }

  return res.body.hits.hits.map((h: any) => h._id);
}

// Observability: bump a rule's fire counter + lastFired. Best-effort.
async function bumpCounters(client: any, ruleId: string) {
  try {
    await client.update({
      index: RULES_INDEX,
      id: ruleId,
      body: {
        script: {
          lang: 'painless',
          source:
            'ctx._source.matchCount = (ctx._source.matchCount == null ? 0 : ctx._source.matchCount) + 1; ctx._source.lastFired = params.now;',
          params: { now: new Date().toISOString() },
        },
      },
    });
  } catch (e) {
    /* best-effort */
  }
}

async function linkAlerts(client: any, alertIds: string[], caseId: string) {
  if (!alertIds.length) return;
  const entry = buildHistoryEntry({ user: RULE_ACTOR, action: 'auto_case_link', to: caseId });
  const body: any[] = [];
  for (const id of alertIds) {
    body.push({ update: { _index: ALERT_STATUS_INDEX, _id: id } });
    body.push({
      script: {
        lang: 'painless',
        source: APPEND_HISTORY_SCRIPT_SOURCE,
        params: { entry, fields: { case_id: caseId, updated_at: entry.timestamp, updated_by: RULE_ACTOR } },
      },
    });
  }
  await client.bulk({ body });
}

/**
 * Per-alert actions (auto-status / auto-assign) applied to every alert in this
 * tick that matches the rule. Only alerts whose value actually differs are
 * touched, so re-runs are idempotent and history stays quiet. Because
 * syncedHits are fresh alerts (the watermark has moved past everything older),
 * each alert is acted on once at ingest — an analyst who later reopens or
 * reassigns is not overridden on a subsequent tick. Returns alerts affected.
 */
async function applyPerAlertActions(client: any, rule: any, matchingHits: any[]): Promise<number> {
  const actions = rule.actions || {};
  const setStatus: string | null = actions.setStatus || null;
  // A blank assignee means "no assignment action", not "unassign".
  const assignTo: string | null = actions.assignTo ? String(actions.assignTo) : null;
  if (!setStatus && !assignTo) return 0;

  const now = new Date().toISOString();
  const body: any[] = [];
  let affected = 0;
  for (const hit of matchingHits) {
    const src = hit._source || {};
    const fields: any = { updated_at: now, updated_by: RULE_ACTOR };
    const changes: string[] = [];
    if (setStatus && src.status !== setStatus) {
      fields.status = setStatus;
      changes.push(`status→${setStatus}`);
    }
    if (assignTo && src.assigned_to !== assignTo) {
      fields.assigned_to = assignTo;
      changes.push(`assigned→${assignTo}`);
    }
    if (!changes.length) continue;
    const entry = buildHistoryEntry({ user: RULE_ACTOR, action: `rule:${rule.id}`, to: changes.join(', ') });
    body.push({ update: { _index: ALERT_STATUS_INDEX, _id: hit._id } });
    body.push({ script: { lang: 'painless', source: APPEND_HISTORY_SCRIPT_SOURCE, params: { entry, fields } } });
    affected += 1;
  }
  if (body.length) await client.bulk({ body });
  return affected;
}

/**
 * After a sync tick has copied fresh alerts in, escalate bursts into cases per
 * the enabled correlation rules. Runs inside the sync tick, so it inherits the
 * leader lock (single writer - no double-creation across replicas). For each
 * rule, entity values seen in THIS tick's alerts are the only candidates
 * considered, so the work is bounded by the batch, not the whole index.
 *
 * Safety: dedup by correlation_key (extend the still-open case rather than
 * spawn a duplicate), and a hard cap on cases created per run.
 */
export async function evaluateCorrelationRules(client: any, syncedHits: any[], logger: Logger) {
  let rules: any[] = [];
  try {
    const r: any = await client.search({
      index: RULES_INDEX,
      body: { size: 200, query: { term: { enabled: true } } },
    });
    rules = r.body.hits.hits.map((h: any) => normalizeRule({ id: h._id, ...(h._source || {}) }));
  } catch (e) {
    return; // rules index absent or unreadable - nothing to do
  }
  if (!rules.length) return;

  let casesCreated = 0;
  let capReported = false;

  for (const rule of rules) {
    const actions = rule.actions || {};
    const trigger = rule.trigger || { type: 'per_alert' };
    let fired = false;

    // Which of this tick's fresh alerts match this rule.
    const matchingHits = syncedHits.filter((h) => alertMatchesRule(rule, h._source));
    if (!matchingHits.length) continue;

    // ---- PER-ALERT trigger: actions apply to every matching alert now. ----
    if (trigger.type !== 'burst') {
      try {
        const affected = await applyPerAlertActions(client, rule, matchingHits);
        if (affected > 0) fired = true;
      } catch (e: any) {
        logger.error(`wazuh-alert-manager: rule ${rule.id} per-alert actions failed: ${e.message}`);
      }
      if (fired) await bumpCounters(client, rule.id);
      continue;
    }

    // ---- BURST trigger: group this tick's matches by entity, then evaluate the
    //      full window for each candidate entity. ----
    if (!trigger.entity || !trigger.threshold || !trigger.windowMinutes) continue;
    const entities = new Set<string>();
    for (const hit of matchingHits) {
      const ev = entityValueFromAlert(trigger.entity, hit._source);
      if (ev) entities.add(ev);
    }
    const triggeredEntities = new Set<string>();

    {
      for (const entityValue of entities) {
        const ids = await windowMatches(client, rule, entityValue);
        if (!ids.length) continue; // threshold / coverage not met
        triggeredEntities.add(entityValue);
        fired = true;

        // Case escalation is optional — only when the rule opts in.
        if (!actions.createCase) continue;
        if (casesCreated >= MAX_AUTO_CASES_PER_RUN) {
          if (!capReported) {
            logger.warn(
              `wazuh-alert-manager: correlation rules hit the per-run case cap (${MAX_AUTO_CASES_PER_RUN}); ` +
                'remaining matches will be picked up next tick. Consider narrowing rule conditions.'
            );
            capReported = true;
          }
          break;
        }

        const key = correlationKey(rule.id, entityValue);
        const now = new Date().toISOString();
        const assignee: string | null = actions.assignTo ? String(actions.assignTo) : null;

        // Dedup: is there already a still-open case for this rule+entity?
        let existing: any = null;
        try {
          const c: any = await client.search({
            index: CASES_INDEX,
            body: {
              size: 1,
              query: {
                bool: {
                  must: [{ term: { correlation_key: key } }, { terms: { status: ['open', 'in_progress'] } }],
                },
              },
            },
          });
          existing = c.body.hits.hits[0] || null;
        } catch (e) {
          /* fall through to create */
        }

        try {
          if (existing) {
            const current: string[] = existing._source.alert_ids || [];
            const merged = Array.from(new Set([...current, ...ids])).slice(0, 1000);
            const newlyLinked = ids.filter((id) => !current.includes(id));
            if (newlyLinked.length === 0) continue; // nothing new - avoid churn
            await client.update({
              index: CASES_INDEX,
              id: existing._id,
              body: {
                script: {
                  lang: 'painless',
                  source: APPEND_HISTORY_SCRIPT_SOURCE,
                  params: {
                    entry: buildHistoryEntry({ user: RULE_ACTOR, action: `rule:${rule.id}`, to: 'extended' }),
                    fields: { alert_ids: merged, updated_at: now, updated_by: RULE_ACTOR },
                  },
                },
              },
            });
            await linkAlerts(client, newlyLinked, existing._id);
            fired = true;
          } else {
            const doc = {
              title: `${rule.name}: ${entityValue}`,
              description: `Opened automatically by rule "${rule.name}" — ${ids.length} matching alerts on ${trigger.entity} ${entityValue} within ${trigger.windowMinutes} minutes.`,
              severity: actions.caseSeverity || 'medium',
              status: 'open',
              assigned_to: assignee,
              alert_ids: ids,
              correlation_key: key,
              created_by: RULE_ACTOR,
              created_at: now,
              updated_by: RULE_ACTOR,
              updated_at: now,
              closed_at: null,
              history: [buildHistoryEntry({ user: RULE_ACTOR, action: `rule:${rule.id}`, to: 'case_auto_created' })],
            };
            const res: any = await client.index({ index: CASES_INDEX, body: doc });
            await linkAlerts(client, ids, res.body._id);
            casesCreated += 1;
            fired = true;
          }
        } catch (e: any) {
          logger.error(`wazuh-alert-manager: correlation rule ${rule.id} failed on entity ${entityValue}: ${e.message}`);
        }
      }
    }

    // Burst-scoped auto-status / auto-assign: apply to THIS tick's alerts on the
    // entities that just fired (bounded, idempotent — differing values only).
    if (triggeredEntities.size && (actions.setStatus || actions.assignTo)) {
      const burstHits = matchingHits.filter((h) => {
        const ev = entityValueFromAlert(trigger.entity, h._source);
        return ev != null && triggeredEntities.has(ev);
      });
      try {
        await applyPerAlertActions(client, rule, burstHits);
      } catch (e: any) {
        logger.error(`wazuh-alert-manager: rule ${rule.id} burst actions failed: ${e.message}`);
      }
    }

    if (fired) await bumpCounters(client, rule.id);
  }

  if (casesCreated > 0) {
    logger.info(`wazuh-alert-manager: correlation rules opened ${casesCreated} case(s) this tick`);
  }
}
