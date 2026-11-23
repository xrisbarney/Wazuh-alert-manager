import { schema } from '@osd/config-schema';
import { IRouter } from '../../../../src/core/server';
import { API_ROOT, ALERTS_READ_ALIAS, MAX_CASE_INDICATOR_ALERTS, MAX_THREAT_MATCHES } from '../../common';
import { aggregateIndicators, AlertSiblingVerdictsResponse, CaseIndicatorsResponse, ThreatMatch } from '../../common/indicators';
import { resolveCaseAlerts } from '../lib/index_resolution';
import { collectCaseEvidence } from '../lib/evidence';
import { resolveCase } from '../lib/case_index_resolution';

/**
 * Aggregate the indicators of every alert linked to a case. Reads only: the
 * case document (read alias), its evidence relationships and the alert
 * records they resolve to (live, archived or the evidence snapshot).
 */
export async function buildCaseIndicators(client: any, caseId: string): Promise<CaseIndicatorsResponse> {
  const caseRes = await resolveCase(client, caseId);
  const { evidence, truncated } = await collectCaseEvidence(client, caseId, caseRes.source.alert_ids, {
    limit: MAX_CASE_INDICATOR_ALERTS,
  });
  if (evidence.length === 0) {
    return { indicators: [], includedAlerts: 0, totalRelationships: 0, truncated, limit: MAX_CASE_INDICATOR_ALERTS };
  }
  const locations = await resolveCaseAlerts(client, evidence);
  const alerts = Array.from(locations.values())
    .filter((item) => item.source)
    .map((item) => ({ _id: item.id, _source: item.source }));
  return {
    indicators: aggregateIndicators(alerts),
    includedAlerts: alerts.length,
    totalRelationships: evidence.length,
    truncated,
    limit: MAX_CASE_INDICATOR_ALERTS,
  };
}

/** Sibling records considered per alert (VirusTotal + Maltiverse rarely exceed two). */
export const MAX_SIBLING_RECORDS = 20;

/**
 * Native verdicts carried by 4.x sibling alerts: the VirusTotal / Maltiverse
 * integrations write a separate alert whose projection stores the enriched
 * alert id in `threat.sibling_of`. Read-only over the alerts read alias; the
 * merged `threat.matches[]` are bounded like a single record's copy.
 */
export async function buildSiblingVerdicts(client: any, alertId: string): Promise<AlertSiblingVerdictsResponse> {
  const res: any = await client.search({
    index: ALERTS_READ_ALIAS,
    size: MAX_SIBLING_RECORDS,
    body: {
      query: { term: { 'threat.sibling_of': alertId } },
      sort: [{ '@timestamp': { order: 'asc' } }],
      _source: ['threat'],
    },
  });
  const hits: any[] = res?.body?.hits?.hits || [];
  const matches: ThreatMatch[] = [];
  for (const hit of hits) {
    const list = hit?._source?.threat?.matches;
    if (!Array.isArray(list)) continue;
    for (const match of list) {
      if (match && typeof match === 'object' && matches.length < MAX_THREAT_MATCHES) matches.push(match);
    }
  }
  return { matches, siblings: hits.length };
}

export function defineIndicatorRoutes(router: IRouter) {
  router.get(
    {
      path: `${API_ROOT}/alerts/{id}/sibling-verdicts`,
      validate: { params: schema.object({ id: schema.string({ minLength: 1, maxLength: 256 }) }) },
    },
    async (context, request, response) => {
      const { id } = request.params as any;
      const client = context.core.opensearch.client.asCurrentUser;
      try {
        return response.ok({ body: await buildSiblingVerdicts(client, id) });
      } catch (e: any) {
        return response.customError({
          statusCode: e?.statusCode || e?.meta?.statusCode || 500,
          body: { message: e.message },
        });
      }
    }
  );

  router.get(
    {
      path: `${API_ROOT}/cases/{id}/indicators`,
      validate: { params: schema.object({ id: schema.string({ minLength: 1, maxLength: 256 }) }) },
    },
    async (context, request, response) => {
      const { id } = request.params as any;
      const client = context.core.opensearch.client.asCurrentUser;
      try {
        return response.ok({ body: await buildCaseIndicators(client, id) });
      } catch (e: any) {
        return response.customError({
          statusCode: e?.statusCode || e?.meta?.statusCode || 500,
          body: { message: e.message },
        });
      }
    }
  );
}
