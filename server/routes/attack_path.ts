import { schema } from '@osd/config-schema';
import { IRouter } from '../../../../src/core/server';
import { API_ROOT } from '../../common';
import { buildAttackGraph } from '../lib/attack_graph';
import { resolveCaseAlerts } from '../lib/index_resolution';
import { listCaseEvidenceWithLegacy } from '../lib/evidence';
import { resolveCase } from '../lib/case_index_resolution';

export function defineAttackPathRoutes(router: IRouter) {
  router.get(
    {
      path: `${API_ROOT}/cases/{id}/attack-path`,
      validate: { params: schema.object({ id: schema.string() }) },
    },
    async (context, request, response) => {
      const { id } = request.params as any;
      const client = context.core.opensearch.client.asCurrentUser;

      try {
        const caseRes = await resolveCase(client, id);
        const relationships: any[] = [];
        const maxGraphAlerts = 5000;
        let truncated = false;
        let cursor: string | undefined;
        do {
          const page = await listCaseEvidenceWithLegacy(
            client,
            id,
            caseRes.source.alert_ids,
            { cursor }
          );
          const remaining = maxGraphAlerts - relationships.length;
          relationships.push(...page.evidence.slice(0, Math.max(0, remaining)));
          if (page.evidence.length > remaining || (page.nextCursor && relationships.length >= maxGraphAlerts)) {
            truncated = true;
            cursor = undefined;
            break;
          }
          cursor = page.nextCursor || undefined;
        } while (cursor);

        if (relationships.length === 0) {
          return response.ok({ body: {
            nodes: [], edges: [], killChain: [], hops: [],
            truncated, limit: maxGraphAlerts, includedAlerts: 0,
          } });
        }

        const locations = await resolveCaseAlerts(client, relationships);
        const alerts = Array.from(locations.values())
          .filter((item) => item.source)
          .map((item) => ({ _id: item.id, _source: item.source }));

        const graph = buildAttackGraph(alerts);
        // Attach each alert's case-relationship state (live / held / archived)
        // so a graph-filtered Linked Alerts view can show and act on it without
        // paging through the evidence list. Snapshots are deliberately omitted.
        const relationshipById = new Map(relationships.map((item: any) => [item.alert_id, item]));
        for (const hop of graph.hops) {
          const rel: any = relationshipById.get(hop.alertId);
          if (rel) {
            hop.evidence = {
              relationship_state: rel.relationship_state ?? null,
              hold_reason: rel.hold_reason ?? null,
              archive_index: rel.archive_index ?? null,
            };
          }
        }

        return response.ok({ body: {
          ...graph,
          truncated,
          limit: maxGraphAlerts,
          includedAlerts: alerts.length,
        } });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );
}
