import { IRouter } from '../../../../src/core/server';
import { API_ROOT, ALERT_STATUS_INDEX } from '../../common';

async function termsAgg(client: any, field: string, fallbackField: string) {
  try {
    const res: any = await client.search({
      index: ALERT_STATUS_INDEX,
      body: { size: 0, aggs: { vals: { terms: { field, size: 100 } } } },
    });
    return res.body.aggregations.vals.buckets;
  } catch (e) {
    const res: any = await client.search({
      index: ALERT_STATUS_INDEX,
      body: { size: 0, aggs: { vals: { terms: { field: fallbackField, size: 100 } } } },
    });
    return res.body.aggregations.vals.buckets;
  }
}

export function defineFilterRoutes(router: IRouter) {
  router.get(
    {
      path: `${API_ROOT}/filters/options`,
      validate: false,
    },
    async (context, request, response) => {
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const [ruleIdBuckets, agentBuckets, alertTypeBuckets, assigneeBuckets, levelStats] = await Promise.all([
          termsAgg(client, 'rule.id', 'rule.id.keyword'),
          termsAgg(client, 'agent.name', 'agent.name.keyword'),
          termsAgg(client, 'rule.groups', 'rule.groups.keyword'),
          termsAgg(client, 'assigned_to', 'assigned_to.keyword'),
          client
            .search({
              index: ALERT_STATUS_INDEX,
              body: { size: 0, aggs: { level_stats: { stats: { field: 'rule.level' } } } },
            })
            .then((r: any) => r.body.aggregations.level_stats),
        ]);

        return response.ok({
          body: {
            ruleIds: ruleIdBuckets.map((b: any) => ({ value: b.key, count: b.doc_count })),
            agents: agentBuckets.map((b: any) => ({ value: b.key, count: b.doc_count })),
            alertTypes: alertTypeBuckets.map((b: any) => ({ value: b.key, count: b.doc_count })),
            assignees: assigneeBuckets.map((b: any) => ({ value: b.key, count: b.doc_count })),
            levelRange: {
              min: Number.isFinite(levelStats.min) ? Math.floor(levelStats.min) : 0,
              max: Number.isFinite(levelStats.max) ? Math.ceil(levelStats.max) : 15,
            },
          },
        });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );
}
