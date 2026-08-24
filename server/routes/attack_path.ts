import { schema } from '@osd/config-schema';
import { IRouter } from '../../../../src/core/server';
import { API_ROOT, CASES_INDEX, ALERT_STATUS_INDEX } from '../../common';
import { buildAttackGraph } from '../lib/attack_graph';

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
        const caseRes: any = await client.get({ index: CASES_INDEX, id });
        const alertIds: string[] = caseRes.body._source.alert_ids || [];

        if (alertIds.length === 0) {
          return response.ok({ body: { nodes: [], edges: [], killChain: [], hops: [] } });
        }

        const mgetRes: any = await client.mget({ index: ALERT_STATUS_INDEX, body: { ids: alertIds } });
        const alerts = mgetRes.body.docs
          .filter((d: any) => d.found)
          .map((d: any) => ({ _id: d._id, _source: d._source }));

        return response.ok({ body: buildAttackGraph(alerts) });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );
}
