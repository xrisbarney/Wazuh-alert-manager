import { schema } from '@osd/config-schema';
import { IRouter } from '../../../../src/core/server';
import { API_ROOT, ALERT_STATUS_INDEX } from '../../common';

// Simple level-based SLA policy: how quickly a closed alert should have
// been resolved, by its rule severity level. Not configurable yet - if
// that's needed, move this into server/config.ts and thread it through.
const SLA_POLICY = [
  { minLevel: 12, label: 'Critical', targetMinutes: 60 },
  { minLevel: 7, label: 'High', targetMinutes: 240 },
  { minLevel: 4, label: 'Medium', targetMinutes: 1440 },
  { minLevel: 0, label: 'Low', targetMinutes: 4320 },
];

function slaForLevel(level: number) {
  return SLA_POLICY.find((tier) => level >= tier.minLevel) || SLA_POLICY[SLA_POLICY.length - 1];
}

function average(values: number[]): number | null {
  return values.length ? values.reduce((sum, v) => sum + v, 0) / values.length : null;
}

export function defineReportRoutes(router: IRouter) {
  router.get(
    {
      path: `${API_ROOT}/reports/metrics`,
      validate: {
        query: schema.object({
          from: schema.string(),
          to: schema.string(),
          size: schema.maybe(schema.number({ min: 1, max: 5000 })),
        }),
      },
    },
    async (context, request, response) => {
      const { from, to, size } = request.query as any;
      const client = context.core.opensearch.client.asCurrentUser;
      const sampleSize = size || 2000;

      try {
        const result: any = await client.search({
          index: ALERT_STATUS_INDEX,
          body: {
            size: sampleSize,
            query: { range: { '@timestamp': { gte: from, lte: to } } },
            _source: ['@timestamp', 'status', 'rule.level', 'history', 'assigned_to'],
          },
        });

        const hits = result.body.hits.hits;
        const totalMatched = result.body.hits.total?.value ?? hits.length;
        const truncated = hits.length < totalMatched;

        const statusBreakdown = { open: 0, in_progress: 0, closed: 0 };
        const resolveMinutesList: number[] = [];
        const assignMinutesList: number[] = [];
        const slaBuckets: Record<string, { label: string; met: number; breached: number }> = {};

        for (const hit of hits) {
          const src = hit._source;
          if (src.status in statusBreakdown) {
            (statusBreakdown as any)[src.status] += 1;
          }

          const occurredAt = new Date(src['@timestamp']).getTime();
          const history: any[] = src.history || [];

          const closeEntries = history.filter((h) => h.action === 'status_change' && h.to === 'closed');
          if (closeEntries.length) {
            const resolvedAt = new Date(closeEntries[closeEntries.length - 1].timestamp).getTime();
            const resolveMinutes = (resolvedAt - occurredAt) / 60000;
            if (resolveMinutes >= 0) {
              resolveMinutesList.push(resolveMinutes);
              const tier = slaForLevel(src.rule?.level || 0);
              const bucket = slaBuckets[tier.label] || (slaBuckets[tier.label] = { label: tier.label, met: 0, breached: 0 });
              if (resolveMinutes <= tier.targetMinutes) bucket.met += 1;
              else bucket.breached += 1;
            }
          }

          const assignEntries = history.filter(
            (h) => (h.action === 'assignment_change' || h.action === 'bulk_update') && h.to
          );
          if (assignEntries.length) {
            const assignedAt = new Date(assignEntries[0].timestamp).getTime();
            const assignMinutes = (assignedAt - occurredAt) / 60000;
            if (assignMinutes >= 0) assignMinutesList.push(assignMinutes);
          }
        }

        const slaBreakdown = Object.values(slaBuckets);
        const slaTracked = slaBreakdown.reduce((sum, b) => sum + b.met + b.breached, 0);
        const slaMet = slaBreakdown.reduce((sum, b) => sum + b.met, 0);

        return response.ok({
          body: {
            from,
            to,
            totalAlerts: totalMatched,
            sampledAlerts: hits.length,
            truncated,
            statusBreakdown,
            resolvedCount: resolveMinutesList.length,
            assignedCount: assignMinutesList.length,
            meanTimeToResolveMinutes: average(resolveMinutesList),
            meanTimeToAssignMinutes: average(assignMinutesList),
            slaCompliancePct: slaTracked ? (slaMet / slaTracked) * 100 : null,
            slaBreakdown,
            slaPolicy: SLA_POLICY,
          },
        });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );
}
