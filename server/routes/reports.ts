import { schema } from '@osd/config-schema';
import { IRouter } from '../../../../src/core/server';
import { API_ROOT, ALERT_STATUS_INDEX, CASES_INDEX, CASE_SEVERITIES } from '../../common';

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
            // Exact totals rather than the 10k default cap, so totalAlerts and
            // the status breakdown are truthful even on large windows.
            track_total_hits: true,
            query: { range: { '@timestamp': { gte: from, lte: to } } },
            _source: ['@timestamp', 'status', 'rule.level', 'history', 'assigned_to'],
            // Status counts come from an aggregation over the FULL match, not
            // the (possibly truncated) sample - otherwise the breakdown would
            // not reconcile with totalAlerts. Time-based metrics below still
            // walk the sample because they need each doc's history array.
            aggs: {
              status_breakdown: { terms: { field: 'status', size: 10 } },
              // Alert volume per day over the window, for the trend chart. Empty
              // days are included so the line does not lie about quiet periods.
              per_day: {
                date_histogram: {
                  field: '@timestamp',
                  fixed_interval: '1d',
                  min_doc_count: 0,
                  extended_bounds: { min: from, max: to },
                },
                // Current disposition of each day's alerts, for the stacked
                // status-over-time chart.
                aggs: {
                  by_status: { terms: { field: 'status', size: 5 } },
                },
              },
            },
          },
        });

        const hits = result.body.hits.hits;
        const totalMatched = result.body.hits.total?.value ?? hits.length;
        const truncated = hits.length < totalMatched;

        const statusBreakdown = { open: 0, in_progress: 0, closed: 0 };
        for (const b of result.body.aggregations?.status_breakdown?.buckets || []) {
          if (b.key in statusBreakdown) (statusBreakdown as any)[b.key] = b.doc_count;
        }

        const perDayBuckets = result.body.aggregations?.per_day?.buckets || [];
        const alertsPerDay = perDayBuckets.map((b: any) => ({
          date: b.key_as_string || new Date(b.key).toISOString(),
          count: b.doc_count,
        }));
        const statusPerDay = perDayBuckets.map((b: any) => {
          const row: any = { date: b.key_as_string || new Date(b.key).toISOString(), open: 0, in_progress: 0, closed: 0 };
          for (const sb of b.by_status?.buckets || []) {
            if (sb.key in row) row[sb.key] = sb.doc_count;
          }
          return row;
        });

        const resolveMinutesList: number[] = [];
        const assignMinutesList: number[] = [];
        const slaBuckets: Record<string, { label: string; met: number; breached: number }> = {};
        // Per-assignee resolve times, gathered from the sample so we can report
        // mean-time-to-resolve per analyst (labelled sample-based, like the
        // overall figure). Keyed by assignee name.
        const perAssigneeResolve: Record<string, number[]> = {};

        for (const hit of hits) {
          const src = hit._source;
          const occurredAt = new Date(src['@timestamp']).getTime();
          const history: any[] = src.history || [];

          const closeEntries = history.filter((h) => h.action === 'status_change' && h.to === 'closed');
          if (closeEntries.length) {
            const resolvedAt = new Date(closeEntries[closeEntries.length - 1].timestamp).getTime();
            const resolveMinutes = (resolvedAt - occurredAt) / 60000;
            if (resolveMinutes >= 0) {
              resolveMinutesList.push(resolveMinutes);
              if (src.assigned_to) {
                (perAssigneeResolve[src.assigned_to] || (perAssigneeResolve[src.assigned_to] = [])).push(resolveMinutes);
              }
              const tier = slaForLevel(src.rule?.level || 0);
              const bucket = slaBuckets[tier.label] || (slaBuckets[tier.label] = { label: tier.label, met: 0, breached: 0 });
              if (resolveMinutes <= tier.targetMinutes) bucket.met += 1;
              else bucket.breached += 1;
            }
          }

          // Only explicit assignment actions. A 'bulk_update' entry's `to` is
          // `status ?? assignedTo ?? caseId` (see alerts.ts bulk-update), so a
          // status-only bulk change would otherwise be miscounted as an
          // assignment and pollute mean-time-to-assign. A single-field bulk
          // assign is already recorded as 'assignment_change', so nothing real
          // is lost by excluding 'bulk_update' here.
          const assignEntries = history.filter((h) => h.action === 'assignment_change' && h.to);
          if (assignEntries.length) {
            const assignedAt = new Date(assignEntries[0].timestamp).getTime();
            const assignMinutes = (assignedAt - occurredAt) / 60000;
            if (assignMinutes >= 0) assignMinutesList.push(assignMinutes);
          }
        }

        const slaBreakdown = Object.values(slaBuckets);
        const slaTracked = slaBreakdown.reduce((sum, b) => sum + b.met + b.breached, 0);
        const slaMet = slaBreakdown.reduce((sum, b) => sum + b.met, 0);

        // Cases opened in the same period, for the Reports tab's case
        // section. Cases are typically far fewer than alerts, so no
        // sampling cap here - a straight aggregation query is enough.
        const caseSeverityBreakdown = Object.fromEntries(CASE_SEVERITIES.map((s) => [s, 0])) as Record<string, number>;
        let totalCases = 0;
        let openCases = 0;
        let inProgressCases = 0;
        let closedCases = 0;
        const caseCloseMinutesList: number[] = [];
        // Per-assignee case stats, keyed by owner name.
        const caseByAssignee: Record<string, { open: number; in_progress: number; closed: number; closeMinutes: number[] }> = {};

        try {
          const caseResult: any = await client.search({
            index: CASES_INDEX,
            body: {
              size: 2000,
              query: { range: { created_at: { gte: from, lte: to } } },
              _source: ['status', 'severity', 'created_at', 'closed_at', 'assigned_to'],
            },
          });
          const caseHits = caseResult.body.hits.hits;
          totalCases = caseResult.body.hits.total?.value ?? caseHits.length;
          for (const hit of caseHits) {
            const src = hit._source;
            if (src.status === 'open') openCases += 1;
            else if (src.status === 'in_progress') inProgressCases += 1;
            else if (src.status === 'closed') closedCases += 1;
            if (src.severity in caseSeverityBreakdown) caseSeverityBreakdown[src.severity] += 1;
            let closeMin: number | null = null;
            if (src.status === 'closed' && src.closed_at) {
              const minutes = (new Date(src.closed_at).getTime() - new Date(src.created_at).getTime()) / 60000;
              if (minutes >= 0) {
                caseCloseMinutesList.push(minutes);
                closeMin = minutes;
              }
            }
            if (src.assigned_to) {
              const a =
                caseByAssignee[src.assigned_to] ||
                (caseByAssignee[src.assigned_to] = { open: 0, in_progress: 0, closed: 0, closeMinutes: [] });
              if (src.status === 'open') a.open += 1;
              else if (src.status === 'in_progress') a.in_progress += 1;
              else if (src.status === 'closed') a.closed += 1;
              if (closeMin != null) a.closeMinutes.push(closeMin);
            }
          }
        } catch (e) {
          // non-fatal - the alert metrics above are still useful on their own
        }

        // Per-analyst ALERT workload (exact, via aggregation on assigned_to).
        // Runs as its own query wrapped in try/catch: on installs whose
        // assigned_to field predates the explicit keyword mapping it is text and
        // cannot be aggregated - degrade to an empty analyst list rather than
        // failing the whole report.
        let analysts: any[] = [];
        // Fresh installs map assigned_to as keyword; installs predating that
        // explicit mapping have it as text with a `.keyword` subfield. Try the
        // plain field first, fall back to the subfield, so per-analyst stats
        // work on both without a reindex.
        const runAssigneeAgg = (field: string) =>
          client.search({
            index: ALERT_STATUS_INDEX,
            body: {
              size: 0,
              query: {
                bool: {
                  must: [{ range: { '@timestamp': { gte: from, lte: to } } }],
                  filter: [{ exists: { field: 'assigned_to' } }],
                },
              },
              aggs: {
                by_assignee: {
                  terms: { field, size: 100 },
                  aggs: { by_status: { terms: { field: 'status', size: 5 } } },
                },
              },
            },
          });
        try {
          let aRes: any;
          try {
            aRes = await runAssigneeAgg('assigned_to');
          } catch (inner) {
            aRes = await runAssigneeAgg('assigned_to.keyword');
          }
          analysts = (aRes.body.aggregations?.by_assignee?.buckets || []).map((b: any) => {
            const s = { open: 0, in_progress: 0, closed: 0 };
            for (const sb of b.by_status.buckets) if (sb.key in s) (s as any)[sb.key] = sb.doc_count;
            const resolves = perAssigneeResolve[b.key] || [];
            return {
              assignee: b.key,
              total: b.doc_count,
              open: s.open,
              in_progress: s.in_progress,
              closed: s.closed,
              resolvedCount: resolves.length,
              meanTimeToResolveMinutes: average(resolves),
            };
          });
          analysts.sort((x, y) => y.total - x.total);
        } catch (e) {
          // assigned_to not aggregatable on this index - leave analysts empty
        }

        const caseAnalysts = Object.entries(caseByAssignee)
          .map(([assignee, v]) => ({
            assignee,
            open: v.open,
            in_progress: v.in_progress,
            closed: v.closed,
            total: v.open + v.in_progress + v.closed,
            meanTimeToCloseMinutes: average(v.closeMinutes),
          }))
          .sort((x, y) => y.total - x.total);

        return response.ok({
          body: {
            from,
            to,
            totalAlerts: totalMatched,
            sampledAlerts: hits.length,
            sampleLimit: sampleSize,
            // Status counts and totalAlerts are exact (aggregation + tracked
            // total). Time-based metrics (MTTR/MTTA/SLA) are computed over the
            // sample only; when truncated the UI should say so.
            truncated,
            statusBreakdown,
            alertsPerDay,
            statusPerDay,
            resolvedCount: resolveMinutesList.length,
            assignedCount: assignMinutesList.length,
            meanTimeToResolveMinutes: average(resolveMinutesList),
            meanTimeToAssignMinutes: average(assignMinutesList),
            slaCompliancePct: slaTracked ? (slaMet / slaTracked) * 100 : null,
            slaBreakdown,
            slaPolicy: SLA_POLICY,
            analysts,
            caseAnalysts,
            cases: {
              totalCases,
              statusBreakdown: { open: openCases, in_progress: inProgressCases, closed: closedCases },
              severityBreakdown: caseSeverityBreakdown,
              meanTimeToCloseMinutes: average(caseCloseMinutesList),
              closedCount: caseCloseMinutesList.length,
            },
          },
        });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );
}
