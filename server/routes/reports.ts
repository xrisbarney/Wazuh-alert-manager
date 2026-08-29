import { schema } from '@osd/config-schema';
import { IRouter } from '../../../../src/core/server';
import { API_ROOT, ALERT_STATUS_INDEX, CASES_INDEX, CASE_SEVERITIES } from '../../common';
import {
  collectCompositeBuckets,
} from '../lib/report_metrics';
import { REPORTING_SLA_POLICY } from '../lib/reporting_fields';

function average(values: number[]): number | null {
  return values.length ? values.reduce((sum, v) => sum + v, 0) / values.length : null;
}

interface AssigneeStatus {
  open: number;
  in_progress: number;
  closed: number;
}

function assigneeStatusFromBuckets(buckets: any[] = []): AssigneeStatus {
  const s: AssigneeStatus = { open: 0, in_progress: 0, closed: 0 };
  for (const sb of buckets) if (sb.key in s) (s as any)[sb.key] = sb.doc_count;
  return s;
}

export function defineReportRoutes(router: IRouter) {
  router.get(
    {
      path: `${API_ROOT}/reports/metrics`,
      validate: {
        query: schema.object({
          from: schema.string(),
          to: schema.string(),
        }),
      },
    },
    async (context, request, response) => {
      const { from, to } = request.query as any;
      const client = context.core.opensearch.client.asCurrentUser;

      try {
        const alertQuery = { range: { '@timestamp': { gte: from, lte: to } } };

        // One exact aggregation query replaces the previous sampled document
        // walk. Timing/SLA are read straight from the bounded write-time
        // `reporting.*` fields, so nothing here depends on hit limits.
        const result: any = await client.search({
          index: ALERT_STATUS_INDEX,
          body: {
            size: 0,
            track_total_hits: true,
            query: alertQuery,
            aggs: {
              status_breakdown: { terms: { field: 'status', size: 10 } },
              per_day: {
                date_histogram: {
                  field: '@timestamp',
                  fixed_interval: '1d',
                  min_doc_count: 0,
                  extended_bounds: { min: from, max: to },
                },
                aggs: { by_status: { terms: { field: 'status', size: 5 } } },
              },
              assigned: {
                filter: { exists: { field: 'reporting.first_assigned_at' } },
                aggs: { avg_minutes: { avg: { field: 'reporting.assign_minutes' } } },
              },
              resolved: {
                filter: {
                  bool: {
                    filter: [
                      { term: { status: 'closed' } },
                      { exists: { field: 'reporting.resolve_minutes' } },
                    ],
                  },
                },
                aggs: {
                  avg_minutes: { avg: { field: 'reporting.resolve_minutes' } },
                  by_tier: {
                    terms: { field: 'reporting.sla_tier', size: 10 },
                    aggs: {
                      met: { filter: { term: { 'reporting.sla_met': true } } },
                      breached: { filter: { term: { 'reporting.sla_met': false } } },
                    },
                  },
                },
              },
              coverage: {
                filters: {
                  filters: {
                    closed_missing: {
                      bool: {
                        filter: [{ term: { status: 'closed' } }],
                        must_not: [{ exists: { field: 'reporting.closed_at' } }],
                      },
                    },
                    assigned_missing: {
                      bool: {
                        filter: [{ exists: { field: 'assigned_to' } }],
                        must_not: [{ exists: { field: 'reporting.first_assigned_at' } }],
                      },
                    },
                  },
                },
              },
            },
          },
        });

        const totalMatched = result.body.hits.total?.value ?? 0;

        const statusBreakdown: Record<string, number> = { open: 0, in_progress: 0, closed: 0 };
        for (const b of result.body.aggregations?.status_breakdown?.buckets || []) {
          if (b.key in statusBreakdown) statusBreakdown[b.key] = b.doc_count;
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

        const assignedAgg = result.body.aggregations?.assigned;
        const assignedCount = assignedAgg?.doc_count ?? 0;
        const meanTimeToAssignMinutes = assignedAgg?.avg_minutes?.value != null
          ? assignedAgg.avg_minutes.value
          : null;

        const resolvedAgg = result.body.aggregations?.resolved;
        const resolvedCount = resolvedAgg?.doc_count ?? 0;
        const meanTimeToResolveMinutes = resolvedAgg?.avg_minutes?.value != null
          ? resolvedAgg.avg_minutes.value
          : null;

        const slaBreakdown = (resolvedAgg?.by_tier?.buckets || []).map((b: any) => ({
          label: b.key,
          met: b.met?.doc_count ?? 0,
          breached: b.breached?.doc_count ?? 0,
        }));
        const slaTracked = slaBreakdown.reduce((sum, b) => sum + b.met + b.breached, 0);
        const slaMet = slaBreakdown.reduce((sum, b) => sum + b.met, 0);
        const slaCompliancePct = slaTracked ? (slaMet / slaTracked) * 100 : null;

        const coverageAgg = result.body.aggregations?.coverage?.buckets || {};
        const coverage = {
          closedMissingReporting: coverageAgg.closed_missing?.doc_count ?? 0,
          assignedMissingReporting: coverageAgg.assigned_missing?.doc_count ?? 0,
        };

        // Per-analyst workload: complete cardinality via composite pagination on
        // assigned_to (keyword). Fresh installs map it as keyword; installs that
        // predate the explicit mapping expose it as text with a `.keyword`
        // subfield, so fall back to that.
        let analysts: any[] = [];
        const analystStatus = new Map<string, AssigneeStatus>();
        try {
          const workloadBuckets = await collectCompositeBuckets(
            client,
            {
              index: ALERT_STATUS_INDEX,
              query: { bool: { must: [alertQuery], filter: [{ exists: { field: 'assigned_to' } }] } },
              bucket: {
                composite: { size: 1000, sources: [{ assignee: { terms: { field: 'assigned_to' } } }] },
                aggs: { by_status: { terms: { field: 'status', size: 5 } } },
              },
            }
          ).catch(() => collectCompositeBuckets(
            client,
            {
              index: ALERT_STATUS_INDEX,
              query: { bool: { must: [alertQuery], filter: [{ exists: { field: 'assigned_to' } }] } },
              bucket: {
                composite: { size: 1000, sources: [{ assignee: { terms: { field: 'assigned_to.keyword' } } }] },
                aggs: { by_status: { terms: { field: 'status', size: 5 } } },
              },
            }
          ));
          for (const b of workloadBuckets) {
            analystStatus.set(b.key.assignee, assigneeStatusFromBuckets(b.by_status?.buckets));
          }
        } catch (e: any) {
          throw new Error(`Exact per-analyst workload aggregation failed: ${e.message || e}`);
        }

        // Per-analyst resolution: complete cardinality on the write-time
        // assignee_at_close field with exact mean resolve times.
        const analystResolve = new Map<string, { count: number; minutes: number[] }>();
        try {
          const resolutionBuckets = await collectCompositeBuckets(client, {
            index: ALERT_STATUS_INDEX,
            query: {
              bool: {
                must: [alertQuery],
                filter: [
                  { term: { status: 'closed' } },
                  { exists: { field: 'reporting.resolve_minutes' } },
                  { exists: { field: 'reporting.assignee_at_close' } },
                ],
              },
            },
            bucket: {
              composite: {
                size: 1000,
                sources: [{ assignee: { terms: { field: 'reporting.assignee_at_close' } } }],
              },
              aggs: { avg_minutes: { avg: { field: 'reporting.resolve_minutes' } } },
            },
          });
          for (const b of resolutionBuckets) {
            analystResolve.set(b.key.assignee, {
              count: b.doc_count ?? 0,
              minutes: b.avg_minutes?.value != null ? [b.avg_minutes.value] : [],
            });
          }
        } catch (e: any) {
          throw new Error(`Exact per-analyst resolution aggregation failed: ${e.message || e}`);
        }

        analysts = Array.from(analystStatus.entries())
          .map(([assignee, status]) => {
            const resolve = analystResolve.get(assignee);
            return {
              assignee,
              total: status.open + status.in_progress + status.closed,
              open: status.open,
              in_progress: status.in_progress,
              closed: status.closed,
              resolvedCount: resolve?.count ?? 0,
              meanTimeToResolveMinutes: resolve?.minutes?.length ? average(resolve.minutes) : null,
            };
          })
          .sort((x, y) => y.total - x.total);

        // Cases opened in the same period. All calculations stay in OpenSearch;
        // high-cardinality assignees are paged with a composite aggregation.
        // This remains exact without materialising the case cohort in dashboard
        // memory, even when the selected period contains millions of cases.
        const caseSeverityBreakdown = Object.fromEntries(CASE_SEVERITIES.map((s) => [s, 0])) as Record<string, number>;
        let totalCases = 0;
        let openCases = 0;
        let inProgressCases = 0;
        let closedCases = 0;
        let meanCaseCloseMinutes: number | null = null;
        let closedCaseTimingCount = 0;
        let caseAnalysts: any[] = [];
        const closeMinutesScript = {
          lang: 'painless',
          source: "(doc['closed_at'].value.toInstant().toEpochMilli() - doc['created_at'].value.toInstant().toEpochMilli()) / 60000.0",
        };
        try {
          const caseResult: any = await client.search({
            index: CASES_INDEX,
            body: {
              size: 0,
              track_total_hits: true,
              query: { range: { created_at: { gte: from, lte: to } } },
              aggs: {
                by_status: { terms: { field: 'status', size: 10 } },
                by_severity: { terms: { field: 'severity', size: 10 } },
                closed_timing: {
                  filter: { bool: { filter: [
                    { term: { status: 'closed' } },
                    { exists: { field: 'created_at' } },
                    { exists: { field: 'closed_at' } },
                  ] } },
                  aggs: { average_minutes: { avg: { script: closeMinutesScript } } },
                },
              },
            },
          });
          totalCases = caseResult?.body?.hits?.total?.value ?? 0;
          for (const bucket of caseResult?.body?.aggregations?.by_status?.buckets || []) {
            if (bucket.key === 'open') openCases = bucket.doc_count;
            else if (bucket.key === 'in_progress') inProgressCases = bucket.doc_count;
            else if (bucket.key === 'closed') closedCases = bucket.doc_count;
          }
          for (const bucket of caseResult?.body?.aggregations?.by_severity?.buckets || []) {
            if (bucket.key in caseSeverityBreakdown) caseSeverityBreakdown[bucket.key] = bucket.doc_count;
          }
          const timing = caseResult?.body?.aggregations?.closed_timing;
          closedCaseTimingCount = timing?.doc_count ?? 0;
          meanCaseCloseMinutes = timing?.average_minutes?.value ?? null;

          const caseAssigneeBuckets = await collectCompositeBuckets(client, {
            index: CASES_INDEX,
            query: { bool: { filter: [
              { range: { created_at: { gte: from, lte: to } } },
              { exists: { field: 'assigned_to' } },
            ] } },
            bucket: {
              composite: { size: 1000, sources: [{ assignee: { terms: { field: 'assigned_to' } } }] },
              aggs: {
                by_status: { terms: { field: 'status', size: 5 } },
                closed_timing: {
                  filter: { bool: { filter: [
                    { term: { status: 'closed' } },
                    { exists: { field: 'created_at' } },
                    { exists: { field: 'closed_at' } },
                  ] } },
                  aggs: { average_minutes: { avg: { script: closeMinutesScript } } },
                },
              },
            },
          });
          caseAnalysts = caseAssigneeBuckets.map((bucket: any) => {
            const status = assigneeStatusFromBuckets(bucket.by_status?.buckets);
            return {
              assignee: bucket.key.assignee,
              ...status,
              total: status.open + status.in_progress + status.closed,
              meanTimeToCloseMinutes: bucket.closed_timing?.average_minutes?.value ?? null,
            };
          }).sort((x: any, y: any) => y.total - x.total);
        } catch (e: any) {
          throw new Error(`Exact case aggregation failed: ${e.message || e}`);
        }

        return response.ok({
          body: {
            from,
            to,
            totalAlerts: totalMatched,
            exact: true,
            alertBasis: 'exact_cohort',
            timingBasis: 'exact_cohort',
            caseBasis: 'exact_cohort',
            // Alerts in the cohort that predate the write-time reporting fields
            // and have not yet been materialized by the resumable backfill.
            coverage,
            statusBreakdown,
            alertsPerDay,
            statusPerDay,
            resolvedCount,
            assignedCount,
            meanTimeToResolveMinutes,
            meanTimeToAssignMinutes,
            slaCompliancePct,
            slaBreakdown,
            slaPolicy: REPORTING_SLA_POLICY,
            analysts,
            caseAnalysts,
            cases: {
              totalCases,
              statusBreakdown: { open: openCases, in_progress: inProgressCases, closed: closedCases },
              severityBreakdown: caseSeverityBreakdown,
              meanTimeToCloseMinutes: meanCaseCloseMinutes,
              closedCount: closedCaseTimingCount,
            },
          },
        });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );
}
