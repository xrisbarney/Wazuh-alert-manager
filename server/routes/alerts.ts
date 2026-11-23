import { schema } from '@osd/config-schema';
import { IRouter } from '../../../../src/core/server';
import { API_ROOT, ALERT_STATUS_INDEX, ALERT_STATUSES, ASSET_CRITICALITIES, CLOSURE_REASON_MAX_LENGTH, DISPOSITIONS, ENRICHMENT_VERDICT_FILTERS, SLA_STATES } from '../../common';
import { dispositionFilterValues, normaliseClosureReason } from '../lib/disposition';
import { severityDisplay, severityRangeClause } from '../../common/severity';
import { getCurrentUsername } from '../lib/opensearch';
import { APPEND_HISTORY_SCRIPT_SOURCE, buildHistoryEntry } from '../lib/history';
import { resolveAlerts } from '../lib/index_resolution';
import { pushActivityBulk } from '../lib/activity';
import { reconcileCaseEvidence } from '../lib/case_evidence_service';
import { buildReportingUpdate, REPORTING_MERGE_SCRIPT, slaStateClause } from '../lib/reporting_fields';
import { getSlaPolicy } from '../lib/sla/policy';
import { resolveCase } from '../lib/case_index_resolution';
import { isApprovedEvidenceIndex, isApprovedSourceIndex } from '../lib/index_namespace';
import { sourceFamilyOfIndex, sourceProfile } from '../lib/source_profile';
import {
  CSV_EXPORT_MAX_ROWS,
  CSV_EXPORT_PAGE_SIZE,
  CsvColumn,
  csvExportFilename,
  csvExportStream,
  downloadResponse,
  searchAfterOf,
} from '../lib/http_download';

/** Query filters shared by the alert list, counts and CSV export routes. */
export const filterQuerySchema = schema.object({
  statuses: schema.maybe(schema.string()), // csv
  levelMin: schema.maybe(schema.number()),
  levelMax: schema.maybe(schema.number()),
  ruleIds: schema.maybe(schema.string()), // csv
  agentNames: schema.maybe(schema.string()), // csv
  alertTypes: schema.maybe(schema.string()), // csv, maps to rule.groups
  assignedTo: schema.maybe(schema.string()), // csv
  caseId: schema.maybe(schema.string()),
  // Stored enrichment worst verdict (step 6.3); absent = any.
  enrichmentVerdict: schema.maybe(schema.oneOf(ENRICHMENT_VERDICT_FILTERS.map((v) => schema.literal(v)) as any)),
  // Stamped asset criticality (step 6.4a); csv of low|medium|high|critical, unknown values ignored.
  assetCriticality: schema.maybe(schema.string()),
  // Due-date state (step 3.2) over reporting.sla_due_at: breached | due_soon | on_track.
  slaState: schema.maybe(schema.oneOf(SLA_STATES.map((v) => schema.literal(v)) as any)),
  // Close outcome (step 2.4): csv of DISPOSITIONS values, unknown values ignored.
  disposition: schema.maybe(schema.string()),
  q: schema.maybe(schema.string()),
  from: schema.maybe(schema.string()),
  to: schema.maybe(schema.string()),
});

/** Due timestamp of an alert (step 3.2). */
export const ALERT_DUE_FIELD = 'reporting.sla_due_at';

/**
 * Sort field aliases: the queue sends `sla_due_at` (or the stored path) for
 * the Due column; everything else is passed through as before.
 */
const ALERT_SORT_FIELD_ALIASES: Record<string, string> = { sla_due_at: ALERT_DUE_FIELD };

export function resolveAlertSortField(sortField: unknown): string {
  const field = typeof sortField === 'string' && sortField ? sortField : '@timestamp';
  // Own-property lookup: a client-sent `toString` or `constructor` would
  // otherwise resolve to an inherited member of the alias map.
  return Object.prototype.hasOwnProperty.call(ALERT_SORT_FIELD_ALIASES, field) ? ALERT_SORT_FIELD_ALIASES[field] : field;
}

/** Bool query for the alert read alias from the validated list filters. */
export function buildBoolQuery(query: Record<string, any>, includeStatusFilter: boolean, now: string = new Date().toISOString()) {
  const filter: any[] = [];
  const must: any[] = [];

  if (includeStatusFilter && query.statuses) {
    filter.push({ terms: { status: String(query.statuses).split(',').filter(Boolean) } });
  }
  // Numeric bounds apply to 4.x rule.level and, through severity bands, to
  // 5.0 label-only findings (see common/severity.ts).
  const severityClause = severityRangeClause(query.levelMin, query.levelMax);
  if (severityClause) filter.push(severityClause);
  if (query.ruleIds) {
    filter.push({ terms: { 'rule.id': String(query.ruleIds).split(',').filter(Boolean) } });
  }
  if (query.agentNames) {
    filter.push({ terms: { 'agent.name': String(query.agentNames).split(',').filter(Boolean) } });
  }
  if (query.alertTypes) {
    filter.push({ terms: { 'rule.groups': String(query.alertTypes).split(',').filter(Boolean) } });
  }
  if (query.assignedTo) {
    filter.push({ terms: { assigned_to: String(query.assignedTo).split(',').filter(Boolean) } });
  }
  if (query.caseId) {
    filter.push({ term: { case_id: query.caseId } });
  }
  if (query.enrichmentVerdict) {
    filter.push({ term: { 'enrichment.worst_verdict': query.enrichmentVerdict } });
  }
  if (query.assetCriticality) {
    const values = String(query.assetCriticality)
      .split(',')
      .filter((value) => (ASSET_CRITICALITIES as readonly string[]).includes(value));
    if (values.length) filter.push({ terms: { 'asset.criticality': values } });
  }
  if (query.slaState) {
    filter.push(slaStateClause(query.slaState, ALERT_DUE_FIELD, now));
  }
  if (query.disposition) {
    const values = dispositionFilterValues(query.disposition);
    if (values.length) filter.push({ terms: { disposition: values } });
  }
  if (query.from || query.to) {
    const range: any = {};
    if (query.from) range.gte = query.from;
    if (query.to) range.lte = query.to;
    filter.push({ range: { '@timestamp': range } });
  }
  if (query.q) {
    must.push({
      query_string: {
        query: query.q,
        default_operator: 'AND',
        analyze_wildcard: true,
        lenient: true,
      },
    });
  }

  if (must.length === 0 && filter.length === 0) {
    return { match_all: {} };
  }
  return { bool: { must, filter } };
}

export function buildAlertListSearchBody(q: any) {
  return {
    from: q.from_offset || 0,
    size: q.size || 20,
    // Workbench totals are operational controls, not sampled search
    // estimates. OpenSearch otherwise caps hits.total.value at 10,000.
    track_total_hits: true,
    // Alerts without a due date (no severity) always sort after the dated ones.
    sort: [{ [resolveAlertSortField(q.sortField)]: { order: q.sortDirection || 'desc', missing: '_last' } }],
    query: buildBoolQuery(q, true),
  };
}

export function buildAlertCountSearchBody(q: any) {
  return {
    size: 0,
    track_total_hits: true,
    query: buildBoolQuery(q, false),
    aggs: { status_counts: { terms: { field: 'status', size: 10 } } },
  };
}

/** An alert hit as the export reads it from the read alias. */
export interface AlertExportRecord {
  _id: string;
  _source: Record<string, any>;
  sort?: unknown[];
}

/**
 * CSV columns of `GET /alerts/export.csv`, in output order. The one place the
 * column list lives; later steps (case report, scheduled summaries) reuse it.
 * Severity is written as the common band plus the raw 4.x level and the 5.0
 * label, so one file reads the same on both Wazuh lines.
 */
export const ALERT_EXPORT_COLUMNS: ReadonlyArray<CsvColumn<AlertExportRecord>> = [
  { header: 'id', value: (hit) => hit._id },
  // Named without the `@` so the header is not caught by the formula guard.
  { header: 'timestamp', value: (hit) => hit._source?.['@timestamp'] ?? '' },
  { header: 'status', value: (hit) => hit._source?.status ?? '' },
  { header: 'assignee', value: (hit) => hit._source?.assigned_to ?? '' },
  { header: 'severity', value: (hit) => severityDisplay(hit._source).band ?? '' },
  { header: 'rule.level', value: (hit) => hit._source?.rule?.level ?? '' },
  { header: 'severity_label', value: (hit) => hit._source?.severity_label ?? '' },
  { header: 'rule.id', value: (hit) => hit._source?.rule?.id ?? '' },
  { header: 'rule.description', value: (hit) => hit._source?.rule?.description ?? '' },
  { header: 'agent.id', value: (hit) => hit._source?.agent?.id ?? '' },
  { header: 'agent.name', value: (hit) => hit._source?.agent?.name ?? '' },
  { header: 'data.srcip', value: (hit) => hit._source?.data?.srcip ?? '' },
  { header: 'data.dstip', value: (hit) => hit._source?.data?.dstip ?? '' },
  { header: 'asset.criticality', value: (hit) => hit._source?.asset?.criticality ?? '' },
  { header: 'enrichment.worst_verdict', value: (hit) => hit._source?.enrichment?.worst_verdict ?? '' },
  { header: 'reporting.sla_due_at', value: (hit) => hit._source?.reporting?.sla_due_at ?? '' },
  { header: 'case_id', value: (hit) => hit._source?.case_id ?? '' },
  // Close outcome (step 2.4); empty until the alert is closed with one.
  { header: 'disposition', value: (hit) => hit._source?.disposition ?? '' },
  { header: 'last_updated', value: (hit) => hit._source?.updated_at ?? '' },
];

/** Source fields the export needs (keeps 10,000-row pages small). */
const ALERT_EXPORT_SOURCE_FIELDS = [
  '@timestamp', 'status', 'assigned_to', 'rule.level', 'rule.id', 'rule.description', 'severity_label',
  'agent.id', 'agent.name', 'data.srcip', 'data.dstip', 'asset.criticality', 'enrichment.worst_verdict', 'disposition',
  'reporting.sla_due_at', 'case_id', 'updated_at',
];

/**
 * One `search_after` page of the export: newest first, `alert_uid` as the
 * tiebreak (a keyword with doc values; `_id` would need fielddata, which
 * `indices.id_field_data.enabled: false` forbids).
 * `track_total_hits` is bounded at the cap + 1, enough to know whether rows
 * were dropped without counting the whole alias.
 */
export function buildAlertExportSearchBody(q: any, searchAfter?: unknown[] | null): Record<string, any> {
  return {
    size: CSV_EXPORT_PAGE_SIZE,
    track_total_hits: CSV_EXPORT_MAX_ROWS + 1,
    _source: ALERT_EXPORT_SOURCE_FIELDS,
    sort: [{ '@timestamp': { order: 'desc' } }, { alert_uid: { order: 'asc' } }],
    query: buildBoolQuery(q, true),
    ...(searchAfter && searchAfter.length ? { search_after: searchAfter } : {}),
  };
}

export function defineAlertRoutes(router: IRouter) {
  router.get(
    {
      path: `${API_ROOT}/alerts`,
      validate: {
        query: filterQuerySchema.extends({
          from_offset: schema.maybe(schema.number({ min: 0 })),
          size: schema.maybe(schema.number({ min: 1, max: 500 })),
          sortField: schema.maybe(schema.string()),
          sortDirection: schema.maybe(schema.oneOf([schema.literal('asc'), schema.literal('desc')])),
        }),
      },
    },
    async (context, request, response) => {
      const q = request.query as any;
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const result: any = await client.search({
          index: ALERT_STATUS_INDEX,
          body: buildAlertListSearchBody(q),
        });
        return response.ok({ body: result.body });
      } catch (e: any) {
        return response.customError({
          statusCode: e?.meta?.statusCode || 500,
          body: { message: e.message },
        });
      }
    }
  );

  // Same filters as the list, streamed as CSV. Reads only the managed read
  // alias (never a native index), as the current user, capped at
  // CSV_EXPORT_MAX_ROWS; `x-wam-truncated: true` says rows were dropped.
  router.get(
    {
      path: `${API_ROOT}/alerts/export.csv`,
      validate: { query: filterQuerySchema },
    },
    async (context, request, response) => {
      const q = request.query as any;
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const logger: any = (context as any).wazuhAlertManager?.logger || console;
        const page = async (searchAfter?: unknown[] | null) => {
          const result: any = await client.search({ index: ALERT_STATUS_INDEX, body: buildAlertExportSearchBody(q, searchAfter) });
          const hits: AlertExportRecord[] = result.body?.hits?.hits || [];
          return { records: hits, searchAfter: searchAfterOf(hits), total: result.body?.hits?.total };
        };
        const first = await page(null);
        const rawTotal = first.total;
        const total = typeof rawTotal === 'number' ? rawTotal : Number(rawTotal?.value ?? 0);
        const truncated = total > CSV_EXPORT_MAX_ROWS || rawTotal?.relation === 'gte';
        const body = csvExportStream<AlertExportRecord>({
          columns: ALERT_EXPORT_COLUMNS,
          firstPage: first,
          fetchPage: page,
          onTruncated: (written) => logger.warn(`alerts CSV export truncated at ${written} rows (cap ${CSV_EXPORT_MAX_ROWS})`),
          onError: (error: any) => logger.error(`alerts CSV export failed mid-stream: ${error?.message || error}`),
        });
        return downloadResponse(response, {
          filename: csvExportFilename('alerts'),
          contentType: 'text/csv; charset=utf-8',
          headers: truncated ? { 'x-wam-truncated': 'true' } : undefined,
          body,
        });
      } catch (e: any) {
        return response.customError({
          statusCode: e?.meta?.statusCode || 500,
          body: { message: e.message },
        });
      }
    }
  );

  router.get(
    {
      path: `${API_ROOT}/alerts/counts`,
      validate: { query: filterQuerySchema },
    },
    async (context, request, response) => {
      const q = request.query as any;
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const result: any = await client.search({
          index: ALERT_STATUS_INDEX,
          body: buildAlertCountSearchBody(q),
        });
        const counts: Record<string, number> = { open: 0, in_progress: 0, closed: 0 };
        for (const bucket of result.body.aggregations?.status_counts?.buckets || []) {
          counts[bucket.key] = bucket.doc_count;
        }
        return response.ok({
          body: {
            ...counts,
            total: result.body.hits.total?.value ?? 0,
          },
        });
      } catch (e: any) {
        return response.customError({
          statusCode: e?.meta?.statusCode || 500,
          body: { message: e.message },
        });
      }
    }
  );

  router.post(
    {
      path: `${API_ROOT}/alerts/bulk-update`,
      validate: {
        body: schema.object({
          ids: schema.arrayOf(schema.string(), { minSize: 1, maxSize: 1000 }),
          status: schema.maybe(schema.oneOf(ALERT_STATUSES.map((s) => schema.literal(s)) as any)),
          caseId: schema.maybe(schema.nullable(schema.string())),
          assignedTo: schema.maybe(schema.nullable(schema.string())),
          // Close outcome (step 2.4): applied only together with `status: 'closed'`.
          disposition: schema.maybe(schema.oneOf(DISPOSITIONS.map((value) => schema.literal(value)) as any)),
          closureReason: schema.maybe(schema.nullable(schema.string({ maxLength: CLOSURE_REASON_MAX_LENGTH }))),
        }),
      },
    },
    async (context, request, response) => {
      const { ids, status, caseId, assignedTo, disposition, closureReason } = request.body as any;
      if (status == null && caseId === undefined && assignedTo === undefined) {
        return response.badRequest({ body: { message: 'Provide at least one of status, caseId, or assignedTo' } });
      }

      const user = await getCurrentUsername(context, request);
      const client = context.core.opensearch.client.asCurrentUser;

      try {
        const uniqueIds = Array.from(new Set((ids as string[]).filter(Boolean)));
        if (uniqueIds.length !== ids.length) {
          return response.badRequest({ body: { message: 'Alert IDs must be unique.' } });
        }
        if (typeof caseId === 'string' && !caseId.trim()) {
          return response.badRequest({ body: { message: 'Target case ID cannot be empty.' } });
        }
        const locations = await resolveAlerts(client, uniqueIds, true);
        const missing = uniqueIds.filter((id) => !locations.has(id));
        if (missing.length) {
          return response.badRequest({ body: { message: 'Every alert must exist in managed storage.', missing } });
        }
        if (caseId) {
          try {
            await resolveCase(client, caseId);
          } catch (e: any) {
            if ((e?.meta?.statusCode || e?.statusCode) === 404) {
              return response.badRequest({ body: { message: `Target case ${caseId} was not found.` } });
            }
            throw e;
          }
        }

        const successful = new Set(uniqueIds);
        const linkageResults: any[] = [];
        if (caseId !== undefined) {
          if (caseId) {
            const linkage = await reconcileCaseEvidence(client, {
              caseId,
              linkAlertIds: uniqueIds,
              actor: user,
              action: 'case_link',
            });
            linkageResults.push(linkage);
            const linked = new Set(linkage.linkedAlertIds);
            for (const id of uniqueIds) if (!linked.has(id)) successful.delete(id);
          } else {
            const byCase = new Map<string, string[]>();
            for (const id of uniqueIds) {
              const oldCaseId = locations.get(id)?.source?.case_id;
              if (!oldCaseId) continue;
              const group = byCase.get(oldCaseId) || [];
              group.push(id);
              byCase.set(oldCaseId, group);
            }
            for (const [oldCaseId, alertIds] of byCase) {
              const linkage = await reconcileCaseEvidence(client, {
                caseId: oldCaseId,
                unlinkAlertIds: alertIds,
                actor: user,
                action: 'case_unlink',
              });
              linkageResults.push(linkage);
              const unlinked = new Set(linkage.unlinkedAlertIds);
              for (const id of alertIds) if (!unlinked.has(id)) successful.delete(id);
            }
          }
        }

        const fields: Record<string, any> = { updated_at: new Date().toISOString(), updated_by: user };
        if (status != null) fields.status = status;
        if (assignedTo !== undefined) fields.assigned_to = assignedTo;
        // The disposition belongs to a close: any other status change leaves
        // the stored outcome alone (reopening keeps it for audit).
        const closing = status === 'closed';
        if (closing && disposition) fields.disposition = disposition;
        if (closing && closureReason !== undefined) fields.closure_reason = normaliseClosureReason(closureReason);
        const changedFields = [
          status != null && 'status_change',
          caseId !== undefined && 'case_link',
          assignedTo !== undefined && 'assignment_change',
        ].filter(Boolean);
        const action = changedFields.length > 1 ? 'bulk_update' : (changedFields[0] as string);
        const entry: Record<string, any> = buildHistoryEntry({ user, action, to: status ?? assignedTo ?? caseId ?? null });
        if (closing && disposition) entry.disposition = disposition;
        const activityDetails = closing && (disposition || fields.closure_reason)
          ? { disposition: disposition ?? null, closure_reason: fields.closure_reason ?? null }
          : null;
        const body: any[] = [];
        const owners: string[] = [];
        if (status != null || assignedTo !== undefined) {
          const now = new Date().toISOString();
          const scriptSource = APPEND_HISTORY_SCRIPT_SOURCE + '\n' + REPORTING_MERGE_SCRIPT;
          const slaPolicy = await getSlaPolicy(client, (context as any).wazuhAlertManager?.logger || console);
          for (const id of uniqueIds) {
            const location = locations.get(id)!;
            const reporting = buildReportingUpdate(location.source, { status, assignedTo }, now, slaPolicy);
            body.push({ update: { _index: location.index, _id: id } });
            body.push({
              script: {
                lang: 'painless',
                source: scriptSource,
                params: { entry, fields, reporting },
              },
            });
            owners.push(id);
            pushActivityBulk(body, { targetType: 'alert', targetId: id, user, action, to: entry.to, details: activityDetails });
            owners.push(id);
          }
        }
        const failed: any[] = [];
        if (body.length) {
          // wait_for: the Workbench queue and alert flyout re-read these alerts
          // through a search right after this call; without it they could show
          // the old status/assignee until the next index refresh. It waits for
          // the scheduled refresh rather than forcing one, so large batches
          // (up to 1000 alerts) add at most ~1s instead of refresh load.
          const result: any = await client.bulk({ body, refresh: 'wait_for' });
          const items = result?.body?.items;
          if (!Array.isArray(items) || items.length !== owners.length) {
            throw new Error(`Bulk response contained ${Array.isArray(items) ? items.length : 0} item(s) for ${owners.length} operation(s)`);
          }
          items.forEach((item: any, index: number) => {
            const detail = item?.update || item?.index;
            const itemStatus = Number(detail?.status || 0);
            if (!detail || detail.error || itemStatus < 200 || itemStatus >= 300) {
              successful.delete(owners[index]);
              failed.push({ alertId: owners[index], operation: item });
            }
          });
        }
        if (failed.length || linkageResults.some((item) => !item.ok)) {
          return response.customError({
            statusCode: 207,
            body: {
              message: `${uniqueIds.length - successful.size}/${uniqueIds.length} alert updates were incomplete`,
              requested: uniqueIds.length,
              updated: successful.size,
              failed,
              linkage: linkageResults,
            },
          });
        }
        return response.ok({ body: { requested: uniqueIds.length, updated: successful.size } });
      } catch (e: any) {
        return response.customError({
          statusCode: e?.meta?.statusCode || 500,
          body: { message: e.message },
        });
      }
    }
  );

  router.get(
    {
      path: `${API_ROOT}/alerts/{id}`,
      validate: { params: schema.object({ id: schema.string() }) },
    },
    async (context, request, response) => {
      const { id } = request.params as any;
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const locations = await resolveAlerts(client, [id], true);
        const found = locations.get(id);
        if (!found) return response.notFound({ body: { message: 'Alert not found' } });
        let rawSource: any = null;
        let rawEvent: any = null;
        const sourceIndex = found.source?.source_index;
        const sourceId = found.source?.source_id;
        // Hydrate only from an exact physical index that the stored record's
        // own family approves (4.x wazuh-alerts-*, 5.0 .ds-wazuh-findings-v5-*).
        // The family comes from the index name itself, so records projected by
        // either build stay readable after a platform transition, and a
        // tampered or stale projection can never point the server elsewhere.
        const family = typeof sourceIndex === 'string' ? sourceFamilyOfIndex(sourceIndex) : null;
        const profile = family ? sourceProfile(family) : null;
        if (found.source?.source_resolved && profile && sourceId && isApprovedSourceIndex(sourceIndex, profile)) {
          try {
            const raw: any = await client.get({ index: sourceIndex, id: sourceId });
            rawSource = raw.body?._source || null;
          } catch (e) {
            // Native retention may have expired. The compact operational
            // projection remains available and is explicitly marked below.
          }
          // 5.0: a finding references its underlying event. Follow it only
          // when both parts pass the strict events backing-index matcher.
          const eventIndex = rawSource?.event?.index ?? found.source?.event_index;
          const eventDocId = rawSource?.event?.doc_id ?? found.source?.event_doc_id;
          if (typeof eventIndex === 'string' && typeof eventDocId === 'string' && eventDocId &&
              isApprovedEvidenceIndex(eventIndex, profile)) {
            try {
              const raw: any = await client.get({ index: eventIndex, id: eventDocId });
              rawEvent = raw.body?._source || null;
            } catch (e) {
              // Event retention is independent of finding retention.
            }
          }
        }
        return response.ok({
          body: {
            _index: found.index,
            _id: id,
            found: true,
            _source: found.source,
            _raw_source: rawSource,
            _source_available: Boolean(rawSource),
            _raw_event: rawEvent,
            _event_available: Boolean(rawEvent),
            _source_family: family,
          },
        });
      } catch (e: any) {
        return response.customError({
          statusCode: e?.meta?.statusCode || 500,
          body: { message: e.message },
        });
      }
    }
  );

  // Precedent: how this same rule has been handled on this host before, so an
  // analyst can see "we've seen this 47 times and closed 44" before spending
  // time. Deterministic, no LLM. Aggregation over already-mapped keyword fields.
  router.get(
    {
      path: `${API_ROOT}/alerts/{id}/precedent`,
      validate: { params: schema.object({ id: schema.string() }) },
    },
    async (context, request, response) => {
      const { id } = request.params as any;
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const locations = await resolveAlerts(client, [id], true);
        const src = locations.get(id)?.source;
        if (!src) return response.notFound({ body: { message: 'Alert not found' } });
        const ruleId = src.rule?.id != null ? String(src.rule.id) : null;
        const agentName = src.agent?.name || null;
        if (!ruleId) {
          return response.ok({ body: { ruleId: null, agentName, total: 0, byStatus: {}, escalatedToCase: 0 } });
        }
        const must: any[] = [{ term: { 'rule.id': ruleId } }];
        if (agentName) must.push({ term: { 'agent.name': agentName } });
        const aggRes: any = await client.search({
          index: ALERT_STATUS_INDEX,
          body: {
            size: 0,
            track_total_hits: true,
            query: { bool: { must } },
            aggs: {
              by_status: { terms: { field: 'status', size: 5 } },
              escalated: { filter: { exists: { field: 'case_id' } } },
            },
          },
        });
        const byStatus: Record<string, number> = { open: 0, in_progress: 0, closed: 0 };
        for (const b of aggRes.body.aggregations?.by_status?.buckets || []) {
          if (b.key in byStatus) byStatus[b.key] = b.doc_count;
        }
        return response.ok({
          body: {
            ruleId,
            agentName,
            ruleDescription: src.rule?.description || null,
            total: aggRes.body.hits.total?.value ?? 0,
            byStatus,
            escalatedToCase: aggRes.body.aggregations?.escalated?.doc_count ?? 0,
          },
        });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );

  router.get(
    {
      path: `${API_ROOT}/alerts/{id}/related`,
      validate: { params: schema.object({ id: schema.string() }) },
    },
    async (context, request, response) => {
      const { id } = request.params as any;
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const locations = await resolveAlerts(client, [id], true);
        const relatedIds: string[] = locations.get(id)?.source?.related_alert_ids || [];
        if (relatedIds.length === 0) {
          return response.ok({ body: { alerts: [] } });
        }
        const relatedLocations = await resolveAlerts(client, relatedIds, true);
        const alerts = relatedIds
          .map((rid) => relatedLocations.get(rid))
          .filter(Boolean)
          .map((d: any) => ({ _id: d.id, _source: d.source }));
        return response.ok({ body: { alerts } });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );

  // Suggested related alerts: other alerts that share an entity (host, source
  // IP, source user, or rule) with this one, within a time window, ranked by how
  // many entities they share and recency. Deterministic triage help — surfaces
  // the alerts an analyst would otherwise search for by hand. Never mutates.
  router.get(
    {
      path: `${API_ROOT}/alerts/{id}/suggested`,
      validate: { params: schema.object({ id: schema.string() }) },
    },
    async (context, request, response) => {
      const { id } = request.params as any;
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const locations = await resolveAlerts(client, [id], true);
        const src = locations.get(id)?.source || {};
        if (!locations.has(id)) return response.notFound({ body: { message: 'Alert not found' } });
        const already: string[] = src.related_alert_ids || [];

        const isPlaceholder = (v: any) => {
          const s = v == null ? '' : String(v);
          return !s || s === '0.0.0.0' || s === '127.0.0.1' || s === '-' || s.toLowerCase() === 'localhost';
        };
        // Each shared entity contributes a should-clause and, if a candidate
        // matches it, a weighted reason. Hosts/IPs/users are stronger signals
        // than a shared rule id.
        const facets: Array<{ field: string; value: any; weight: number; label: (v: string) => string }> = [
          { field: 'agent.name', value: src.agent?.name, weight: 3, label: (v) => `same host ${v}` },
          { field: 'data.srcip', value: src.data?.srcip, weight: 3, label: (v) => `same source IP ${v}` },
          { field: 'data.srcuser', value: src.data?.srcuser, weight: 3, label: (v) => `same user ${v}` },
          { field: 'rule.id', value: src.rule?.id, weight: 1, label: (v) => `same rule ${v}` },
        ].filter((f) => !isPlaceholder(f.value));

        if (facets.length === 0) {
          return response.ok({ body: { alerts: [] } });
        }

        const ts = src['@timestamp'];
        const tMs = ts ? Date.parse(ts) : Date.now();
        const DAY = 86400000;
        const shoulds = facets.map((f) => ({ term: { [f.field]: f.value } }));

        const res: any = await client.search({
          index: ALERT_STATUS_INDEX,
          body: {
            size: 60,
            _source: ['@timestamp', 'agent', 'data.srcip', 'data.srcuser', 'rule', 'status', 'case_id', 'assigned_to'],
            query: {
              bool: {
                must: [{ range: { '@timestamp': { gte: new Date(tMs - DAY).toISOString(), lte: new Date(tMs + DAY).toISOString() } } }],
                should: shoulds,
                minimum_should_match: 1,
                must_not: [{ ids: { values: [id, ...already] } }],
              },
            },
            sort: [{ '@timestamp': { order: 'desc' } }],
          },
        });

        const scored = (res.body.hits.hits || []).map((h: any) => {
          const hs = h._source || {};
          const reasons: string[] = [];
          let score = 0;
          for (const f of facets) {
            const hv = f.field === 'agent.name' ? hs.agent?.name : f.field === 'rule.id' ? hs.rule?.id : hs.data?.[f.field.split('.')[1]];
            if (hv != null && String(hv) === String(f.value)) {
              reasons.push(f.label(String(f.value)));
              score += f.weight;
            }
          }
          // Recency tiebreaker: closer in time ranks higher.
          const proximity = 1 - Math.min(1, Math.abs(Date.parse(hs['@timestamp'] || '') - tMs) / DAY);
          return { _id: h._id, _source: hs, reasons, score: score + proximity };
        });
        scored.sort((a: any, b: any) => b.score - a.score);

        return response.ok({ body: { alerts: scored.slice(0, 8) } });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );

  router.post(
    {
      path: `${API_ROOT}/alerts/{id}/related`,
      validate: {
        params: schema.object({ id: schema.string() }),
        body: schema.object({
          relatedIds: schema.arrayOf(schema.string(), { minSize: 1, maxSize: 50 }),
          mode: schema.oneOf([schema.literal('add'), schema.literal('remove')]),
        }),
      },
    },
    async (context, request, response) => {
      const { id } = request.params as any;
      const { relatedIds, mode } = request.body as any;
      const user = await getCurrentUsername(context, request);
      const client = context.core.opensearch.client.asCurrentUser;

      const scriptSource =
        mode === 'add'
          ? `
            if (ctx._source.related_alert_ids == null) { ctx._source.related_alert_ids = []; }
            for (id in params.ids) { if (!ctx._source.related_alert_ids.contains(id)) { ctx._source.related_alert_ids.add(id); } }
          `
          : `
            if (ctx._source.related_alert_ids != null) { ctx._source.related_alert_ids.removeIf(v -> params.ids.contains(v)); }
          `;

      const entry = buildHistoryEntry({
        user,
        action: mode === 'add' ? 'related_alert_linked' : 'related_alert_unlinked',
        to: relatedIds.join(', '),
      });

      try {
        if (new Set([id, ...relatedIds]).size !== relatedIds.length + 1) {
          return response.badRequest({
            body: { message: 'Related alert IDs must be unique and cannot include the source alert.' },
          });
        }
        const locations = await resolveAlerts(client, [id, ...relatedIds]);
        const sourceIndex = locations.get(id)?.index;
        if (!sourceIndex) return response.notFound({ body: { message: 'Alert not found' } });
        const missing = relatedIds.filter((relatedId: string) => !locations.has(relatedId));
        if (missing.length) {
          return response.badRequest({ body: { message: 'Every related alert must exist in managed storage.', missing } });
        }
        const body: any[] = [
          { update: { _index: sourceIndex, _id: id } },
          { script: { lang: 'painless', source: scriptSource, params: { ids: relatedIds } } },
          { update: { _index: sourceIndex, _id: id } },
          {
            script: {
              lang: 'painless',
              source: APPEND_HISTORY_SCRIPT_SOURCE,
              params: { entry, fields: null },
            },
          },
        ];
        for (const relatedId of relatedIds) {
          const targetIndex = locations.get(relatedId)!.index;
          body.push({ update: { _index: targetIndex, _id: relatedId } });
          body.push({ script: { lang: 'painless', source: scriptSource, params: { ids: [id] } } });
        }

        // wait_for: the Related Alerts panel re-reads related_alert_ids (and
        // the Suggested exclusions) through a search immediately after this
        // call, and a search only sees the update once the index refreshes.
        // Without it the panel showed the pre-link state until a later reload.
        const result: any = await client.bulk({ body, refresh: 'wait_for' });
        const items = result?.body?.items;
        const expectedItems = relatedIds.length + 2;
        if (!Array.isArray(items) || items.length !== expectedItems) {
          throw new Error(`Bulk response contained ${Array.isArray(items) ? items.length : 0} item(s) for ${expectedItems} operation(s)`);
        }
        const failed = items.filter((item: any) => {
          const detail = item?.update;
          const itemStatus = Number(detail?.status || 0);
          return !detail || detail.error || itemStatus < 200 || itemStatus >= 300;
        });
        if (failed.length) {
          return response.customError({
            statusCode: 207,
            body: { message: `${failed.length}/${expectedItems} relationship updates failed`, updated: false, failed },
          });
        }
        return response.ok({ body: { updated: true, alertsUpdated: relatedIds.length + 1 } });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );
}
