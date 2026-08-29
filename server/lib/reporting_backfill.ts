import { Logger } from '../../../../src/core/server';
import { ALERTS_READ_ALIAS, ACTIVITY_READ_ALIAS, META_INDEX } from '../../common';
import { assertManagedWriteTarget } from './index_namespace';
import { loadReportActivity, deriveAlertReporting } from './report_metrics';
import { REPORTING_MERGE_SCRIPT } from './reporting_fields';

const BACKFILL_STATE_ID = 'reporting_backfill_state_v2';
const PAGE_SIZE = 500;

interface BackfillState {
  last_id?: string;
  processed: number;
  updated: number;
  started_at?: string;
  completed_at?: string;
}

async function loadState(client: any): Promise<BackfillState> {
  try {
    const res: any = await client.get({ index: META_INDEX, id: BACKFILL_STATE_ID });
    return res?.body?._source || { processed: 0, updated: 0 };
  } catch (e: any) {
    if ((e?.meta?.statusCode || e?.statusCode) === 404) return { processed: 0, updated: 0 };
    throw e;
  }
}

async function saveState(client: any, state: BackfillState) {
  await client.index({
    index: assertManagedWriteTarget(META_INDEX),
    id: BACKFILL_STATE_ID,
    body: { ...state, updated_at: new Date().toISOString() },
    refresh: 'wait_for',
  });
}

// Alerts that have triage history but predate the write-time reporting fields.
// Everything else (never-assigned, never-closed) has nothing to materialize and
// is correctly skipped, so the backfill is bounded by real work and terminates.
function candidateQuery(): any {
  return {
    bool: {
      should: [
        {
          bool: {
            filter: [{ term: { status: 'closed' } }],
            must_not: [{ exists: { field: 'reporting.closed_at' } }],
          },
        },
        {
          bool: {
            filter: [{ exists: { field: 'assigned_to' } }],
            must_not: [{ exists: { field: 'reporting.first_assigned_at' } }],
          },
        },
      ],
      minimum_should_match: 1,
    },
  };
}

/**
 * Materialize write-time reporting fields for live alerts that already have
 * assignment/close history but lack the derived fields. Idempotent and
 * resumable via a meta-document `search_after` cursor on `_id`.
 */
export async function runReportingBackfill(client: any, logger: Logger) {
  let state = await loadState(client);
  if (state.completed_at) {
    // Completed in a previous run. Re-scan only if a re-run is explicitly
    // requested; routine startup does nothing.
    return state;
  }

  let afterId: string | undefined = state.last_id;
  let pageCount = 0;
  let anyUpdated = false;

  try {
    while (true) {
      const body: any = {
        size: PAGE_SIZE,
        sort: [{ alert_uid: { order: 'asc' } }],
        _source: ['@timestamp', 'status', 'assigned_to', 'rule.level', 'history'],
        query: candidateQuery(),
      };
      if (afterId) body.search_after = [afterId];

      const res: any = await client.search({ index: ALERTS_READ_ALIAS, body });
      const hits = res?.body?.hits?.hits || [];
      if (!hits.length) break;

      const activity = await loadReportActivity(
        client,
        ACTIVITY_READ_ALIAS,
        hits.map((h: any) => h._id)
      );

      const updates: any[] = [];
      let pageUpdated = 0;
      for (const hit of hits) {
        const reporting = deriveAlertReporting(hit._source || {}, activity[hit._id] || []);
        updates.push({ update: { _index: hit._index, _id: hit._id } });
        updates.push({
          script: { lang: 'painless', source: REPORTING_MERGE_SCRIPT, params: { reporting } },
        });
        pageUpdated += 1;
      }
      if (updates.length) {
        const bulk: any = await client.bulk({ body: updates });
        const failed = (bulk?.body?.items || []).filter(
          (item: any) => {
            const detail = item?.update;
            const status = Number(detail?.status || 0);
            return !detail || detail.error || status < 200 || status >= 300;
          }
        ).length;
        if (failed) {
          throw new Error(`reporting backfill: ${failed} of ${updates.length / 2} updates failed`);
        }
        state.updated += pageUpdated;
        anyUpdated = true;
      }

      state.processed += hits.length;
      state.last_id = hits[hits.length - 1]._source?.alert_uid || hits[hits.length - 1]._id;
      afterId = state.last_id;
      pageCount += 1;

      // Persist progress every page so a crash resumes without rescanning.
      await saveState(client, state);
      if (pageCount % 100 === 0) {
        logger.info(`wazuh-alert-manager: reporting backfill progress (${state.processed} scanned, ${state.updated} updated)`);
      }
    }
  } catch (e: any) {
    logger.error(`wazuh-alert-manager: reporting backfill failed: ${e.message}`);
    throw e;
  }

  state.completed_at = new Date().toISOString();
  await saveState(client, state);
  logger.info(
    `wazuh-alert-manager: reporting backfill complete (${state.processed} scanned, ${state.updated} updated)`
  );
  return state;
}

export async function reportingBackfillStatus(client: any): Promise<any> {
  const state = await loadState(client);
  return state;
}
