import { Logger } from '../../../../src/core/server';
import { META_INDEX } from '../../common';
import { AlertManagerConfigType } from '../config';
import { projectNativeCase5 } from './adapters/wazuh5_finding_adapter';
import { assertManagedWriteTarget } from './index_namespace';
import { resolveAlerts } from './index_resolution';
import { alertUid } from './operational_projection';

/**
 * Bounded reconciliation of the read-only `native_case` projection (step 2.6).
 *
 * The main sync tick only re-reads findings whose `@timestamp` falls inside
 * the current window (last watermark minus `sync.overlapSeconds`). A native
 * case created or edited in the Wazuh Cases app is a partial update of the
 * finding that leaves `@timestamp` untouched, so a case changed more than the
 * overlap after ingestion would never reach `native_case` without this pass.
 *
 * Every 5.0 tick that completes its window therefore also searches the
 * findings family for `wazuh.case.updated_at` / `created_at` at or after its
 * own watermark (meta doc `native_case_reconcile:wazuh5_findings`), projects
 * ONLY `native_case` through the same bounded allowlist the adapter uses and
 * applies it with a partial `doc` update to the alert's resolved physical
 * index. Nothing else on the record is touched, nothing is ever inserted (a
 * finding the main sync has not carried yet is skipped; its first projection
 * will include the case), and nothing is written back to the finding.
 * The result is size-capped per tick; a full page advances the watermark only
 * to the last case seen, so the next tick continues from there.
 */
export const NATIVE_CASE_RECONCILE_DOC_ID = 'native_case_reconcile:wazuh5_findings';
/** Findings examined per tick; a full page checkpoints and continues next tick. */
export const NATIVE_CASE_RECONCILE_PAGE = 500;
export const NATIVE_CASE_UPDATED_FIELD = 'wazuh.case.updated_at';
export const NATIVE_CASE_CREATED_FIELD = 'wazuh.case.created_at';

export interface NativeCaseReconcileOptions {
  /** Validated source pattern of the 5.0 findings family (`resolveSource().pattern`). */
  pattern: string;
  /** Re-validates the sync lease before the write; the pass aborts without writing when it is lost. */
  renewLock: () => Promise<boolean>;
  now?: Date;
}

export interface NativeCaseReconcileResult {
  status: 'ok' | 'lock_lost' | 'write_failed';
  scanned: number;
  updated: number;
  /** Findings with a changed case that the main sync has not carried yet. */
  skipped: number;
  windowFrom: string;
  windowTo: string;
  /** True when the page was full and the next tick continues from the checkpoint. */
  more: boolean;
}

interface ReconcileState {
  watermark: string;
}

async function getReconcileState(client: any, config: AlertManagerConfigType, now: Date): Promise<ReconcileState> {
  try {
    const res: any = await client.get({ index: META_INDEX, id: NATIVE_CASE_RECONCILE_DOC_ID });
    const watermark = res?.body?._source?.watermark;
    if (typeof watermark === 'string' && Number.isFinite(Date.parse(watermark))) return { watermark };
  } catch (e) {
    // Not found on first run - fall through to the initial lookback.
  }
  // First run: cases edited inside the initial lookback are reconciled once;
  // anything older was projected when the finding itself was first synced.
  const lookbackMs = config.sync.initialLookbackMinutes * 60 * 1000;
  return { watermark: new Date(now.getTime() - lookbackMs).toISOString() };
}

async function setReconcileState(client: any, watermark: string) {
  await client.index({
    index: assertManagedWriteTarget(META_INDEX),
    id: NATIVE_CASE_RECONCILE_DOC_ID,
    body: { watermark, source_family: 'wazuh5_findings', updated_at: new Date().toISOString() },
  });
}

/** Source query: findings whose native case was created or edited inside the window. */
export function nativeCaseReconcileQuery(windowFrom: string, windowTo: string): any {
  return {
    bool: {
      should: [
        { range: { [NATIVE_CASE_UPDATED_FIELD]: { gte: windowFrom, lte: windowTo } } },
        { range: { [NATIVE_CASE_CREATED_FIELD]: { gte: windowFrom, lte: windowTo } } },
      ],
      minimum_should_match: 1,
    },
  };
}

/**
 * Oldest edit first so a full page can checkpoint on the last edit seen.
 * `numeric_type: date` keeps the key in milliseconds whatever the field's
 * resolution (the adapter's `@timestamp` sort has the same guard);
 * `unmapped_type` keeps a template without the field from failing the search.
 */
export function nativeCaseReconcileSort(): any[] {
  return [
    { [NATIVE_CASE_UPDATED_FIELD]: { order: 'asc', numeric_type: 'date', missing: '_first', unmapped_type: 'date' } },
    { _doc: { order: 'asc' } },
  ];
}

function caseStamp(source: any): string | null {
  const updated = source?.wazuh?.case?.updated_at;
  const created = source?.wazuh?.case?.created_at;
  const candidates = [updated, created]
    .filter((v) => typeof v === 'string' && Number.isFinite(Date.parse(v)))
    .map((v) => new Date(v).toISOString())
    .sort();
  return candidates.length ? candidates[candidates.length - 1] : null;
}

export async function reconcileNativeCases(
  client: any,
  config: AlertManagerConfigType,
  logger: Logger,
  options: NativeCaseReconcileOptions
): Promise<NativeCaseReconcileResult> {
  const now = options.now || new Date();
  const state = await getReconcileState(client, config, now);
  const overlapMs = config.sync.overlapSeconds * 1000;
  const windowFrom = new Date(new Date(state.watermark).getTime() - overlapMs).toISOString();
  const windowTo = now.toISOString();
  const base = { scanned: 0, updated: 0, skipped: 0, windowFrom, windowTo, more: false };

  const results: any = await client.search({
    index: options.pattern,
    size: NATIVE_CASE_RECONCILE_PAGE,
    body: {
      query: nativeCaseReconcileQuery(windowFrom, windowTo),
      sort: nativeCaseReconcileSort(),
      _source: ['wazuh.case'],
    },
  });
  const hits: any[] = results?.body?.hits?.hits || [];
  const pageFull = hits.length >= NATIVE_CASE_RECONCILE_PAGE;
  // A full page checkpoints on the last edit seen (ties replay, idempotent);
  // otherwise the whole window is done.
  const lastStamp = pageFull ? caseStamp(hits[hits.length - 1]?._source) : null;
  const nextWatermark = pageFull && lastStamp ? lastStamp : windowTo;

  if (hits.length === 0) {
    await setReconcileState(client, nextWatermark);
    return { status: 'ok', ...base };
  }

  const candidates = hits.map((hit) => ({
    alertUid: alertUid(String(hit._index || ''), String(hit._id || '')),
    nativeCase: projectNativeCase5(hit._source || {}),
  }));
  const locations = await resolveAlerts(
    client,
    candidates.map((c) => c.alertUid)
  );

  // The search and the resolution above are external waits: re-validate the
  // lease before writing, exactly as the main tick does.
  if (!(await options.renewLock())) {
    logger.warn('wazuh-alert-manager sync: lost the sync lock before the native case reconciliation write, aborting');
    return { status: 'lock_lost', ...base, scanned: hits.length };
  }

  const body: any[] = [];
  let skipped = 0;
  for (const candidate of candidates) {
    const location = locations.get(candidate.alertUid);
    if (!location) {
      skipped += 1;
      continue;
    }
    body.push({ update: { _index: assertManagedWriteTarget(location.index), _id: candidate.alertUid } });
    // Partial doc update: only native_case changes, every plugin-owned field
    // and the rest of the projection stay exactly as they are.
    body.push({ doc: { native_case: candidate.nativeCase } });
  }

  let updated = 0;
  if (body.length) {
    let response: any;
    try {
      response = await client.bulk({ body, refresh: false });
    } catch (e: any) {
      logger.error(`wazuh-alert-manager sync: native case reconciliation bulk update failed: ${e.message}`);
      return { status: 'write_failed', ...base, scanned: hits.length, skipped };
    }
    const items: any[] = response?.body?.items || [];
    const failed = items.filter((item) => item?.update?.error);
    updated = items.length - failed.length;
    if (response?.body?.errors || failed.length) {
      logger.error(
        `wazuh-alert-manager sync: ${failed.length}/${items.length} native case reconciliation updates failed. First error: ${JSON.stringify(
          failed[0]?.update?.error
        )}`
      );
      // Keep the watermark: the window replays on the next tick.
      return { status: 'write_failed', ...base, scanned: hits.length, updated, skipped };
    }
  }

  await setReconcileState(client, nextWatermark);
  if (pageFull) {
    logger.warn(
      `wazuh-alert-manager sync: native case reconciliation page (${NATIVE_CASE_RECONCILE_PAGE}) full for window ${windowFrom} - ${windowTo}; continuing from ${nextWatermark} on the next tick`
    );
  }
  logger.debug(
    `wazuh-alert-manager sync: native case reconciliation scanned ${hits.length}, updated ${updated}, skipped ${skipped} (${windowFrom} - ${windowTo})`
  );
  return { status: 'ok', ...base, scanned: hits.length, updated, skipped, more: pageFull };
}
