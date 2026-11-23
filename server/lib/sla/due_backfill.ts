import { ALERTS_READ_ALIAS, META_INDEX, SLA_BANDS, SLA_DUE_BACKFILL_DOC_ID } from '../../../common/constants';
import type { SlaBand, SlaDueBackfillStatus, SlaPolicy } from '../../../common/types';
import { BAND_LEVEL_RANGES, SEVERITY_BANDS, labelsOfBand } from '../../../common/severity';
import { assertManagedWriteTarget } from '../index_namespace';
import { acquireOrRenewLease, holderId, releaseLease } from '../lease';
import { SLA_ACTIVE_STATUSES, slaBandOfSeverity, slaTargetOf } from '../reporting_fields';

/**
 * Due-date backfill (step 3.2).
 *
 * The sync upsert stamps `reporting.sla_due_at` / `reporting.assign_due_at`
 * once, at first projection, and never rewrites them (so an overlap replay
 * cannot move a due date). A policy change therefore recomputes them here,
 * explicitly: one `update_by_query` over the live alert read alias (every
 * live generation; the write alias is only the newest one) whose painless
 * script derives the band from `rule.level` (4.x) or `severity_label` (5.0)
 * exactly like common/severity.ts and writes `@timestamp` + the new targets
 * for open / in_progress alerts only. Closed alerts keep the due date they
 * had, the same way they keep their `sla_met` verdict.
 *
 * The update_by_query is submitted as a server-side task
 * (`wait_for_completion: false`) and polled through the tasks API, so the
 * run is never cut by the client's HTTP request timeout (30 s by default);
 * every poll renews the lease and records progress on the status doc. Alerts
 * an analyst or a sync replay touched during a pass are skipped by
 * `conflicts: proceed`; because the script is idempotent (noop when the due
 * fields already match) the pass is repeated, up to
 * `SLA_DUE_BACKFILL_MAX_PASSES` times, until no conflict remains; a run that
 * still has conflicts after the last pass is recorded `partial`.
 *
 * `PUT /sla/policy` (when the targets changed) and `POST /sla/backfill`
 * start it in the background. A lease on META_INDEX keeps two replicas (or a
 * PUT racing a run-now) from running it concurrently; the loser answers
 * `skipped`. Progress lives in the META_INDEX doc `sla_due_backfill`.
 */

export const SLA_DUE_BACKFILL_LEASE_ID = 'sla-due-backfill';
/** Default `requests_per_second` of the update_by_query (documents per second). */
export const SLA_DUE_BACKFILL_REQUESTS_PER_SECOND = 500;
/** Lease TTL; a crashed run frees the lease after this long (renewed on every poll). */
export const SLA_DUE_BACKFILL_LEASE_TTL_MS = 30 * 60 * 1000;
/** How often a running task is polled (and the lease renewed, progress recorded). */
export const SLA_DUE_BACKFILL_POLL_INTERVAL_MS = 2000;
/** Passes of the update_by_query over documents that conflicted during the previous pass. */
export const SLA_DUE_BACKFILL_MAX_PASSES = 3;
/** Hard cap on one run; beyond it the task is cancelled and the run recorded `failed`. */
export const SLA_DUE_BACKFILL_MAX_RUN_MS = 6 * 60 * 60 * 1000;
/** Per-bulk shard timeout of the update_by_query (not the operation's bound). */
const UPDATE_BY_QUERY_TIMEOUT = '5m';
const ISO_MILLIS_PATTERN = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
/** 4.x alerts seen with an `+0000` offset instead of `Z`. */
const ALT_TIMESTAMP_PATTERN = "yyyy-MM-dd'T'HH:mm:ss.SSSZ";

export interface SlaDueBackfillLogger {
  info?(message: string): void;
  warn?(message: string): void;
  error?(message: string): void;
  debug?(message: string): void;
}

export interface SlaDueBackfillOptions {
  /** `updated_at` of the policy document; recorded on the status doc. */
  policyVersion?: string | null;
  requestsPerSecond?: number;
  /** Lease holder identity (defaults to a fresh `holderId()`). */
  holder?: string;
  now?: () => string;
  /** Poll interval of the server-side task (tests shorten it). */
  pollIntervalMs?: number;
  /** Conflict re-passes (default `SLA_DUE_BACKFILL_MAX_PASSES`). */
  maxPasses?: number;
  /** Hard cap on the run (default `SLA_DUE_BACKFILL_MAX_RUN_MS`). */
  maxRunMs?: number;
}

/** Painless source + params of the recompute script (exported for tests). */
export function buildDueBackfillScript(policy: SlaPolicy | null | undefined): { lang: 'painless'; source: string; params: any } {
  const targetsMs: Record<SlaBand, { resolve: number; assign: number }> = {} as any;
  for (const band of SLA_BANDS) {
    const target = slaTargetOf(policy, band);
    targetsMs[band] = { resolve: target.resolveMinutes * 60000, assign: target.assignMinutes * 60000 };
  }
  // Label -> SLA band, the same alias table common/severity.ts uses (5.0 labels).
  const labelBands: Record<string, SlaBand> = {};
  for (const band of SEVERITY_BANDS) {
    const slaBand = slaBandOfSeverity(band)!;
    for (const label of labelsOfBand(band)) labelBands[label] = slaBand;
  }
  const floors = {
    critical: BAND_LEVEL_RANGES.critical!.min,
    high: BAND_LEVEL_RANGES.high!.min,
    medium: BAND_LEVEL_RANGES.medium!.min,
  };
  const source = `
    String band = null;
    def level = ctx._source.rule == null ? null : ctx._source.rule.level;
    if (level instanceof Number) {
      long l = ((Number) level).longValue();
      if (l >= params.floors.critical) { band = 'critical'; }
      else if (l >= params.floors.high) { band = 'high'; }
      else if (l >= params.floors.medium) { band = 'medium'; }
      else { band = 'low'; }
    } else if (ctx._source.severity_label != null) {
      band = params.labelBands[ctx._source.severity_label.toString().trim().toLowerCase()];
    }
    def ts = ctx._source['@timestamp'];
    if (band == null || ts == null) {
      ctx.op = 'noop';
    } else {
      long base = -1L;
      try {
        base = Instant.parse(ts.toString()).toEpochMilli();
      } catch (Exception e) {
        try {
          base = OffsetDateTime.parse(ts.toString(), DateTimeFormatter.ofPattern(params.altPattern)).toInstant().toEpochMilli();
        } catch (Exception e2) {
          base = -1L;
        }
      }
      if (base < 0L) {
        ctx.op = 'noop';
      } else {
        def target = params.targets[band];
        DateTimeFormatter out = DateTimeFormatter.ofPattern(params.outPattern);
        String due = ZonedDateTime.ofInstant(Instant.ofEpochMilli(base + target.resolve), ZoneOffset.UTC).format(out);
        String assign = ZonedDateTime.ofInstant(Instant.ofEpochMilli(base + target.assign), ZoneOffset.UTC).format(out);
        if (ctx._source.reporting == null) { ctx._source.reporting = [:]; }
        if (due.equals(ctx._source.reporting.sla_due_at) && assign.equals(ctx._source.reporting.assign_due_at)) {
          ctx.op = 'noop';
        } else {
          ctx._source.reporting.sla_due_at = due;
          ctx._source.reporting.assign_due_at = assign;
        }
      }
    }
  `;
  return {
    lang: 'painless',
    source,
    params: { targets: targetsMs, labelBands, floors, outPattern: ISO_MILLIS_PATTERN, altPattern: ALT_TIMESTAMP_PATTERN },
  };
}

/** Only open / in_progress alerts are recomputed. */
export function dueBackfillQuery(): any {
  return { bool: { filter: [{ terms: { status: [...SLA_ACTIVE_STATUSES] } }] } };
}

/**
 * Short, index-name-free description of a failure for the status doc, which
 * `GET /sla/backfill` serves to every signed-in user. The full message goes
 * to the server log only.
 */
export function sanitizeBackfillError(e: any): string {
  const statusCode = e?.meta?.statusCode || e?.statusCode;
  const name = String(e?.name || '').trim();
  if (name === 'TimeoutError') return 'request timed out';
  if (name === 'ConnectionError') return 'connection failed';
  const type = e?.meta?.body?.error?.type;
  if (typeof type === 'string' && type) return statusCode ? `${type} (HTTP ${statusCode})` : type;
  if (statusCode) return `request failed (HTTP ${statusCode})`;
  return name && name !== 'Error' ? name : 'unexpected error';
}

async function writeStatus(client: any, status: SlaDueBackfillStatus, refresh: 'wait_for' | false = 'wait_for'): Promise<void> {
  await client.index({
    index: assertManagedWriteTarget(META_INDEX),
    id: SLA_DUE_BACKFILL_DOC_ID,
    body: { document_type: 'sla_due_backfill', ...status },
    refresh,
  });
}

/**
 * The last run (or the one in progress), null when the backfill never ran. A
 * `running` document whose last heartbeat is older than the lease TTL is a
 * run whose process died: it is answered as `failed` (`stale run`) so the API
 * never reports a dead run as in progress.
 */
export async function readSlaDueBackfillStatus(
  client: any,
  now: () => string = () => new Date().toISOString()
): Promise<SlaDueBackfillStatus | null> {
  try {
    const res: any = await client.get({ index: META_INDEX, id: SLA_DUE_BACKFILL_DOC_ID });
    const source = res?.body?._source;
    if (!source) return null;
    const status: SlaDueBackfillStatus = {
      status: source.status,
      started_at: source.started_at,
      finished_at: source.finished_at ?? null,
      heartbeat_at: source.heartbeat_at ?? null,
      updated: Number(source.updated) || 0,
      failures: Number(source.failures) || 0,
      version_conflicts: Number(source.version_conflicts) || 0,
      policy_version: source.policy_version ?? null,
      error: source.error ?? null,
    };
    if (status.status === 'running') {
      const lastSeen = Date.parse(status.heartbeat_at || status.started_at || '');
      if (!Number.isFinite(lastSeen) || Date.parse(now()) - lastSeen > SLA_DUE_BACKFILL_LEASE_TTL_MS) {
        status.status = 'failed';
        status.error = 'stale run (no heartbeat since the lease expired)';
      }
    }
    return status;
  } catch (e: any) {
    if ((e?.meta?.statusCode || e?.statusCode) === 404) return null;
    throw e;
  }
}

interface PassResult {
  updated: number;
  versionConflicts: number;
  failures: number;
}

function summarise(body: any): PassResult {
  const response = body || {};
  return {
    updated: Number(response.updated) || 0,
    versionConflicts: Number(response.version_conflicts) || 0,
    failures: Array.isArray(response.failures) ? response.failures.length : 0,
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

interface PassContext {
  client: any;
  logger: SlaDueBackfillLogger | null | undefined;
  holder: string;
  now: () => string;
  pollIntervalMs: number;
  deadlineMs: number;
  status: SlaDueBackfillStatus;
  /** Documents updated by the passes before this one. */
  updatedBefore: number;
}

/**
 * One update_by_query pass. Submitted as a task and polled; a client (or a
 * test double) that answers the result inline, without a task id, is taken
 * as is.
 */
async function runPass(ctx: PassContext, request: any): Promise<PassResult> {
  const submitted: any = await ctx.client.updateByQuery({ ...request, wait_for_completion: false });
  const taskId = submitted?.body?.task;
  if (!taskId) return summarise(submitted?.body);
  for (;;) {
    await sleep(ctx.pollIntervalMs);
    const task: any = await ctx.client.tasks.get({ task_id: taskId });
    const body = task?.body || {};
    if (body.completed) {
      if (body.error) {
        const err: any = new Error(body.error.reason || body.error.type || 'update_by_query failed');
        err.meta = { body: { error: body.error } };
        throw err;
      }
      return summarise(body.response);
    }
    const renewed = await acquireOrRenewLease(ctx.client, {
      leaseId: SLA_DUE_BACKFILL_LEASE_ID,
      holder: ctx.holder,
      ttlMs: SLA_DUE_BACKFILL_LEASE_TTL_MS,
    });
    if (!renewed.acquired) {
      ctx.logger?.warn?.('wazuh-alert-manager sla: due-date backfill lease could not be renewed while a task is running');
    }
    const progress = Number(body.task?.status?.updated) || 0;
    ctx.status.updated = ctx.updatedBefore + progress;
    ctx.status.heartbeat_at = ctx.now();
    try {
      await writeStatus(ctx.client, ctx.status, false);
    } catch (e: any) {
      ctx.logger?.debug?.(`wazuh-alert-manager sla: due-date backfill progress not recorded: ${e?.message || e}`);
    }
    if (Date.now() > ctx.deadlineMs) {
      try {
        await ctx.client.tasks.cancel({ task_id: taskId });
      } catch (e: any) {
        ctx.logger?.warn?.(`wazuh-alert-manager sla: could not cancel the due-date backfill task ${taskId}: ${e?.message || e}`);
      }
      const err: any = new Error('due-date backfill exceeded its run cap');
      err.name = 'TimeoutError';
      throw err;
    }
  }
}

export interface StartedSlaDueBackfill {
  /** `running` (the lease was taken and the run started) or `skipped`. */
  status: SlaDueBackfillStatus;
  /** Resolves with the final status; never rejects. */
  completion: Promise<SlaDueBackfillStatus>;
}

/**
 * Take the lease, record the run as `running` and continue in the
 * background. Resolves as soon as the run is started (or skipped) so a route
 * can answer 202 while the task runs; `completion` settles with the final
 * status (`completed`, `partial` or `failed`) and never rejects: a failure is
 * recorded on the status doc (sanitised) and logged in full.
 */
export async function beginSlaDueBackfill(
  client: any,
  logger: SlaDueBackfillLogger | null | undefined,
  policy: SlaPolicy | null | undefined,
  options: SlaDueBackfillOptions = {}
): Promise<StartedSlaDueBackfill> {
  const now = options.now || (() => new Date().toISOString());
  const holder = options.holder || holderId();
  const policyVersion = options.policyVersion ?? null;
  const startedAt = now();
  const lease = await acquireOrRenewLease(client, { leaseId: SLA_DUE_BACKFILL_LEASE_ID, holder, ttlMs: SLA_DUE_BACKFILL_LEASE_TTL_MS });
  if (!lease.acquired) {
    const message = `due-date backfill already running elsewhere${lease.expiresAt ? ` (lease until ${lease.expiresAt})` : ''}`;
    logger?.info?.(`wazuh-alert-manager sla: ${message}`);
    const skipped: SlaDueBackfillStatus = {
      status: 'skipped',
      started_at: startedAt,
      finished_at: startedAt,
      heartbeat_at: null,
      updated: 0,
      failures: 0,
      version_conflicts: 0,
      policy_version: policyVersion,
      error: message,
    };
    return { status: skipped, completion: Promise.resolve(skipped) };
  }
  const running: SlaDueBackfillStatus = {
    status: 'running',
    started_at: startedAt,
    finished_at: null,
    heartbeat_at: startedAt,
    updated: 0,
    failures: 0,
    version_conflicts: 0,
    policy_version: policyVersion,
    error: null,
  };
  const maxPasses = Math.max(1, options.maxPasses ?? SLA_DUE_BACKFILL_MAX_PASSES);
  const ctx: PassContext = {
    client,
    logger,
    holder,
    now,
    pollIntervalMs: options.pollIntervalMs ?? SLA_DUE_BACKFILL_POLL_INTERVAL_MS,
    deadlineMs: Date.now() + (options.maxRunMs ?? SLA_DUE_BACKFILL_MAX_RUN_MS),
    status: running,
    updatedBefore: 0,
  };
  const request = {
    index: assertManagedWriteTarget(ALERTS_READ_ALIAS),
    conflicts: 'proceed',
    refresh: true,
    requests_per_second: options.requestsPerSecond ?? SLA_DUE_BACKFILL_REQUESTS_PER_SECOND,
    timeout: UPDATE_BY_QUERY_TIMEOUT,
    body: { query: dueBackfillQuery(), script: buildDueBackfillScript(policy) },
  };

  // The run itself; `started` below resolves before it to let a route answer early.
  const work = async (): Promise<SlaDueBackfillStatus> => {
    try {
      let updated = 0;
      let failures = 0;
      let versionConflicts = 0;
      for (let pass = 1; pass <= maxPasses; pass += 1) {
        ctx.updatedBefore = updated;
        const result = await runPass(ctx, request);
        updated += result.updated;
        failures = result.failures;
        versionConflicts = result.versionConflicts;
        if (failures || !versionConflicts) break;
        logger?.info?.(
          `wazuh-alert-manager sla: due-date backfill pass ${pass} left ${versionConflicts} conflicting document(s)${pass < maxPasses ? ', repeating' : ''}`
        );
      }
      const status: SlaDueBackfillStatus['status'] = failures ? 'failed' : versionConflicts ? 'partial' : 'completed';
      const finished: SlaDueBackfillStatus = {
        ...running,
        status,
        finished_at: now(),
        heartbeat_at: null,
        updated,
        failures,
        version_conflicts: versionConflicts,
        error: failures
          ? `${failures} document(s) failed to update`
          : versionConflicts
          ? `${versionConflicts} document(s) changed concurrently in every pass; run the backfill again`
          : null,
      };
      await writeStatus(client, finished);
      logger?.info?.(
        `wazuh-alert-manager sla: due-date backfill ${finished.status}: ${finished.updated} updated, ${finished.failures} failure(s), ${finished.version_conflicts} conflict(s)`
      );
      return finished;
    } catch (e: any) {
      const failed: SlaDueBackfillStatus = {
        ...running,
        status: 'failed',
        finished_at: now(),
        heartbeat_at: null,
        updated: ctx.status.updated,
        error: sanitizeBackfillError(e),
      };
      logger?.error?.(`wazuh-alert-manager sla: due-date backfill failed: ${e?.message || String(e)}`);
      try {
        await writeStatus(client, failed);
      } catch (writeError: any) {
        logger?.warn?.(`wazuh-alert-manager sla: could not record the backfill failure: ${writeError?.message || writeError}`);
      }
      return failed;
    } finally {
      await releaseLease(client, { leaseId: SLA_DUE_BACKFILL_LEASE_ID, holder });
    }
  };

  let started: () => void = () => undefined;
  const gate = new Promise<void>((resolve) => {
    started = resolve;
  });
  const completion = gate.then(work);
  try {
    await writeStatus(client, running);
  } catch (e: any) {
    // The run goes on; the final write (or the next heartbeat) records it.
    logger?.warn?.(`wazuh-alert-manager sla: could not record the backfill start: ${e?.message || e}`);
  }
  started();
  return { status: running, completion };
}

/**
 * Recompute the due timestamps of every open / in_progress alert under
 * `policy` and wait for the outcome. Never throws: a failure is recorded on
 * the status doc (and logged) and returned as `status: 'failed'`; a run that
 * could not take the lease answers `status: 'skipped'` without touching
 * anything.
 */
export async function runSlaDueBackfill(
  client: any,
  logger: SlaDueBackfillLogger | null | undefined,
  policy: SlaPolicy | null | undefined,
  options: SlaDueBackfillOptions = {}
): Promise<SlaDueBackfillStatus> {
  const started = await beginSlaDueBackfill(client, logger, policy, options);
  return started.completion;
}

/** Fire-and-forget wrapper for `PUT /sla/policy`: never rejects, never blocks the response. */
export function scheduleSlaDueBackfill(
  client: any,
  logger: SlaDueBackfillLogger | null | undefined,
  policy: SlaPolicy | null | undefined,
  options: SlaDueBackfillOptions = {}
): void {
  beginSlaDueBackfill(client, logger, policy, options).catch((e: any) => {
    logger?.error?.(`wazuh-alert-manager sla: scheduled due-date backfill crashed: ${e?.message || e}`);
  });
}
