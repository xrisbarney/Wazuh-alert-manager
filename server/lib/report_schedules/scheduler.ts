import { Logger } from '../../../../../src/core/server';
import { META_INDEX, REPORT_RUN_DOC_PREFIX, REPORT_RUN_MAX_ATTEMPTS, REPORT_SCHEDULER_LEASE_ID } from '../../../common';
import type { ReportRun, ReportRunSummary, ReportSchedule } from '../../../common';
import type { AlertManagerConfigType } from '../../config';
import { appendActivity } from '../activity';
import { assertManagedWriteTarget } from '../index_namespace';
import { acquireOrRenewLease, holderId, releaseLease } from '../lease';
import type { NotificationEmitter } from '../notifications/emitters';
import { collectReportSummary } from './metrics';
import { renderReportSummaryMarkdown, TRUNCATION_NOTE, truncateMarkdown } from './render';
import { loadReportSchedules } from './settings';

/**
 * Scheduled summaries (step 5.4).
 *
 * Slots are computed in UTC from the schedule's `hourUtc` (and `dayOfWeek`
 * for weekly schedules), so there is no DST. A schedule is "due" for the
 * latest slot at or before now; the run document `report_run:<scheduleId>`
 * stores the slot its Markdown covers and a tick skips a schedule whose
 * stored slot equals the due slot (or whose due slot already failed
 * `REPORT_RUN_MAX_ATTEMPTS` times), so a slot is rendered once however many
 * ticks (or replicas, through the `report_scheduler` lease) see it. A slot
 * missed while the dashboard was down is rendered at the next tick (the
 * latest one only; older missed slots are not back-filled).
 */

const DAY_MS = 24 * 60 * 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;
export const SCHEDULER_ACTOR = 'scheduler';
export const REPORT_RUN_DOCUMENT_TYPE = 'report_run';

export function reportRunDocId(scheduleId: string): string {
  return `${REPORT_RUN_DOC_PREFIX}${scheduleId}`;
}

function startOfUtcDay(ms: number): number {
  return Math.floor(ms / DAY_MS) * DAY_MS;
}

type SlotSchedule = Pick<ReportSchedule, 'cadence' | 'dayOfWeek' | 'hourUtc'>;

/** The latest slot at or before `now` (ISO). */
export function dueSlot(schedule: SlotSchedule, now: Date): string {
  const nowMs = now.getTime();
  let slot = startOfUtcDay(nowMs) + schedule.hourUtc * HOUR_MS;
  if (schedule.cadence === 'weekly') {
    const today = new Date(startOfUtcDay(nowMs)).getUTCDay();
    const back = (today - schedule.dayOfWeek + 7) % 7;
    slot -= back * DAY_MS;
    if (slot > nowMs) slot -= 7 * DAY_MS;
  } else if (slot > nowMs) {
    slot -= DAY_MS;
  }
  return new Date(slot).toISOString();
}

/** The earliest slot strictly after `now` (ISO). */
export function nextSlot(schedule: SlotSchedule, now: Date): string {
  const due = Date.parse(dueSlot(schedule, now));
  return new Date(due + (schedule.cadence === 'weekly' ? 7 : 1) * DAY_MS).toISOString();
}

/** The range a slot covers: `rangeDays` days ending at the slot. */
export function slotRange(schedule: Pick<ReportSchedule, 'rangeDays'>, slot: string): { from: string; to: string } {
  const to = Date.parse(slot);
  return { from: new Date(to - schedule.rangeDays * DAY_MS).toISOString(), to: new Date(to).toISOString() };
}

export function summariseRun(run: ReportRun): ReportRunSummary {
  const { markdown, ...rest } = run;
  const body = markdown || '';
  return { ...rest, markdown_bytes: Buffer.byteLength(body, 'utf8'), truncated: body.endsWith(TRUNCATION_NOTE) };
}

function isNotFound(error: any): boolean {
  return error?.meta?.statusCode === 404 || error?.statusCode === 404;
}

function runFromSource(source: any, scheduleId: string): ReportRun | null {
  if (!source || source.document_type !== REPORT_RUN_DOCUMENT_TYPE) return null;
  const attempts = typeof source.attempts === 'number' && Number.isFinite(source.attempts) ? Math.max(0, Math.floor(source.attempts)) : 0;
  return {
    schedule_id: String(source.schedule_id ?? scheduleId),
    slot: String(source.slot ?? ''),
    generated_at: String(source.generated_at ?? ''),
    range_from: String(source.range_from ?? ''),
    range_to: String(source.range_to ?? ''),
    triggered_by: String(source.triggered_by ?? SCHEDULER_ACTOR),
    markdown: typeof source.markdown === 'string' ? source.markdown : '',
    error: typeof source.error === 'string' && source.error ? source.error : null,
    failed_slot: typeof source.failed_slot === 'string' && source.failed_slot ? source.failed_slot : null,
    failed_at: typeof source.failed_at === 'string' && source.failed_at ? source.failed_at : null,
    attempts,
  };
}

/** True when the scheduler should not render `slot` again: already stored, or failed `REPORT_RUN_MAX_ATTEMPTS` times. */
export function slotCovered(existing: ReportRun | null, slot: string): boolean {
  if (!existing) return false;
  if (existing.slot === slot) return true;
  return existing.failed_slot === slot && existing.attempts >= REPORT_RUN_MAX_ATTEMPTS;
}

export async function readReportRun(client: any, scheduleId: string): Promise<ReportRun | null> {
  try {
    const res: any = await client.get({ index: META_INDEX, id: reportRunDocId(scheduleId) });
    return runFromSource(res?.body?._source, scheduleId);
  } catch (e: any) {
    if (isNotFound(e)) return null;
    throw e;
  }
}

/** Last runs for several schedules in one `mget`; ids without a run are absent. */
export async function readReportRuns(client: any, scheduleIds: string[]): Promise<Record<string, ReportRun>> {
  const out: Record<string, ReportRun> = {};
  if (!scheduleIds.length) return out;
  const res: any = await client.mget({ index: META_INDEX, body: { ids: scheduleIds.map(reportRunDocId) } });
  for (const doc of res?.body?.docs || []) {
    if (!doc?.found) continue;
    const id = String(doc._id ?? '').startsWith(REPORT_RUN_DOC_PREFIX) ? String(doc._id).slice(REPORT_RUN_DOC_PREFIX.length) : '';
    const run = runFromSource(doc._source, id);
    if (run && scheduleIds.includes(run.schedule_id)) out[run.schedule_id] = run;
  }
  return out;
}

export interface RunScheduleOptions {
  /** The slot the run covers; defaults to the due slot at `now`. */
  slot?: string;
  now?: Date;
  /** Recorded as `triggered_by`; the scheduler uses `scheduler`, "Run now" the admin's name. */
  actor: string;
  logger?: Logger;
  /** Test seam: replaces `collectReportSummary`. */
  collect?: typeof collectReportSummary;
  /**
   * Notification emitter (step 1.3): after a successful render the run goes
   * out as `report.scheduled` to the schedule's `channelIds` (deterministic
   * outbox id per slot and channel, so "Run now" on a delivered slot is a
   * silent duplicate). Absent = nothing is delivered.
   */
  emitter?: Pick<NotificationEmitter, 'emitReportEvent'> | null;
}

/**
 * Render one schedule for a slot and store the result as
 * `report_run:<scheduleId>`. A success replaces the document (and clears any
 * recorded failure). A rendering failure never discards the last successful
 * Markdown: it is merged into the document as `error` / `failed_slot` /
 * `failed_at` / `attempts` (doc-merge update, upsert when no run exists), so
 * the download keeps serving the previous report and the scheduler retries
 * the slot up to `REPORT_RUN_MAX_ATTEMPTS` times; "Run now" re-renders on
 * demand. Never throws for a render failure; a failure to store the run does
 * throw.
 */
export async function runSchedule(client: any, schedule: ReportSchedule, options: RunScheduleOptions): Promise<ReportRun> {
  const now = options.now || new Date();
  const slot = options.slot || dueSlot(schedule, now);
  const range = slotRange(schedule, slot);
  const collect = options.collect || collectReportSummary;
  let markdown = '';
  let error: string | null = null;
  try {
    const data = await collect(client, range);
    markdown = truncateMarkdown(
      renderReportSummaryMarkdown(data, { schedule, from: range.from, to: range.to, generatedAt: now.toISOString() })
    ).markdown;
  } catch (e: any) {
    error = String(e?.message || e).slice(0, 2000);
    options.logger?.warn(`wazuh-alert-manager report scheduler: schedule "${schedule.id}" failed for slot ${slot}: ${error}`);
  }
  const docId = reportRunDocId(schedule.id);
  const index = assertManagedWriteTarget(META_INDEX);
  let run: ReportRun;
  if (error === null) {
    run = {
      schedule_id: schedule.id,
      slot,
      generated_at: now.toISOString(),
      range_from: range.from,
      range_to: range.to,
      triggered_by: options.actor,
      markdown,
      error: null,
      failed_slot: null,
      failed_at: null,
      attempts: 0,
    };
    await client.index({ index, id: docId, body: { document_type: REPORT_RUN_DOCUMENT_TYPE, ...run }, refresh: 'wait_for' });
  } else {
    let previous: ReportRun | null = null;
    try {
      previous = await readReportRun(client, schedule.id);
    } catch (e: any) {
      options.logger?.warn(`wazuh-alert-manager report scheduler: could not read the last run of "${schedule.id}" before recording a failure: ${e?.message || e}`);
    }
    const failure = {
      error,
      failed_slot: slot,
      failed_at: now.toISOString(),
      attempts: previous && previous.failed_slot === slot ? previous.attempts + 1 : 1,
    };
    const base: ReportRun = previous || {
      schedule_id: schedule.id,
      slot: '',
      generated_at: '',
      range_from: '',
      range_to: '',
      triggered_by: options.actor,
      markdown: '',
      error: null,
      failed_slot: null,
      failed_at: null,
      attempts: 0,
    };
    run = { ...base, ...failure };
    await client.update({
      index,
      id: docId,
      body: {
        doc: { document_type: REPORT_RUN_DOCUMENT_TYPE, schedule_id: schedule.id, ...failure },
        doc_as_upsert: true,
      },
      refresh: 'wait_for',
    });
  }
  try {
    await appendActivity(client, {
      targetType: 'system',
      targetId: docId,
      user: options.actor,
      action: error ? 'report_schedule_failed' : 'report_schedule_run',
      to: slot,
      source: options.actor === SCHEDULER_ACTOR ? 'scheduler' : 'user',
    });
  } catch (e: any) {
    options.logger?.warn(`wazuh-alert-manager report scheduler: audit write failed for "${schedule.id}": ${e?.message || e}`);
  }
  // Delivery (step 1.3): only a successful render is sent; the emitter
  // validates the channel ids, swallows every failure and logs it.
  if (error === null && options.emitter && schedule.channelIds?.length) {
    await options.emitter.emitReportEvent(schedule, run, { now });
  }
  return run;
}

export interface TickOptions {
  holder: string;
  ttlMs: number;
  now?: Date;
  logger?: Logger;
  collect?: typeof collectReportSummary;
  /** Notification emitter (step 1.3), handed to every `runSchedule` of the tick. */
  emitter?: Pick<NotificationEmitter, 'emitReportEvent'> | null;
}

export interface TickResult {
  acquired: boolean;
  /** Schedule ids rendered this tick. */
  ran: string[];
  /** Schedule ids whose due slot was already stored, or failed `REPORT_RUN_MAX_ATTEMPTS` times. */
  skipped: string[];
}

/**
 * One scheduler pass: lease, read schedules, render every due slot not yet
 * covered. Each schedule is handled inside its own try/catch so one bad entry
 * or one failing write never stops the others.
 */
export async function tickReportScheduler(client: any, options: TickOptions): Promise<TickResult> {
  const { holder, ttlMs, logger } = options;
  const now = options.now || new Date();
  const lease = await acquireOrRenewLease(client, { leaseId: REPORT_SCHEDULER_LEASE_ID, holder, ttlMs, now: now.getTime(), logger });
  if (!lease.acquired) return { acquired: false, ran: [], skipped: [] };
  const result: TickResult = { acquired: true, ran: [], skipped: [] };
  const schedules = await loadReportSchedules(client, logger);
  for (const schedule of schedules) {
    if (!schedule.enabled) continue;
    try {
      const slot = dueSlot(schedule, now);
      const existing = await readReportRun(client, schedule.id);
      if (slotCovered(existing, slot)) {
        result.skipped.push(schedule.id);
        continue;
      }
      await runSchedule(client, schedule, { slot, now, actor: SCHEDULER_ACTOR, logger, collect: options.collect, emitter: options.emitter });
      result.ran.push(schedule.id);
    } catch (e: any) {
      logger?.error(`wazuh-alert-manager report scheduler: schedule "${schedule.id}" skipped this tick: ${e?.message || e}`);
    }
  }
  return result;
}

/**
 * Background loop next to the sync job: one tick every
 * `reports.scheduler.tickSeconds`, overlapping ticks prevented, lease
 * released on stop. Returns the stop function.
 */
export function startReportScheduler(
  client: any,
  config: AlertManagerConfigType,
  logger: Logger,
  options: { emitter?: Pick<NotificationEmitter, 'emitReportEvent'> | null } = {}
): () => void {
  const tickSeconds = config.reports?.scheduler?.tickSeconds ?? 60;
  const emitter = options.emitter ?? null;
  const ttlMs = Math.max(tickSeconds * 3, 120) * 1000;
  const holder = holderId();
  let stopped = false;
  let running = false;
  let timer: ReturnType<typeof setTimeout> | null = null;

  const schedule = () => {
    if (!stopped) timer = setTimeout(tick, tickSeconds * 1000);
  };

  const tick = async () => {
    if (stopped || running) return;
    running = true;
    try {
      const result = await tickReportScheduler(client, { holder, ttlMs, logger, emitter });
      if (result.ran.length) logger.info(`wazuh-alert-manager report scheduler: rendered ${result.ran.join(', ')}`);
    } catch (e: any) {
      logger.error(`wazuh-alert-manager report scheduler: unexpected error: ${e?.message || e}`);
    } finally {
      running = false;
      schedule();
    }
  };

  schedule();
  return () => {
    stopped = true;
    if (timer) clearTimeout(timer);
    releaseLease(client, { leaseId: REPORT_SCHEDULER_LEASE_ID, holder, logger }).catch(() => {});
  };
}
