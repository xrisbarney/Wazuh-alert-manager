import {
  REPORT_SCHEDULES_DOC_ID,
  REPORT_SCHEDULES_MAX,
  REPORT_SCHEDULE_CADENCES,
  REPORT_SCHEDULE_MAX_CHANNELS,
  REPORT_SCHEDULE_MAX_RANGE_DAYS,
} from '../../../common/constants';
import type { ReportSchedule, ReportScheduleCadence } from '../../../common/types';
import { defineSettingsDoc, typedError } from '../plugin_settings';

/**
 * Scheduled summaries settings document (`report_schedules` in META_INDEX,
 * step 5.4). No secrets. `channelIds` are stored and validated as strings
 * only: delivery through notification channels is wired by phase 1.
 */

export interface ReportSchedulesDoc {
  schedules: ReportSchedule[];
}

export const REPORT_SCHEDULE_ID = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const MAX_NAME = 120;
const MAX_CHANNEL_ID = 128;
const CADENCES = new Set<string>(REPORT_SCHEDULE_CADENCES);

function bad(message: string): never {
  throw typedError(message, 400);
}

function integerIn(value: unknown, min: number, max: number): number | null {
  const n = typeof value === 'string' && /^-?\d+$/.test(value.trim()) ? Number(value) : value;
  if (typeof n !== 'number' || !Number.isInteger(n) || n < min || n > max) return null;
  return n;
}

function cleanChannelIds(raw: unknown, label: string): string[] {
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) bad(`${label}: channelIds must be a list of strings.`);
  const out: string[] = [];
  for (const item of raw) {
    if (typeof item !== 'string') bad(`${label}: channelIds must be a list of strings.`);
    const id = item.trim();
    if (!id) continue;
    if (id.length > MAX_CHANNEL_ID) bad(`${label}: a channel id must be at most ${MAX_CHANNEL_ID} characters.`);
    if (/[\r\n\0]/.test(id)) bad(`${label}: a channel id must be a single line.`);
    if (!out.includes(id)) out.push(id);
  }
  if (out.length > REPORT_SCHEDULE_MAX_CHANNELS) bad(`${label}: at most ${REPORT_SCHEDULE_MAX_CHANNELS} channels per schedule.`);
  return out;
}

export function normaliseReportSchedule(raw: any, index: number): ReportSchedule {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) bad(`schedules[${index}] must be an object.`);
  const id = typeof raw.id === 'string' ? raw.id : '';
  if (!REPORT_SCHEDULE_ID.test(id)) bad(`schedules[${index}]: id must be 1-64 lower-case letters, digits, "-" or "_".`);
  const label = `Schedule "${id}"`;
  const name = typeof raw.name === 'string' ? raw.name.trim() : '';
  if (!name) bad(`${label}: name is required.`);
  if (name.length > MAX_NAME) bad(`${label}: name must be at most ${MAX_NAME} characters.`);
  if (/[\r\n\0]/.test(name)) bad(`${label}: name must be a single line.`);
  const cadence = typeof raw.cadence === 'string' ? raw.cadence : '';
  if (!CADENCES.has(cadence)) bad(`${label}: cadence must be one of ${REPORT_SCHEDULE_CADENCES.join(', ')}.`);
  const hourUtc = integerIn(raw.hourUtc, 0, 23);
  if (hourUtc === null) bad(`${label}: hourUtc must be an integer between 0 and 23.`);
  let dayOfWeek = 1;
  if (cadence === 'weekly') {
    const day = integerIn(raw.dayOfWeek, 0, 6);
    if (day === null) bad(`${label}: dayOfWeek must be an integer between 0 (Sunday) and 6 (Saturday) for a weekly schedule.`);
    dayOfWeek = day;
  } else if (raw.dayOfWeek !== undefined && raw.dayOfWeek !== null) {
    // Kept when valid so switching a schedule back to weekly restores the day.
    dayOfWeek = integerIn(raw.dayOfWeek, 0, 6) ?? 1;
  }
  const rangeDays = integerIn(raw.rangeDays, 1, REPORT_SCHEDULE_MAX_RANGE_DAYS);
  if (rangeDays === null) bad(`${label}: rangeDays must be an integer between 1 and ${REPORT_SCHEDULE_MAX_RANGE_DAYS}.`);
  if (raw.enabled !== undefined && typeof raw.enabled !== 'boolean') bad(`${label}: enabled must be a boolean.`);
  return {
    id,
    name,
    cadence: cadence as ReportScheduleCadence,
    dayOfWeek,
    hourUtc: hourUtc as number,
    rangeDays: rangeDays as number,
    channelIds: cleanChannelIds(raw.channelIds, label),
    enabled: raw.enabled === undefined ? true : raw.enabled,
  };
}

/** Validate and normalise the merged document. */
export function normaliseReportSchedules(doc: ReportSchedulesDoc): ReportSchedulesDoc {
  const list = Array.isArray(doc?.schedules) ? doc.schedules : [];
  if (list.length > REPORT_SCHEDULES_MAX) bad(`At most ${REPORT_SCHEDULES_MAX} report schedules can be configured.`);
  const seen = new Set<string>();
  const schedules = list.map((raw, index) => {
    const entry = normaliseReportSchedule(raw, index);
    if (seen.has(entry.id)) bad(`Schedule id "${entry.id}" is used more than once.`);
    seen.add(entry.id);
    return entry;
  });
  return { schedules };
}

export const reportSchedulesSettings = defineSettingsDoc<ReportSchedulesDoc>({
  docId: REPORT_SCHEDULES_DOC_ID,
  defaults: { schedules: [] },
  validate: normaliseReportSchedules,
});

type LoadLogger = { debug(message: string): void; warn?(message: string): void };

function warn(logger: LoadLogger | undefined, message: string): void {
  if (logger?.warn) logger.warn(message);
  else logger?.debug(message);
}

/**
 * The stored schedules, each re-validated through `normaliseReportSchedule`.
 * Never throws: a missing document is the empty list, an entry that no
 * longer validates (hand-edited document, older writer) is dropped with a
 * warning so the others still run, and any other read failure is logged
 * (when a logger is given) and also yields the empty list so a scheduler
 * tick still completes.
 */
export async function loadReportSchedules(client: any, logger?: LoadLogger): Promise<ReportSchedule[]> {
  let stored: unknown[];
  try {
    const doc = await reportSchedulesSettings.read(client);
    stored = Array.isArray(doc.schedules) ? doc.schedules : [];
  } catch (e: any) {
    warn(logger, `wazuh-alert-manager report scheduler: could not read ${REPORT_SCHEDULES_DOC_ID}, skipping this tick: ${e?.message || String(e)}`);
    return [];
  }
  const schedules: ReportSchedule[] = [];
  const seen = new Set<string>();
  stored.forEach((raw, index) => {
    try {
      const entry = normaliseReportSchedule(raw, index);
      if (seen.has(entry.id)) throw new Error(`Schedule id "${entry.id}" is used more than once.`);
      seen.add(entry.id);
      schedules.push(entry);
    } catch (e: any) {
      warn(logger, `wazuh-alert-manager report scheduler: ignoring invalid stored schedule at ${REPORT_SCHEDULES_DOC_ID}.schedules[${index}]: ${e?.message || String(e)}`);
    }
  });
  return schedules;
}
