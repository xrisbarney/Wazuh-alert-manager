import { randomBytes } from 'crypto';
import { schema } from '@osd/config-schema';
import { IRouter } from '../../../../src/core/server';
import {
  API_ROOT,
  META_INDEX,
  REPORT_EXPORT_FORMATS,
  REPORT_SCHEDULES_DOC_ID,
  REPORT_SCHEDULES_MAX,
  REPORT_SCHEDULE_CADENCES,
  REPORT_SCHEDULE_MAX_CHANNELS,
  REPORT_SCHEDULE_MAX_RANGE_DAYS,
} from '../../common';
import type { ReportExportFormat, ReportRunSummary, ReportSchedule, ReportSchedulesResponse } from '../../common';
import { appendActivity } from '../lib/activity';
import { requirePluginAdmin } from '../lib/authorization';
import { downloadResponse } from '../lib/http_download';
import { trustedIdentity } from '../lib/identity';
import { assertManagedWriteTarget } from '../lib/index_namespace';
import { getNotificationEmitter } from '../lib/notifications/emitters';
import { collectReportMetrics, collectReportSummary } from '../lib/report_schedules/metrics';
import { renderReportSummary, reportExportContentType, reportExportFilename } from '../lib/report_schedules/render';
import { nextSlot, readReportRun, readReportRuns, reportRunDocId, runSchedule, summariseRun } from '../lib/report_schedules/scheduler';
import { REPORT_SCHEDULE_ID, reportSchedulesSettings } from '../lib/report_schedules/settings';

/**
 * PUT body: the whole schedule list. Shape only; `normaliseReportSchedules`
 * (run inside the settings doc write) does the semantic checks (weekly day,
 * bounds, duplicate ids) and answers 400.
 */
const scheduleSchema = schema.object(
  {
    id: schema.string({ minLength: 1, maxLength: 64 }),
    name: schema.string({ minLength: 1, maxLength: 120 }),
    cadence: schema.oneOf(REPORT_SCHEDULE_CADENCES.map((cadence) => schema.literal(cadence)) as any),
    dayOfWeek: schema.maybe(schema.number()),
    hourUtc: schema.number(),
    rangeDays: schema.number({ min: 1, max: REPORT_SCHEDULE_MAX_RANGE_DAYS }),
    channelIds: schema.maybe(schema.arrayOf(schema.string({ maxLength: 128 }), { maxSize: REPORT_SCHEDULE_MAX_CHANNELS })),
    enabled: schema.boolean({ defaultValue: true }),
  },
  { unknowns: 'forbid' }
);

const scheduleIdParams = schema.object({ id: schema.string({ minLength: 1, maxLength: 64 }) });

/**
 * Query of `GET /reports/export` (step 10.3): the same window as the
 * metrics route plus the format; `inline` / `print` (HTML only) accept `1`
 * or `true` and show the document in a tab instead of saving it.
 */
export const reportExportQuerySchema = schema.object({
  from: schema.string(),
  to: schema.string(),
  format: schema.oneOf(REPORT_EXPORT_FORMATS.map((format) => schema.literal(format)) as any, { defaultValue: 'html' }),
  inline: schema.maybe(schema.string({ maxLength: 8 })),
  print: schema.maybe(schema.string({ maxLength: 8 })),
});

function isTruthyFlag(value: unknown): boolean {
  return value === '1' || value === 'true' || value === true;
}

/** CSP of the HTML export shown in a tab: inline styles only, scripts solely by nonce (the print trigger). */
export function reportExportCsp(nonce: string): string {
  return `default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}'; base-uri 'none'; form-action 'none'`;
}

/** Title of an ad-hoc export; the intro replaces the schedule cadence sentence of the Markdown summary. */
export const REPORT_EXPORT_TITLE = 'SOC report';
export const REPORT_EXPORT_INTRO = 'SOC report over the alerts and cases of the selected window';

function failure(response: any, e: any) {
  const statusCode = e?.statusCode || e?.meta?.statusCode || 500;
  if (statusCode === 400) return response.badRequest({ body: { message: e.message } });
  if (statusCode === 403) return response.forbidden({ body: { message: e.message } });
  if (statusCode === 404) return response.notFound({ body: { message: e.message } });
  return response.customError({ statusCode, body: { message: e.message } });
}

function notFound(id: string): never {
  throw Object.assign(new Error(`Report schedule "${id}" was not found.`), { statusCode: 404 });
}

function validScheduleId(id: string): string {
  if (!REPORT_SCHEDULE_ID.test(id)) notFound(id);
  return id;
}

async function schedulesBody(client: any, masked: any, now: Date): Promise<ReportSchedulesResponse> {
  const schedules: ReportSchedule[] = Array.isArray(masked.schedules) ? masked.schedules : [];
  const runs = await readReportRuns(client, schedules.map((s) => s.id));
  const lastRuns: Record<string, ReportRunSummary> = {};
  for (const id of Object.keys(runs)) lastRuns[id] = summariseRun(runs[id]);
  const nextSlots: Record<string, string> = {};
  for (const schedule of schedules) nextSlots[schedule.id] = nextSlot(schedule, now);
  return { schedules, lastRuns, nextSlots, updated_at: masked.updated_at, updated_by: masked.updated_by };
}

/**
 * Remove `report_run:<id>` for every schedule id present before a PUT and
 * absent after it (deleted or renamed), so no orphaned report stays
 * readable and a re-created id does not inherit a stale run. A missing run
 * doc is fine; any other delete failure is reported to the caller.
 */
export async function deleteOrphanedRuns(client: any, before: ReportSchedule[], after: ReportSchedule[]): Promise<string[]> {
  const kept = new Set(after.map((s) => s.id));
  const removed = before.map((s) => s.id).filter((id) => REPORT_SCHEDULE_ID.test(id) && !kept.has(id));
  for (const id of removed) {
    try {
      await client.delete({ index: assertManagedWriteTarget(META_INDEX), id: reportRunDocId(id), refresh: 'wait_for' });
    } catch (e: any) {
      if (e?.meta?.statusCode === 404 || e?.statusCode === 404) continue;
      throw e;
    }
  }
  return removed;
}

/** The stored schedule with this id, or a 404. Also guards the open last-run routes against ids no schedule owns. */
async function findSchedule(client: any, id: string): Promise<ReportSchedule> {
  const doc = await reportSchedulesSettings.read(client);
  const schedule = (doc.schedules || []).find((s: ReportSchedule) => s.id === id);
  if (!schedule) notFound(id);
  return schedule as ReportSchedule;
}

export function reportRunFilename(scheduleId: string, slot: string): string {
  const day = /^\d{4}-\d{2}-\d{2}/.exec(slot)?.[0] || 'latest';
  return `wam-report-${scheduleId}-${day}.md`;
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
        return response.ok({
          body: await collectReportMetrics(client, { from, to }, (context as any).wazuhAlertManager?.logger || console),
        });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );

  // Ad-hoc export of the Reporting page (step 10.3): read-only, the caller's
  // client, the same window as the metrics route. HTML is served inline
  // (with the print trigger) for the browser's Save as PDF, otherwise every
  // format is an attachment.
  router.get(
    {
      path: `${API_ROOT}/reports/export`,
      validate: { query: reportExportQuerySchema },
    },
    async (context, request, response) => {
      const q = request.query as any;
      const format: ReportExportFormat = q.format;
      const inline = format === 'html' && isTruthyFlag(q.inline);
      // The print trigger only makes sense for the document shown in a tab; a
      // saved file must never print itself when opened later.
      const print = inline && isTruthyFlag(q.print);
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const now = new Date();
        const identity = await trustedIdentity(context, request);
        const data = await collectReportSummary(client, { from: q.from, to: q.to }, (context as any).wazuhAlertManager?.logger || console);
        // OSD core adds no CSP to API responses and the HTML export is a
        // top-level document on the dashboard origin: a per-response nonce
        // lets only our own print script run, whatever the escaping missed.
        const nonce = randomBytes(16).toString('base64');
        const body = renderReportSummary(data, format, {
          schedule: { name: REPORT_EXPORT_TITLE, cadence: 'daily', rangeDays: 1 },
          intro: REPORT_EXPORT_INTRO,
          from: q.from,
          to: q.to,
          generatedAt: now.toISOString(),
          generatedBy: identity.source === 'security_plugin' ? identity.name : undefined,
          print,
          nonce,
        });
        const contentType = reportExportContentType(format);
        const filename = reportExportFilename(format, q.from, q.to, now);
        const headers = { 'x-content-type-options': 'nosniff', 'content-security-policy': format === 'html' ? reportExportCsp(nonce) : "default-src 'none'" };
        if (inline) {
          return response.ok({
            headers: {
              ...headers,
              'content-type': contentType,
              'content-disposition': `inline; filename="${filename}"`,
              'cache-control': 'no-store',
              'referrer-policy': 'no-referrer',
            },
            body,
          });
        }
        return downloadResponse(response, { filename, contentType, headers, body });
      } catch (e: any) {
        return failure(response, e);
      }
    }
  );

  // Scheduled summaries (step 5.4). Reading and writing the schedule list is
  // an administrator action; a stored run is readable by any signed-in user.
  router.get({ path: `${API_ROOT}/reports/schedules`, validate: false }, async (context, request, response) => {
    try {
      await requirePluginAdmin(context, request);
      const client = context.core.opensearch.client.asCurrentUser;
      const masked = await reportSchedulesSettings.read(client);
      return response.ok({ body: await schedulesBody(client, masked, new Date()) });
    } catch (e: any) {
      return failure(response, e);
    }
  });

  router.put(
    {
      path: `${API_ROOT}/reports/schedules`,
      validate: {
        body: schema.object({ schedules: schema.arrayOf(scheduleSchema, { maxSize: REPORT_SCHEDULES_MAX }) }),
      },
    },
    async (context, request, response) => {
      try {
        const identity = await requirePluginAdmin(context, request);
        const client = context.core.opensearch.client.asCurrentUser;
        const { schedules } = request.body as any;
        const before = await reportSchedulesSettings.read(client);
        const masked = await reportSchedulesSettings.write(client, { schedules }, { actor: identity.name });
        await appendActivity(client, {
          targetType: 'system',
          targetId: REPORT_SCHEDULES_DOC_ID,
          user: identity.name,
          action: 'report_schedules_updated',
          to: String((masked.schedules || []).length),
        });
        await deleteOrphanedRuns(client, before.schedules || [], masked.schedules || []);
        return response.ok({ body: await schedulesBody(client, masked, new Date()) });
      } catch (e: any) {
        return failure(response, e);
      }
    }
  );

  router.get(
    { path: `${API_ROOT}/reports/schedules/{id}/last-run`, validate: { params: scheduleIdParams } },
    async (context, request, response) => {
      try {
        const id = validScheduleId((request.params as any).id);
        const client = context.core.opensearch.client.asCurrentUser;
        await findSchedule(client, id);
        const run = await readReportRun(client, id);
        return response.ok({ body: { run: run ? summariseRun(run) : null } });
      } catch (e: any) {
        return failure(response, e);
      }
    }
  );

  router.get(
    { path: `${API_ROOT}/reports/schedules/{id}/last-run.md`, validate: { params: scheduleIdParams } },
    async (context, request, response) => {
      try {
        const id = validScheduleId((request.params as any).id);
        const client = context.core.opensearch.client.asCurrentUser;
        await findSchedule(client, id);
        const run = await readReportRun(client, id);
        if (!run) throw Object.assign(new Error(`Report schedule "${id}" has not run yet.`), { statusCode: 404 });
        // The stored Markdown is the last successful render; a later failed
        // attempt leaves it in place, so it is served regardless of `error`.
        if (!run.markdown) {
          throw Object.assign(new Error(`Report schedule "${id}" has no stored report yet${run.error ? ` (last attempt failed: ${run.error})` : ''}.`), { statusCode: 404 });
        }
        return downloadResponse(response, {
          filename: reportRunFilename(id, run.slot),
          contentType: 'text/markdown; charset=utf-8',
          headers: { 'x-content-type-options': 'nosniff', 'content-security-policy': "default-src 'none'" },
          body: run.markdown,
        });
      } catch (e: any) {
        return failure(response, e);
      }
    }
  );

  router.post(
    { path: `${API_ROOT}/reports/schedules/{id}/run-now`, validate: { params: scheduleIdParams } },
    async (context, request, response) => {
      try {
        const identity = await requirePluginAdmin(context, request);
        const id = validScheduleId((request.params as any).id);
        const client = context.core.opensearch.client.asCurrentUser;
        const schedule = await findSchedule(client, id);
        // Rendered with the caller's client and stored for the due slot, so
        // the scheduler does not render the same slot again afterwards. The
        // run is delivered to the schedule's channels like a scheduled one
        // (step 1.3; a slot already delivered is a silent duplicate).
        const run = await runSchedule(client, schedule, { actor: identity.name, now: new Date(), emitter: getNotificationEmitter() });
        return response.ok({ body: { run: summariseRun(run) } });
      } catch (e: any) {
        return failure(response, e);
      }
    }
  );
}
