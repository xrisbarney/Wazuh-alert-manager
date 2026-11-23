import { ACTIVITY_WRITE_ALIAS, META_INDEX, REPORT_RUN_MAX_ATTEMPTS, REPORT_SCHEDULES_DOC_ID } from '../../../common';
import type { ReportSchedule, ReportSummaryData } from '../../../common';
import {
  dueSlot,
  nextSlot,
  readReportRun,
  readReportRuns,
  reportRunDocId,
  runSchedule,
  slotCovered,
  slotRange,
  summariseRun,
  tickReportScheduler,
} from './scheduler';
import { TRUNCATION_NOTE } from './render';

function mockLogger() {
  return { debug: jest.fn(), info: jest.fn(), warn: jest.fn(), error: jest.fn() } as any;
}

/** In-memory meta index: get/create/update/delete/index/mget by id, plus activity writes. */
function memoryClient(initial: Record<string, any> = {}) {
  const docs = new Map<string, { source: any; seq: number }>(Object.entries(initial).map(([id, source]) => [id, { source, seq: 1 }]));
  const activity: any[] = [];
  const notFound = () => Object.assign(new Error('not found'), { meta: { statusCode: 404 } });
  const client = {
    docs,
    activity,
    get: jest.fn(async ({ index, id }: any) => {
      if (index !== META_INDEX) throw notFound();
      const doc = docs.get(id);
      if (!doc) throw notFound();
      return { body: { _id: id, _source: doc.source, _seq_no: doc.seq, _primary_term: 1 } };
    }),
    create: jest.fn(async ({ id, body }: any) => {
      if (docs.has(id)) throw Object.assign(new Error('conflict'), { meta: { statusCode: 409 } });
      docs.set(id, { source: body, seq: 1 });
      return { body: { result: 'created' } };
    }),
    update: jest.fn(async ({ id, body, if_seq_no }: any) => {
      const doc = docs.get(id);
      if (!doc) {
        if (!body.doc_as_upsert) throw notFound();
        docs.set(id, { source: { ...body.doc }, seq: 1 });
        return { body: { result: 'created' } };
      }
      if (if_seq_no !== undefined && if_seq_no !== doc.seq) throw Object.assign(new Error('conflict'), { meta: { statusCode: 409 } });
      docs.set(id, { source: { ...doc.source, ...body.doc }, seq: doc.seq + 1 });
      return { body: { result: 'updated' } };
    }),
    delete: jest.fn(async ({ id }: any) => {
      docs.delete(id);
      return { body: { result: 'deleted' } };
    }),
    index: jest.fn(async ({ index, id, body }: any) => {
      if (index === ACTIVITY_WRITE_ALIAS) {
        activity.push(body);
        return { body: { result: 'created' } };
      }
      if (index !== META_INDEX) throw new Error(`unexpected index ${index}`);
      const existing = docs.get(id);
      docs.set(id, { source: body, seq: (existing?.seq ?? 0) + 1 });
      return { body: { result: existing ? 'updated' : 'created' } };
    }),
    mget: jest.fn(async ({ body }: any) => ({
      body: { docs: body.ids.map((id: string) => (docs.has(id) ? { _id: id, found: true, _source: docs.get(id)!.source } : { _id: id, found: false })) },
    })),
  };
  return client;
}

const fixture: ReportSummaryData = {
  metrics: {
    from: '',
    to: '',
    totalAlerts: 3,
    exact: true,
    alertBasis: 'exact_cohort',
    timingBasis: 'exact_cohort',
    caseBasis: 'exact_cohort',
    coverage: { closedMissingReporting: 0, assignedMissingReporting: 0 },
    statusBreakdown: { open: 1, in_progress: 1, closed: 1 },
    resolvedCount: 1,
    assignedCount: 2,
    meanTimeToResolveMinutes: 30,
    meanTimeToAssignMinutes: 5,
    slaCompliancePct: 100,
    slaBreakdown: [],
    slaPolicy: [],
    analysts: [],
    caseAnalysts: [],
    cases: { totalCases: 0, statusBreakdown: { open: 0, in_progress: 0, closed: 0 }, severityBreakdown: { low: 0, medium: 0, high: 0, critical: 0 }, meanTimeToCloseMinutes: null, closedCount: 0 },
  },
  extras: { severityBands: {}, topRules: [], topAgents: [], openCasesBySeverity: {}, breachedCount: 0 },
};

const daily: ReportSchedule = { id: 'daily-8', name: 'Daily 08:00', cadence: 'daily', dayOfWeek: 1, hourUtc: 8, rangeDays: 1, channelIds: [], enabled: true };
const weekly: ReportSchedule = { id: 'weekly-mon', name: 'Weekly', cadence: 'weekly', dayOfWeek: 1, hourUtc: 6, rangeDays: 7, channelIds: [], enabled: true };

describe('slot computation (UTC, DST-free)', () => {
  test('daily: the slot is today at hourUtc once passed, else yesterday', () => {
    expect(dueSlot(daily, new Date('2026-11-20T08:00:00.000Z'))).toBe('2026-11-20T08:00:00.000Z');
    expect(dueSlot(daily, new Date('2026-11-20T07:59:59.999Z'))).toBe('2026-11-19T08:00:00.000Z');
    expect(dueSlot(daily, new Date('2026-11-20T23:59:59.999Z'))).toBe('2026-11-20T08:00:00.000Z');
    expect(nextSlot(daily, new Date('2026-11-20T08:00:00.000Z'))).toBe('2026-11-21T08:00:00.000Z');
    expect(nextSlot(daily, new Date('2026-11-20T07:00:00.000Z'))).toBe('2026-11-20T08:00:00.000Z');
  });

  test('daily: hour 0 and hour 23 across a month and year boundary', () => {
    const midnight = { ...daily, hourUtc: 0 };
    expect(dueSlot(midnight, new Date('2026-12-01T00:00:00.000Z'))).toBe('2026-12-01T00:00:00.000Z');
    expect(dueSlot(midnight, new Date('2026-01-01T00:00:00.000Z'))).toBe('2026-01-01T00:00:00.000Z');
    expect(dueSlot(midnight, new Date('2025-12-31T23:59:59.000Z'))).toBe('2025-12-31T00:00:00.000Z');
    const late = { ...daily, hourUtc: 23 };
    expect(dueSlot(late, new Date('2026-01-01T00:30:00.000Z'))).toBe('2025-12-31T23:00:00.000Z');
  });

  test('weekly: 2026-11-20 is a Friday; Monday 06:00 is due from the 16th', () => {
    expect(new Date('2026-11-20T00:00:00.000Z').getUTCDay()).toBe(5);
    expect(dueSlot(weekly, new Date('2026-11-20T10:00:00.000Z'))).toBe('2026-11-16T06:00:00.000Z');
    // Same weekday, before the hour: the previous week's slot.
    expect(dueSlot(weekly, new Date('2026-11-16T05:59:59.000Z'))).toBe('2026-11-09T06:00:00.000Z');
    expect(dueSlot(weekly, new Date('2026-11-16T06:00:00.000Z'))).toBe('2026-11-16T06:00:00.000Z');
    expect(nextSlot(weekly, new Date('2026-11-16T06:00:00.000Z'))).toBe('2026-11-23T06:00:00.000Z');
    // Sunday (0) and Saturday (6) are both reachable.
    expect(dueSlot({ ...weekly, dayOfWeek: 0 }, new Date('2026-11-20T10:00:00.000Z'))).toBe('2026-11-15T06:00:00.000Z');
    expect(dueSlot({ ...weekly, dayOfWeek: 6 }, new Date('2026-11-20T10:00:00.000Z'))).toBe('2026-11-14T06:00:00.000Z');
  });

  test('slots ignore the process time zone (same answer in any TZ offset)', () => {
    // 2026-03-29 is the European DST switch; the slot is still 02:00 UTC exactly.
    expect(dueSlot({ ...daily, hourUtc: 2 }, new Date('2026-03-29T12:00:00.000Z'))).toBe('2026-03-29T02:00:00.000Z');
    expect(dueSlot({ ...daily, hourUtc: 2 }, new Date('2026-03-29T01:59:00.000Z'))).toBe('2026-03-28T02:00:00.000Z');
  });

  test('slotRange covers rangeDays days ending at the slot', () => {
    expect(slotRange({ rangeDays: 7 }, '2026-11-16T06:00:00.000Z')).toEqual({ from: '2026-11-09T06:00:00.000Z', to: '2026-11-16T06:00:00.000Z' });
  });
});

describe('runSchedule', () => {
  test('stores the run doc, audits it, and summarises without the body', async () => {
    const client = memoryClient();
    const collect = jest.fn(async () => fixture);
    const now = new Date('2026-11-20T08:03:00.000Z');
    const run = await runSchedule(client, daily, { actor: 'scheduler', now, collect });
    expect(collect).toHaveBeenCalledWith(client, { from: '2026-11-19T08:00:00.000Z', to: '2026-11-20T08:00:00.000Z' });
    expect(run.slot).toBe('2026-11-20T08:00:00.000Z');
    expect(run.error).toBeNull();
    expect(run.markdown).toContain('# Daily 08:00');
    const stored = client.docs.get(reportRunDocId('daily-8'))!.source;
    expect(stored.document_type).toBe('report_run');
    expect(stored.schedule_id).toBe('daily-8');
    expect(client.index.mock.calls.find(([req]: any[]) => req.index === META_INDEX)?.[0]).toMatchObject({ id: 'report_run:daily-8', refresh: 'wait_for' });
    expect(client.activity).toEqual([expect.objectContaining({ action: 'report_schedule_run', target_id: 'report_run:daily-8', user: 'scheduler', source: 'scheduler', to: run.slot })]);
    const summary = summariseRun(run);
    expect((summary as any).markdown).toBeUndefined();
    expect(summary.markdown_bytes).toBe(Buffer.byteLength(run.markdown));
    expect(summary.truncated).toBe(false);
    expect(summariseRun({ ...run, markdown: `x${TRUNCATION_NOTE}` }).truncated).toBe(true);
  });

  test('a first rendering failure is upserted as a failed attempt (no stored report yet)', async () => {
    const client = memoryClient();
    const logger = mockLogger();
    const run = await runSchedule(client, daily, {
      actor: 'scheduler',
      now: new Date('2026-11-20T09:00:00.000Z'),
      collect: jest.fn(async () => { throw new Error('search_phase_execution_exception'); }),
      logger,
    });
    expect(run.error).toBe('search_phase_execution_exception');
    expect(run.markdown).toBe('');
    expect(run.slot).toBe('');
    expect(run.failed_slot).toBe('2026-11-20T08:00:00.000Z');
    expect(run.attempts).toBe(1);
    expect(client.activity[0].action).toBe('report_schedule_failed');
    expect(logger.warn).toHaveBeenCalled();
    expect(client.index).not.toHaveBeenCalledWith(expect.objectContaining({ index: META_INDEX }));
    expect(client.update).toHaveBeenCalledWith(expect.objectContaining({ id: 'report_run:daily-8', body: expect.objectContaining({ doc_as_upsert: true }) }));
    expect(await readReportRun(client, 'daily-8')).toMatchObject({ error: 'search_phase_execution_exception', slot: '', failed_slot: run.failed_slot, attempts: 1 });
    expect(slotCovered(run, run.failed_slot as string)).toBe(false);
  });

  test('a failure after a success keeps the stored Markdown and counts attempts; a success clears the failure', async () => {
    const client = memoryClient();
    const good = await runSchedule(client, daily, { actor: 'scheduler', now: new Date('2026-11-20T08:01:00.000Z'), collect: async () => fixture });
    const failing = jest.fn(async () => { throw new Error('timeout'); });
    const first = await runSchedule(client, daily, { actor: 'scheduler', now: new Date('2026-11-21T08:01:00.000Z'), collect: failing });
    expect(first).toMatchObject({ slot: good.slot, markdown: good.markdown, generated_at: good.generated_at, error: 'timeout', failed_slot: '2026-11-21T08:00:00.000Z', attempts: 1 });
    const second = await runSchedule(client, daily, { actor: 'scheduler', now: new Date('2026-11-21T08:02:00.000Z'), collect: failing });
    expect(second.attempts).toBe(2);
    expect((await readReportRun(client, 'daily-8'))!.markdown).toBe(good.markdown);
    // A failure at a different slot restarts the count.
    const other = await runSchedule(client, daily, { actor: 'scheduler', now: new Date('2026-11-22T08:02:00.000Z'), collect: failing });
    expect(other).toMatchObject({ failed_slot: '2026-11-22T08:00:00.000Z', attempts: 1, markdown: good.markdown });
    const recovered = await runSchedule(client, daily, { actor: 'scheduler', now: new Date('2026-11-22T08:03:00.000Z'), collect: async () => fixture });
    expect(recovered).toMatchObject({ slot: '2026-11-22T08:00:00.000Z', error: null, failed_slot: null, failed_at: null, attempts: 0 });
    expect(await readReportRun(client, 'daily-8')).toMatchObject({ error: null, failed_slot: null, attempts: 0 });
  });

  test('readReportRun / readReportRuns ignore foreign docs and missing ids', async () => {
    const client = memoryClient({ 'report_run:other': { document_type: 'lease' } });
    expect(await readReportRun(client, 'other')).toBeNull();
    expect(await readReportRun(client, 'missing')).toBeNull();
    await runSchedule(client, daily, { actor: 'admin', now: new Date('2026-11-20T09:00:00.000Z'), collect: async () => fixture });
    const runs = await readReportRuns(client, ['daily-8', 'other', 'missing']);
    expect(Object.keys(runs)).toEqual(['daily-8']);
    expect(runs['daily-8'].triggered_by).toBe('admin');
  });
});

describe('tickReportScheduler', () => {
  const settings = { [REPORT_SCHEDULES_DOC_ID]: { schedules: [daily, weekly, { ...daily, id: 'off', enabled: false }] } };

  test('renders every enabled due schedule once, then skips the stored slot', async () => {
    const client = memoryClient(settings);
    const collect = jest.fn(async () => fixture);
    const now = new Date('2026-11-20T08:00:30.000Z');
    const first = await tickReportScheduler(client, { holder: 'h1', ttlMs: 180_000, now, collect });
    expect(first).toEqual({ acquired: true, ran: ['daily-8', 'weekly-mon'], skipped: [] });
    expect(collect).toHaveBeenCalledTimes(2);

    const second = await tickReportScheduler(client, { holder: 'h1', ttlMs: 180_000, now: new Date('2026-11-20T08:01:30.000Z'), collect });
    expect(second).toEqual({ acquired: true, ran: [], skipped: ['daily-8', 'weekly-mon'] });
    expect(collect).toHaveBeenCalledTimes(2);

    // The next daily slot is rendered; the weekly one is still covered.
    const third = await tickReportScheduler(client, { holder: 'h1', ttlMs: 180_000, now: new Date('2026-11-21T08:00:10.000Z'), collect });
    expect(third).toEqual({ acquired: true, ran: ['daily-8'], skipped: ['weekly-mon'] });
    expect(client.docs.get('report_run:daily-8')!.source.slot).toBe('2026-11-21T08:00:00.000Z');
  });

  test('a run stored by "Run now" for the due slot is not rendered again', async () => {
    const client = memoryClient(settings);
    const now = new Date('2026-11-20T12:00:00.000Z');
    await runSchedule(client, daily, { actor: 'admin', now, collect: async () => fixture });
    const collect = jest.fn(async () => fixture);
    const result = await tickReportScheduler(client, { holder: 'h1', ttlMs: 180_000, now, collect });
    expect(result.skipped).toContain('daily-8');
    expect(result.ran).toEqual(['weekly-mon']);
  });

  test('does nothing when another replica holds a fresh lease', async () => {
    const client = memoryClient({
      ...settings,
      'lease:report_scheduler': { document_type: 'lease', lease_id: 'report_scheduler', holder_id: 'other', expires_at: '2026-11-20T08:05:00.000Z', updated_at: '2026-11-20T08:02:00.000Z' },
    });
    const collect = jest.fn(async () => fixture);
    const result = await tickReportScheduler(client, { holder: 'h1', ttlMs: 180_000, now: new Date('2026-11-20T08:03:00.000Z'), collect });
    expect(result).toEqual({ acquired: false, ran: [], skipped: [] });
    expect(collect).not.toHaveBeenCalled();
    expect(client.docs.has('report_run:daily-8')).toBe(false);
  });

  test('takes over an expired lease held elsewhere', async () => {
    const client = memoryClient({
      ...settings,
      'lease:report_scheduler': { document_type: 'lease', lease_id: 'report_scheduler', holder_id: 'other', expires_at: '2026-11-20T08:00:00.000Z', updated_at: '2026-11-20T07:57:00.000Z' },
    });
    const result = await tickReportScheduler(client, { holder: 'h1', ttlMs: 180_000, now: new Date('2026-11-20T08:03:00.000Z'), collect: async () => fixture });
    expect(result.acquired).toBe(true);
    expect(result.ran).toEqual(['daily-8', 'weekly-mon']);
    expect(client.docs.get('lease:report_scheduler')!.source.holder_id).toBe('h1');
  });

  test('a transient failure keeps the previous report and is retried up to REPORT_RUN_MAX_ATTEMPTS times', async () => {
    const client = memoryClient({ [REPORT_SCHEDULES_DOC_ID]: { schedules: [daily] } });
    const logger = mockLogger();
    const good = jest.fn(async () => fixture);
    await tickReportScheduler(client, { holder: 'h1', ttlMs: 180_000, now: new Date('2026-11-20T08:00:30.000Z'), collect: good, logger });
    const markdown = client.docs.get('report_run:daily-8')!.source.markdown;
    expect(markdown).toContain('# Daily 08:00');

    const failing = jest.fn(async () => { throw new Error('timeout'); });
    const failed = await tickReportScheduler(client, { holder: 'h1', ttlMs: 180_000, now: new Date('2026-11-21T08:00:30.000Z'), collect: failing, logger });
    expect(failed).toEqual({ acquired: true, ran: ['daily-8'], skipped: [] });
    const stored = client.docs.get('report_run:daily-8')!.source;
    expect(stored.markdown).toBe(markdown);
    expect(stored.slot).toBe('2026-11-20T08:00:00.000Z');
    expect(stored).toMatchObject({ error: 'timeout', failed_slot: '2026-11-21T08:00:00.000Z', attempts: 1 });

    // The next healthy tick retries the slot instead of skipping it.
    const healthy = await tickReportScheduler(client, { holder: 'h1', ttlMs: 180_000, now: new Date('2026-11-21T08:01:30.000Z'), collect: good, logger });
    expect(healthy).toEqual({ acquired: true, ran: ['daily-8'], skipped: [] });
    expect(good).toHaveBeenCalledTimes(2);
    expect(client.docs.get('report_run:daily-8')!.source).toMatchObject({ slot: '2026-11-21T08:00:00.000Z', error: null, attempts: 0 });

    // Persistent failures stop after REPORT_RUN_MAX_ATTEMPTS at the same slot.
    for (let i = 0; i < REPORT_RUN_MAX_ATTEMPTS; i += 1) {
      const r = await tickReportScheduler(client, { holder: 'h1', ttlMs: 180_000, now: new Date(`2026-11-22T08:0${i + 1}:00.000Z`), collect: failing, logger });
      expect(r.ran).toEqual(['daily-8']);
    }
    failing.mockClear();
    const exhausted = await tickReportScheduler(client, { holder: 'h1', ttlMs: 180_000, now: new Date('2026-11-22T08:30:00.000Z'), collect: failing, logger });
    expect(exhausted).toEqual({ acquired: true, ran: [], skipped: ['daily-8'] });
    expect(failing).not.toHaveBeenCalled();
    expect(client.docs.get('report_run:daily-8')!.source).toMatchObject({ slot: '2026-11-21T08:00:00.000Z', failed_slot: '2026-11-22T08:00:00.000Z', attempts: REPORT_RUN_MAX_ATTEMPTS });
    // The following slot is attempted again.
    const nextDay = await tickReportScheduler(client, { holder: 'h1', ttlMs: 180_000, now: new Date('2026-11-23T08:00:10.000Z'), collect: failing, logger });
    expect(nextDay.ran).toEqual(['daily-8']);
    expect(client.docs.get('report_run:daily-8')!.source).toMatchObject({ failed_slot: '2026-11-23T08:00:00.000Z', attempts: 1 });
  });

  test('an invalid stored entry is dropped with a warning and the valid schedules still render', async () => {
    const client = memoryClient({
      [REPORT_SCHEDULES_DOC_ID]: { schedules: [{ ...daily, id: 'broken', hourUtc: undefined }, { ...daily, id: 'fine' }, { ...daily, id: 'Bad Id' }] },
    });
    const logger = mockLogger();
    const collect = jest.fn(async () => fixture);
    const result = await tickReportScheduler(client, { holder: 'h1', ttlMs: 180_000, now: new Date('2026-11-20T08:00:30.000Z'), collect, logger });
    expect(result).toEqual({ acquired: true, ran: ['fine'], skipped: [] });
    expect(client.docs.has('report_run:fine')).toBe(true);
    expect(client.docs.has('report_run:broken')).toBe(false);
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('schedules[0]'));
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('schedules[2]'));
  });

  test('a failing run read or write skips only that schedule', async () => {
    const client = memoryClient({ [REPORT_SCHEDULES_DOC_ID]: { schedules: [daily, weekly] } });
    const logger = mockLogger();
    client.get.mockImplementation(async ({ id }: any) => {
      if (id === 'report_run:daily-8') throw new Error('cluster_block_exception');
      const doc = client.docs.get(id);
      if (!doc) throw Object.assign(new Error('not found'), { meta: { statusCode: 404 } });
      return { body: { _id: id, _source: doc.source, _seq_no: doc.seq, _primary_term: 1 } };
    });
    const result = await tickReportScheduler(client, { holder: 'h1', ttlMs: 180_000, now: new Date('2026-11-20T08:00:30.000Z'), collect: async () => fixture, logger });
    expect(result).toEqual({ acquired: true, ran: ['weekly-mon'], skipped: [] });
    expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('cluster_block_exception'));
  });

  test('a missing settings doc means nothing to run, and an unreadable one is logged', async () => {
    const client = memoryClient();
    const logger = mockLogger();
    expect(await tickReportScheduler(client, { holder: 'h1', ttlMs: 180_000, logger })).toEqual({ acquired: true, ran: [], skipped: [] });
    const broken = memoryClient();
    broken.get.mockImplementation(async ({ id }: any) => {
      if (id === REPORT_SCHEDULES_DOC_ID) throw new Error('cluster_block_exception');
      throw Object.assign(new Error('not found'), { meta: { statusCode: 404 } });
    });
    expect(await tickReportScheduler(broken, { holder: 'h1', ttlMs: 180_000, logger })).toEqual({ acquired: true, ran: [], skipped: [] });
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('cluster_block_exception'));
  });
});

describe('report.scheduled delivery (step 1.3)', () => {
  test('a successful run is handed to the emitter with the schedule and the stored run, after the run doc is written; a failed render or a schedule without channels sends nothing', async () => {
    const client = memoryClient();
    const emitter: { emitReportEvent: jest.Mock } = { emitReportEvent: jest.fn(async () => ({})) };
    const withChannels: ReportSchedule = { ...daily, channelIds: ['slack', 'hook'] };
    const now = new Date('2026-11-20T08:03:00.000Z');
    const run = await runSchedule(client, withChannels, { actor: 'admin', now, collect: async () => fixture, emitter });
    expect(emitter.emitReportEvent).toHaveBeenCalledTimes(1);
    expect(emitter.emitReportEvent).toHaveBeenCalledWith(withChannels, run, { now });
    expect(run.slot).toBe('2026-11-20T08:00:00.000Z');
    expect(run.markdown).toContain('# Daily 08:00');
    expect(client.index.mock.invocationCallOrder[0]).toBeLessThan(emitter.emitReportEvent.mock.invocationCallOrder[0]);

    emitter.emitReportEvent.mockClear();
    const failed = await runSchedule(client, withChannels, { actor: 'scheduler', now: new Date('2026-11-21T08:03:00.000Z'), collect: async () => { throw new Error('nope'); }, emitter });
    expect(failed.error).toBe('nope');
    expect(emitter.emitReportEvent).not.toHaveBeenCalled();

    await runSchedule(client, daily, { actor: 'scheduler', now: new Date('2026-11-22T08:03:00.000Z'), collect: async () => fixture, emitter });
    expect(emitter.emitReportEvent).not.toHaveBeenCalled();

    // No emitter: the 5.4 behaviour.
    const plain = await runSchedule(memoryClient(), withChannels, { actor: 'scheduler', now, collect: async () => fixture });
    expect(plain.error).toBeNull();
  });

  test('the scheduler tick passes the emitter to every due schedule and a stored slot is not delivered twice', async () => {
    const bound = { ...daily, channelIds: ['slack'] };
    const client = memoryClient({ [REPORT_SCHEDULES_DOC_ID]: { schedules: [bound, { ...weekly, channelIds: ['slack'] }] } });
    const emitter: { emitReportEvent: jest.Mock } = { emitReportEvent: jest.fn(async () => ({})) };
    const first = await tickReportScheduler(client, { holder: 'h1', ttlMs: 180_000, now: new Date('2026-11-20T08:00:30.000Z'), collect: async () => fixture, emitter });
    expect(first.ran).toEqual(['daily-8', 'weekly-mon']);
    expect(emitter.emitReportEvent).toHaveBeenCalledTimes(2);
    expect(emitter.emitReportEvent.mock.calls.map(([schedule, run]: any[]) => [schedule.id, run.slot])).toEqual([
      ['daily-8', '2026-11-20T08:00:00.000Z'],
      ['weekly-mon', '2026-11-16T06:00:00.000Z'],
    ]);
    emitter.emitReportEvent.mockClear();
    const second = await tickReportScheduler(client, { holder: 'h1', ttlMs: 180_000, now: new Date('2026-11-20T08:01:30.000Z'), collect: async () => fixture, emitter });
    expect(second.skipped).toEqual(['daily-8', 'weekly-mon']);
    expect(emitter.emitReportEvent).not.toHaveBeenCalled();
  });
});
