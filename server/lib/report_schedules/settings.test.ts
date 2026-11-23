import { META_INDEX, REPORT_SCHEDULES_DOC_ID, REPORT_SCHEDULES_MAX } from '../../../common';
import { loadReportSchedules, normaliseReportSchedule, normaliseReportSchedules, reportSchedulesSettings } from './settings';

const valid = { id: 'daily-8', name: 'Daily 08:00', cadence: 'daily', hourUtc: 8, rangeDays: 1, channelIds: ['slack-soc'], enabled: true };

describe('normaliseReportSchedule', () => {
  test('accepts a daily schedule, defaults dayOfWeek to Monday and enabled to true', () => {
    const { enabled, ...rest } = valid;
    expect(normaliseReportSchedule(rest, 0)).toEqual({ ...valid, dayOfWeek: 1, enabled: true });
  });

  test('weekly requires dayOfWeek 0-6; daily keeps a valid one for later', () => {
    expect(() => normaliseReportSchedule({ ...valid, cadence: 'weekly' }, 0)).toThrow(/dayOfWeek/);
    expect(() => normaliseReportSchedule({ ...valid, cadence: 'weekly', dayOfWeek: 7 }, 0)).toThrow(/dayOfWeek/);
    expect(normaliseReportSchedule({ ...valid, cadence: 'weekly', dayOfWeek: 0 }, 0).dayOfWeek).toBe(0);
    expect(normaliseReportSchedule({ ...valid, cadence: 'weekly', dayOfWeek: '6' }, 0).dayOfWeek).toBe(6);
    expect(normaliseReportSchedule({ ...valid, dayOfWeek: 3 }, 0).dayOfWeek).toBe(3);
    expect(normaliseReportSchedule({ ...valid, dayOfWeek: 9 }, 0).dayOfWeek).toBe(1);
  });

  test('bounds: id, name, cadence, hourUtc, rangeDays, channelIds', () => {
    expect(() => normaliseReportSchedule({ ...valid, id: 'Bad Id' }, 2)).toThrow(/schedules\[2\]: id/);
    expect(() => normaliseReportSchedule({ ...valid, name: '  ' }, 0)).toThrow(/name is required/);
    expect(() => normaliseReportSchedule({ ...valid, name: 'x'.repeat(121) }, 0)).toThrow(/at most 120/);
    expect(() => normaliseReportSchedule({ ...valid, name: 'a\nb' }, 0)).toThrow(/single line/);
    expect(() => normaliseReportSchedule({ ...valid, cadence: 'monthly' }, 0)).toThrow(/cadence/);
    expect(() => normaliseReportSchedule({ ...valid, hourUtc: 24 }, 0)).toThrow(/hourUtc/);
    expect(() => normaliseReportSchedule({ ...valid, hourUtc: 1.5 }, 0)).toThrow(/hourUtc/);
    expect(() => normaliseReportSchedule({ ...valid, rangeDays: 0 }, 0)).toThrow(/rangeDays/);
    expect(() => normaliseReportSchedule({ ...valid, rangeDays: 91 }, 0)).toThrow(/rangeDays/);
    expect(() => normaliseReportSchedule({ ...valid, channelIds: 'slack' }, 0)).toThrow(/channelIds/);
    expect(() => normaliseReportSchedule({ ...valid, channelIds: [1] }, 0)).toThrow(/channelIds/);
    expect(() => normaliseReportSchedule({ ...valid, enabled: 'yes' }, 0)).toThrow(/enabled/);
    expect(normaliseReportSchedule({ ...valid, channelIds: [' a ', 'a', '', 'b'] }, 0).channelIds).toEqual(['a', 'b']);
    expect(normaliseReportSchedule({ ...valid, hourUtc: '23', rangeDays: '90' }, 0)).toMatchObject({ hourUtc: 23, rangeDays: 90 });
  });
});

describe('normaliseReportSchedules', () => {
  test('caps the list and rejects duplicate ids', () => {
    expect(normaliseReportSchedules({ schedules: undefined as any })).toEqual({ schedules: [] });
    expect(() => normaliseReportSchedules({ schedules: [valid, { ...valid, name: 'again' }] as any })).toThrow(/used more than once/);
    const many = Array.from({ length: REPORT_SCHEDULES_MAX + 1 }, (_, i) => ({ ...valid, id: `s-${i}` }));
    expect(() => normaliseReportSchedules({ schedules: many as any })).toThrow(/At most 20/);
    expect(normaliseReportSchedules({ schedules: many.slice(0, REPORT_SCHEDULES_MAX) as any }).schedules).toHaveLength(REPORT_SCHEDULES_MAX);
  });
});

describe('reportSchedulesSettings / loadReportSchedules', () => {
  function clientWith(stored: any | null) {
    return {
      get: jest.fn(async ({ index, id }: any) => {
        if (index === META_INDEX && id === REPORT_SCHEDULES_DOC_ID && stored !== null) return { body: { _source: stored } };
        throw Object.assign(new Error('not found'), { meta: { statusCode: 404 } });
      }),
      index: jest.fn(async ({ body }: any) => {
        stored = body;
        return { body: { result: 'created' } };
      }),
    };
  }

  test('reads defaults, writes a validated list with the envelope', async () => {
    const client = clientWith(null);
    expect(await reportSchedulesSettings.read(client)).toEqual({ schedules: [] });
    const written = await reportSchedulesSettings.write(client, { schedules: [{ ...valid, hourUtc: '8' }] }, { actor: 'admin' });
    expect(written.schedules).toEqual([{ ...valid, dayOfWeek: 1 }]);
    expect(written.updated_by).toBe('admin');
    expect(client.index.mock.calls[0][0]).toMatchObject({ index: META_INDEX, id: REPORT_SCHEDULES_DOC_ID, refresh: 'wait_for' });
    await expect(reportSchedulesSettings.write(client, { schedules: [{ ...valid, hourUtc: 99 }] }, { actor: 'admin' })).rejects.toMatchObject({ statusCode: 400 });
  });

  test('loadReportSchedules never throws', async () => {
    expect(await loadReportSchedules(clientWith(null))).toEqual([]);
    // Stored entries are re-normalised (dayOfWeek filled in for a daily entry).
    expect(await loadReportSchedules(clientWith({ schedules: [valid] }))).toEqual([{ ...valid, dayOfWeek: 1 }]);
    // An entry that no longer validates is dropped with a warning; the rest survive.
    const partial = { debug: jest.fn(), warn: jest.fn() };
    const loaded = await loadReportSchedules(
      clientWith({ schedules: [{ ...valid, id: 'no-hour', hourUtc: undefined }, valid, { ...valid, name: '' }, valid] }),
      partial
    );
    expect(loaded).toEqual([{ ...valid, dayOfWeek: 1 }]);
    expect(partial.warn).toHaveBeenCalledTimes(3);
    expect(partial.warn).toHaveBeenCalledWith(expect.stringContaining('schedules[0]'));
    expect(partial.warn).toHaveBeenCalledWith(expect.stringContaining('used more than once'));
    const broken = { get: jest.fn(async () => { throw new Error('boom'); }) };
    const logger = { debug: jest.fn(), warn: jest.fn() };
    expect(await loadReportSchedules(broken, logger)).toEqual([]);
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('boom'));
  });
});
