/**
 * @jest-environment jsdom
 */
import React from 'react';
import { configure, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { LastRunCell, ReportSchedulesView, describeCadence, formatSlot, suggestScheduleId } from './report_schedules_view';

configure({ testIdAttribute: 'data-test-subj' });

const daily = { id: 'daily-8', name: 'Daily 08:00', cadence: 'daily' as const, dayOfWeek: 1, hourUtc: 8, rangeDays: 1, channelIds: [], enabled: true };
const weekly = { id: 'weekly-mon', name: 'Weekly', cadence: 'weekly' as const, dayOfWeek: 1, hourUtc: 6, rangeDays: 7, channelIds: ['slack-soc'], enabled: false };

const storedRun = {
  schedule_id: 'daily-8',
  slot: '2026-11-20T08:00:00.000Z',
  generated_at: '2026-11-20T08:00:05.000Z',
  range_from: '2026-11-19T08:00:00.000Z',
  range_to: '2026-11-20T08:00:00.000Z',
  triggered_by: 'scheduler',
  error: null,
  failed_slot: null,
  failed_at: null,
  attempts: 0,
  markdown_bytes: 2048,
  truncated: false,
};

const listing = {
  schedules: [daily, weekly],
  lastRuns: { 'daily-8': storedRun },
  nextSlots: { 'daily-8': '2026-11-21T08:00:00.000Z', 'weekly-mon': '2026-11-23T06:00:00.000Z' },
  updated_at: '2026-11-20T07:00:00.000Z',
  updated_by: 'admin',
};

function apiServiceWith(isPluginAdmin: boolean, overrides: Record<string, any> = {}) {
  return {
    fetchSystemCapabilities: jest.fn(async () => ({ isPluginAdmin })),
    fetchReportSchedules: jest.fn(async () => listing),
    saveReportSchedules: jest.fn(async (payload: any) => ({ ...listing, schedules: payload.schedules, updated_by: 'admin' })),
    runReportScheduleNow: jest.fn(async () => ({ run: { ...storedRun, triggered_by: 'admin' } })),
    downloadReportScheduleLastRun: jest.fn(async () => ({ blob: new Blob(['# x']), filename: 'wam-report-daily-8-2026-11-20.md', truncated: false })),
    ...overrides,
  } as any;
}

describe('ReportSchedulesView', () => {
  test('locks the tab for non-administrators', async () => {
    render(<ReportSchedulesView apiService={apiServiceWith(false)} onToast={jest.fn()} />);
    await waitFor(() => expect(screen.getByText(/administered by Wazuh administrators/)).toBeTruthy());
    expect(screen.queryByTestId('wamReportScheduleSave')).toBeNull();
    expect(screen.queryByTestId('wamReportScheduleAdd')).toBeNull();
  });

  test('shows the load error with a Retry that reloads the list', async () => {
    const api = apiServiceWith(true, {
      fetchReportSchedules: jest.fn().mockRejectedValueOnce({ body: { message: 'meta index unavailable' } }).mockResolvedValue(listing),
    });
    render(<ReportSchedulesView apiService={api} onToast={jest.fn()} />);
    await waitFor(() => expect(screen.getByTestId('wamReportScheduleLoadError')).toBeTruthy());
    expect(screen.getByText('meta index unavailable')).toBeTruthy();
    fireEvent.click(screen.getByTestId('wamReportScheduleRetry'));
    await waitFor(() => expect(screen.getByTestId('wamReportSchedule-daily-8')).toBeTruthy());
    expect(api.fetchReportSchedules).toHaveBeenCalledTimes(2);
  });

  test('an empty list shows the empty-table message and the Add button', async () => {
    const api = apiServiceWith(true, { fetchReportSchedules: jest.fn(async () => ({ schedules: [], lastRuns: {}, nextSlots: {} })) });
    render(<ReportSchedulesView apiService={api} onToast={jest.fn()} />);
    await waitFor(() => expect(screen.getByText('No report schedules yet.')).toBeTruthy());
    expect(screen.getByTestId('wamReportScheduleAdd')).toBeTruthy();
    expect((screen.getByTestId('wamReportScheduleSave') as HTMLButtonElement).disabled).toBe(true);
  });

  test('lists schedules with cadence, next slot and last run; removing one marks the list dirty and saves the rest', async () => {
    const api = apiServiceWith(true);
    render(<ReportSchedulesView apiService={api} onToast={jest.fn()} />);
    await waitFor(() => expect(screen.getByTestId('wamReportSchedule-daily-8')).toBeTruthy());
    expect(screen.getByTestId('wamReportSchedule-weekly-mon')).toBeTruthy();
    expect(screen.getByText('Daily, 08:00 UTC')).toBeTruthy();
    expect(screen.getByText('Weekly, Monday 06:00 UTC')).toBeTruthy();
    expect(screen.getByText('2026-11-21 08:00 UTC')).toBeTruthy();
    expect(screen.getByText('paused')).toBeTruthy();
    expect(screen.getByText('Stored')).toBeTruthy();
    expect(screen.getByText('Never')).toBeTruthy();
    expect((screen.getByTestId('wamReportScheduleDownload-daily-8') as HTMLButtonElement).disabled).toBe(false);
    expect((screen.getByTestId('wamReportScheduleDownload-weekly-mon') as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByTestId('wamReportScheduleRemove-weekly-mon'));
    expect(screen.getByTestId('wamReportScheduleDirty')).toBeTruthy();
    fireEvent.click(screen.getByTestId('wamReportScheduleSave'));
    await waitFor(() => expect(api.saveReportSchedules).toHaveBeenCalledWith({ schedules: [daily] }));
  });

  test('the editor adds a weekly schedule with a derived id and comma separated channels', async () => {
    const api = apiServiceWith(true);
    render(<ReportSchedulesView apiService={api} onToast={jest.fn()} />);
    await waitFor(() => expect(screen.getByTestId('wamReportScheduleAdd')).toBeTruthy());
    fireEvent.click(screen.getByTestId('wamReportScheduleAdd'));
    expect(screen.getByTestId('wamReportScheduleEditor')).toBeTruthy();
    fireEvent.change(screen.getByTestId('wamReportScheduleEditorName'), { target: { value: 'SOC Weekly' } });
    expect((screen.getByTestId('wamReportScheduleEditorId') as HTMLInputElement).value).toBe('soc-weekly');
    fireEvent.change(screen.getByTestId('wamReportScheduleEditorCadence'), { target: { value: 'weekly' } });
    fireEvent.change(screen.getByTestId('wamReportScheduleEditorDay'), { target: { value: '5' } });
    fireEvent.change(screen.getByTestId('wamReportScheduleEditorHour'), { target: { value: '17' } });
    fireEvent.change(screen.getByTestId('wamReportScheduleEditorRange'), { target: { value: '7' } });
    fireEvent.change(screen.getByTestId('wamReportScheduleEditorChannels'), { target: { value: 'slack-soc, mail, slack-soc' } });
    fireEvent.click(screen.getByTestId('wamReportScheduleEditorApply'));
    await waitFor(() => expect(screen.getByTestId('wamReportSchedule-soc-weekly')).toBeTruthy());
    expect(screen.queryByTestId('wamReportScheduleEditor')).toBeNull();
    fireEvent.click(screen.getByTestId('wamReportScheduleSave'));
    await waitFor(() => expect(api.saveReportSchedules).toHaveBeenCalled());
    expect(api.saveReportSchedules.mock.calls[0][0].schedules[2]).toEqual({
      id: 'soc-weekly',
      name: 'SOC Weekly',
      cadence: 'weekly',
      dayOfWeek: 5,
      hourUtc: 17,
      rangeDays: 7,
      channelIds: ['slack-soc', 'mail'],
      enabled: true,
    });
  });

  test('an invalid editor draft is refused with a toast and nothing is added', async () => {
    const api = apiServiceWith(true);
    const onToast = jest.fn();
    render(<ReportSchedulesView apiService={api} onToast={onToast} />);
    await waitFor(() => expect(screen.getByTestId('wamReportScheduleAdd')).toBeTruthy());
    fireEvent.click(screen.getByTestId('wamReportScheduleAdd'));
    fireEvent.change(screen.getByTestId('wamReportScheduleEditorHour'), { target: { value: '24' } });
    fireEvent.click(screen.getByTestId('wamReportScheduleEditorApply'));
    expect(onToast).toHaveBeenCalledWith(expect.stringMatching(/Hour must be/), 'danger');
    expect(screen.getByTestId('wamReportScheduleEditor')).toBeTruthy();
    expect(screen.queryByTestId('wamReportScheduleDirty')).toBeNull();
  });

  test('Run now stores the returned run and Download fetches the stored Markdown', async () => {
    const api = apiServiceWith(true);
    const onToast = jest.fn();
    render(<ReportSchedulesView apiService={api} onToast={onToast} />);
    await waitFor(() => expect(screen.getByTestId('wamReportScheduleRunNow-weekly-mon')).toBeTruthy());
    fireEvent.click(screen.getByTestId('wamReportScheduleRunNow-weekly-mon'));
    await waitFor(() => expect(api.runReportScheduleNow).toHaveBeenCalledWith('weekly-mon'));
    await waitFor(() => expect(onToast).toHaveBeenCalledWith('"Weekly" rendered', 'success', expect.stringContaining('stored')));
    fireEvent.click(screen.getByTestId('wamReportScheduleDownload-daily-8'));
    await waitFor(() => expect(api.downloadReportScheduleLastRun).toHaveBeenCalledWith('daily-8'));
  });
});

describe('LastRunCell', () => {
  test('a failed attempt after a stored report shows both, a failure without one only the failure', () => {
    const { unmount } = render(<LastRunCell run={{ ...storedRun, error: 'timeout', failed_slot: '2026-11-21T08:00:00.000Z', failed_at: '2026-11-21T08:00:30.000Z', attempts: 2 }} />);
    expect(screen.getByText('Stored')).toBeTruthy();
    expect(screen.getByTestId('wamReportScheduleFailed').textContent).toBe('Last attempt failed');
    expect(screen.getByText(/attempt 2/)).toBeTruthy();
    unmount();
    render(<LastRunCell run={{ ...storedRun, slot: '', markdown_bytes: 0, error: 'boom', failed_slot: '2026-11-21T08:00:00.000Z', failed_at: null, attempts: 1 }} />);
    expect(screen.queryByText('Stored')).toBeNull();
    expect(screen.getByTestId('wamReportScheduleFailed').textContent).toBe('Failed');
  });

  test('helpers: suggestScheduleId, describeCadence, formatSlot', () => {
    expect(suggestScheduleId('Daily SOC summary!', [])).toBe('daily-soc-summary');
    expect(suggestScheduleId('daily-8', [daily])).toBe('daily-8-2');
    expect(describeCadence(weekly)).toBe('Weekly, Monday 06:00 UTC');
    expect(formatSlot('2026-11-20T08:00:00.000Z')).toBe('2026-11-20 08:00 UTC');
    expect(formatSlot(null)).toBe('-');
    expect(formatSlot('nope')).toBe('nope');
  });
});
