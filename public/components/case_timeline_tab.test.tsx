/**
 * @jest-environment jsdom
 */
import React from 'react';
import { configure, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { CaseTimelineEntry } from '../../common';
import { CaseTimelineTab, groupTimelineByDay, timelineDayKey } from './case_timeline_tab';

configure({ testIdAttribute: 'data-test-subj' });

const ALERT: CaseTimelineEntry = { id: 'alert:a1', kind: 'alert', at: '2026-11-20T08:00:00.000Z', actor: null, title: 'sshd: brute force', details: 'rule 5712 · on web-01 · high (10)', ref: { alert_id: 'a1' }, severity_band: 'high' };
const COMMENT: CaseTimelineEntry = { id: 'activity:cm1', kind: 'comment', at: '2026-11-20T09:00:00.000Z', actor: 'alice', title: 'Comment', details: 'Blocked at the firewall', ref: { activity_id: 'cm1' } };
const AUDIT: CaseTimelineEntry = { id: 'activity:au1', kind: 'audit', at: '2026-11-21T10:00:00.000Z', actor: 'bob', title: 'status change: open → in_progress', details: null, ref: { activity_id: 'au1' }, action: 'status_change' };
const SLA: CaseTimelineEntry = { id: 'activity:au2', kind: 'audit', at: '2026-11-21T11:00:00.000Z', actor: 'system', title: 'sla breached: 2026-11-21T10:30:00.000Z', details: null, ref: { activity_id: 'au2' }, action: 'sla_breached' };
const TASK: CaseTimelineEntry = { id: 'task_due:t1', kind: 'task_due', at: '2026-11-22T12:00:00.000Z', actor: 'carol', title: 'Task due: Collect logs', details: 'owner carol', ref: { task_id: 't1' } };

function service(pages: Array<any | Error>) {
  let call = 0;
  return {
    fetchCaseTimeline: jest.fn(async () => {
      const page = pages[Math.min(call, pages.length - 1)];
      call += 1;
      if (page instanceof Error) throw page;
      return page;
    }),
  } as any;
}

describe('groupTimelineByDay', () => {
  test('groups consecutive entries of one calendar day and keeps the order', () => {
    const groups = groupTimelineByDay([ALERT, COMMENT, AUDIT, SLA, TASK]);
    expect(groups.map((group) => group.entries.map((entry) => entry.id))).toEqual([
      ['alert:a1', 'activity:cm1'],
      ['activity:au1', 'activity:au2'],
      ['task_due:t1'],
    ]);
    expect(groups[0].day).toBe(timelineDayKey(ALERT.at));
    expect(timelineDayKey('not a date')).toBe('Unknown date');
    expect(groupTimelineByDay([])).toEqual([]);
  });
});

describe('CaseTimelineTab', () => {
  test('renders the entries grouped by day with kind badges, actors and details; alert rows open the alert', async () => {
    const apiService = service([{ entries: [ALERT, COMMENT, AUDIT, SLA, TASK], next_cursor: null, truncated_alerts: false }]);
    const onOpenAlert = jest.fn();
    const onError = jest.fn();
    render(<CaseTimelineTab caseId="case-1" apiService={apiService} onError={onError} onOpenAlert={onOpenAlert} />);
    await waitFor(() => expect(screen.getByTestId('wamCaseTimeline')).toBeTruthy());
    expect(apiService.fetchCaseTimeline).toHaveBeenCalledWith('case-1', { cursor: null });
    expect(screen.getAllByTestId(/^wamCaseTimelineDay-/)).toHaveLength(3);
    expect(screen.getAllByTestId(/^wamCaseTimelineRow-/).map((row) => row.getAttribute('data-test-subj'))).toEqual([
      'wamCaseTimelineRow-alert:a1', 'wamCaseTimelineRow-activity:cm1', 'wamCaseTimelineRow-activity:au1', 'wamCaseTimelineRow-activity:au2', 'wamCaseTimelineRow-task_due:t1',
    ]);
    expect(screen.getByTestId('wamCaseTimelineBadge-alert:a1').textContent).toBe('Alert · High');
    expect(screen.getByTestId('wamCaseTimelineBadge-activity:cm1').textContent).toBe('Comment');
    expect(screen.getByTestId('wamCaseTimelineBadge-activity:au1').textContent).toBe('Status');
    expect(screen.getByTestId('wamCaseTimelineBadge-activity:au2').textContent).toBe('SLA breached');
    expect(screen.getByTestId('wamCaseTimelineBadge-task_due:t1').textContent).toBe('Task due');
    expect(screen.getByTestId('wamCaseTimelineActor-activity:cm1').textContent).toBe('alice');
    expect(screen.queryByTestId('wamCaseTimelineActor-alert:a1')).toBeNull();
    expect(screen.getByTestId('wamCaseTimelineDetails-activity:cm1').textContent).toBe('Blocked at the firewall');
    expect(screen.queryByTestId('wamCaseTimelineDetails-activity:au1')).toBeNull();
    expect(screen.getByTestId('wamCaseTimelineRow-alert:a1').className).toContain('wamCaseTimelineRow--alert');
    expect(screen.queryByTestId('wamCaseTimelineLoadMore')).toBeNull();
    expect(screen.queryByTestId('wamCaseTimelineTruncatedAlerts')).toBeNull();
    expect(screen.queryByTestId('wamCaseTimelineEmpty')).toBeNull();

    fireEvent.click(screen.getByTestId('wamCaseTimelineOpenAlert-alert:a1'));
    expect(onOpenAlert).toHaveBeenCalledWith('a1');
    expect(screen.queryByTestId('wamCaseTimelineOpenAlert-activity:cm1')).toBeNull();
    expect(onError).not.toHaveBeenCalled();
  });

  test('"Load more" follows next_cursor, appends without duplicates and shows the alert-cap notice', async () => {
    const apiService = service([
      { entries: [ALERT, COMMENT], next_cursor: 'cursor-1', truncated_alerts: true },
      { entries: [COMMENT, AUDIT], next_cursor: null, truncated_alerts: true },
    ]);
    render(<CaseTimelineTab caseId="case-1" apiService={apiService} onError={jest.fn()} pageSize={2} />);
    await waitFor(() => expect(screen.getByTestId('wamCaseTimelineLoadMore')).toBeTruthy());
    expect(apiService.fetchCaseTimeline).toHaveBeenCalledWith('case-1', { cursor: null, limit: 2 });
    expect(screen.getByTestId('wamCaseTimelineTruncatedAlerts')).toBeTruthy();
    expect(screen.getAllByTestId(/^wamCaseTimelineRow-/)).toHaveLength(2);

    fireEvent.click(screen.getByTestId('wamCaseTimelineLoadMore'));
    await waitFor(() => expect(screen.getAllByTestId(/^wamCaseTimelineRow-/)).toHaveLength(3));
    expect(apiService.fetchCaseTimeline).toHaveBeenLastCalledWith('case-1', { cursor: 'cursor-1', limit: 2 });
    expect(screen.queryByTestId('wamCaseTimelineLoadMore')).toBeNull();
    // Alert rows without a handler are plain text.
    expect(screen.queryByTestId('wamCaseTimelineOpenAlert-alert:a1')).toBeNull();
    expect(screen.getByTestId('wamCaseTimelineTitle-alert:a1').textContent).toBe('sshd: brute force');
  });

  test('a failed load shows an in-tab error with Retry; the empty state afterwards', async () => {
    const apiService = service([Object.assign(new Error('nope'), { body: { message: 'Case c1 was not found.' } }), { entries: [], next_cursor: null, truncated_alerts: false }]);
    const onError = jest.fn();
    render(<CaseTimelineTab caseId="case-1" apiService={apiService} onError={onError} />);
    await waitFor(() => expect(screen.getByTestId('wamCaseTimelineError')).toBeTruthy());
    expect(screen.getByTestId('wamCaseTimelineError').textContent).toContain('Case c1 was not found.');
    expect(onError).not.toHaveBeenCalled();

    fireEvent.click(screen.getByTestId('wamCaseTimelineRetry'));
    await waitFor(() => expect(screen.getByTestId('wamCaseTimelineEmpty')).toBeTruthy());
    expect(screen.queryByTestId('wamCaseTimelineError')).toBeNull();
    expect(apiService.fetchCaseTimeline).toHaveBeenCalledTimes(2);
  });

  test('a "Load more" failure is reported through onError and the loaded entries stay', async () => {
    const apiService = service([{ entries: [ALERT], next_cursor: 'cursor-1', truncated_alerts: false }, new Error('boom')]);
    const onError = jest.fn();
    render(<CaseTimelineTab caseId="case-1" apiService={apiService} onError={onError} />);
    await waitFor(() => expect(screen.getByTestId('wamCaseTimelineLoadMore')).toBeTruthy());
    fireEvent.click(screen.getByTestId('wamCaseTimelineLoadMore'));
    await waitFor(() => expect(onError).toHaveBeenCalledWith('boom'));
    expect(screen.getAllByTestId(/^wamCaseTimelineRow-/)).toHaveLength(1);
    expect(screen.getByTestId('wamCaseTimelineLoadMore')).toBeTruthy();
  });

  test('a load that outlives the tab neither touches state nor raises an error', async () => {
    let resolve: (value: any) => void = () => {};
    const apiService = { fetchCaseTimeline: jest.fn(() => new Promise((r) => { resolve = r; })) } as any;
    const onError = jest.fn();
    const { unmount } = render(<CaseTimelineTab caseId="case-1" apiService={apiService} onError={onError} />);
    expect(screen.getByTestId('wamCaseTimelineLoading')).toBeTruthy();
    unmount();
    resolve({ entries: [ALERT], next_cursor: null, truncated_alerts: false });
    await new Promise((r) => setTimeout(r, 0));
    expect(onError).not.toHaveBeenCalled();
  });
});
