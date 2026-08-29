import {
  collectReportHits,
  deriveAlertTiming,
  loadReportActivity,
  loadReportActivityCoverage,
  mergeReportHistory,
  REPORT_ALERT_SAMPLE_SORT,
} from './report_metrics';

const source = (overrides: any = {}) => ({
  '@timestamp': '2026-08-28T10:00:00.000Z',
  status: 'closed',
  assigned_to: 'current-owner',
  history: [],
  ...overrides,
});

describe('report metric history compatibility', () => {
  test('merges embedded and activity events and deduplicates exact copies', () => {
    const close = { timestamp: '2026-08-28T11:00:00.000Z', user: 'rule', action: 'status_change', to: 'closed' };
    const assignment = { timestamp: '2026-08-28T10:10:00.000Z', user: 'analyst', action: 'assignment_change', to: 'alice' };
    expect(mergeReportHistory([close, assignment], [assignment])).toEqual([assignment, close]);
  });

  test('preserves embedded close when activity contains only an assignment', () => {
    const result = deriveAlertTiming(
      source({ history: [{ timestamp: '2026-08-28T11:00:00.000Z', action: 'status_change', to: 'closed' }] }),
      [{ timestamp: '2026-08-28T10:10:00.000Z', action: 'assignment_change', to: 'alice' }]
    );
    expect(result.resolveMinutes).toBe(60);
    expect(result.assignMinutes).toBe(10);
    expect(result.assigneeAtClose).toBe('alice');
  });

  test('does not count a reopened alert as resolved', () => {
    const result = deriveAlertTiming(source({
      status: 'open',
      history: [
        { timestamp: '2026-08-28T11:00:00.000Z', action: 'status_change', to: 'closed' },
        { timestamp: '2026-08-28T12:00:00.000Z', action: 'status_change', to: 'open' },
      ],
    }));
    expect(result.resolveMinutes).toBeNull();
  });

  test('attributes resolution to the assignee at close, not a later assignee', () => {
    const result = deriveAlertTiming(source({
      assigned_to: 'bob',
      history: [
        { timestamp: '2026-08-28T10:10:00.000Z', action: 'assignment_change', to: 'alice' },
        { timestamp: '2026-08-28T11:00:00.000Z', action: 'status_change', to: 'closed' },
        { timestamp: '2026-08-28T12:00:00.000Z', action: 'assignment_change', to: 'bob' },
      ],
    }));
    expect(result.assigneeAtClose).toBe('alice');
  });

  test('does not attribute a close when the only known assignment happened later', () => {
    const result = deriveAlertTiming(source({
      assigned_to: 'bob',
      history: [
        { timestamp: '2026-08-28T11:00:00.000Z', action: 'status_change', to: 'closed' },
        { timestamp: '2026-08-28T12:00:00.000Z', action: 'assignment_change', to: 'bob' },
      ],
    }));
    expect(result.assigneeAtClose).toBeNull();
  });

  test('excludes events after the report end', () => {
    const result = deriveAlertTiming(
      source({ history: [{ timestamp: '2026-08-28T13:00:00.000Z', action: 'status_change', to: 'closed' }] }),
      [],
      Date.parse('2026-08-28T12:00:00.000Z')
    );
    expect(result.resolveMinutes).toBeNull();
  });

  test('orders equal-timestamp events deterministically', () => {
    const a = { timestamp: '2026-08-28T11:00:00.000Z', action: 'status_change', to: 'closed' };
    const b = { timestamp: '2026-08-28T11:00:00.000Z', action: 'assignment_change', to: 'alice' };
    expect(mergeReportHistory([a, b])).toEqual(mergeReportHistory([b, a]));
  });
});

describe('report scroll collection', () => {
  function pagedClient(pages: any[][]) {
    const remaining = pages.slice(1);
    return {
      search: jest.fn(async () => ({ body: { _scroll_id: 'report-scroll', hits: { hits: pages[0] || [] } } })),
      scroll: jest.fn(async () => ({ body: { _scroll_id: 'report-scroll', hits: { hits: remaining.shift() || [] } } })),
      clearScroll: jest.fn(async () => ({})),
    };
  }

  test('collects more than 2000 cases without count divergence and clears the scroll', async () => {
    const hits = Array.from({ length: 2501 }, (_, i) => ({ _id: `case-${i}` }));
    const client = pagedClient([hits.slice(0, 1000), hits.slice(1000, 2000), hits.slice(2000)]);
    await expect(collectReportHits(client, { index: 'cases', size: 1000, body: {} })).resolves.toHaveLength(2501);
    expect(client.clearScroll).toHaveBeenCalledWith({ scrollId: 'report-scroll' });
  });

  test('defines a deterministic alert timing sample order', () => {
    expect(REPORT_ALERT_SAMPLE_SORT).toEqual([
      { '@timestamp': { order: 'asc' } },
      { alert_uid: { order: 'asc' } },
    ]);
    expect(JSON.stringify(REPORT_ALERT_SAMPLE_SORT)).not.toContain('_id');
  });

  test('loads more than 10000 activity events without truncation and clears the scroll', async () => {
    const hits = Array.from({ length: 10001 }, (_, i) => ({
      _source: { target_id: 'alert-1', timestamp: new Date(i).toISOString(), action: 'status_change' },
    }));
    const pages = Array.from({ length: 11 }, (_, i) => hits.slice(i * 1000, (i + 1) * 1000));
    const client = pagedClient(pages);
    const activity = await loadReportActivity(client, 'activity', ['alert-1']);
    expect(activity['alert-1']).toHaveLength(10001);
    expect(client.clearScroll).toHaveBeenCalledWith({ scrollId: 'report-scroll' });
  });

  test('propagates a scroll failure after clearing the scroll', async () => {
    const client = pagedClient([[{ _id: 'case-1' }]]);
    client.scroll.mockRejectedValueOnce(new Error('expired'));
    await expect(collectReportHits(client, { index: 'cases', body: {} })).rejects.toThrow('expired');
    expect(client.clearScroll).toHaveBeenCalledWith({ scrollId: 'report-scroll' });
  });

  test('propagates incomplete activity coverage as explicit truncation', async () => {
    const client = pagedClient([[{ _source: { target_id: 'alert-1' } }]]);
    client.scroll.mockRejectedValueOnce(new Error('expired'));
    await expect(loadReportActivityCoverage(client, 'activity', ['alert-1'])).resolves.toEqual({
      byAlert: {},
      truncated: true,
    });
    expect(client.clearScroll).toHaveBeenCalledWith({ scrollId: 'report-scroll' });
  });
});
