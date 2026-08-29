import { buildAlertCountSearchBody, buildAlertListSearchBody } from './alerts';

describe('alert route exact totals', () => {
  test('requests exact total hits for the paged Workbench queue', () => {
    const body = buildAlertListSearchBody({
      from_offset: 20, size: 20, sortField: '@timestamp', sortDirection: 'desc',
      statuses: 'open',
    });

    expect(body.track_total_hits).toBe(true);
    expect(body.from).toBe(20);
    expect(body.size).toBe(20);
  });

  test('requests exact total hits for summary counts', () => {
    const body = buildAlertCountSearchBody({ from: '2026-08-29T00:00:00.000Z' });

    expect(body.track_total_hits).toBe(true);
    expect(body.size).toBe(0);
    expect(body.aggs.status_counts.terms.field).toBe('status');
  });
});
