import { ACTIVITY_READ_ALIAS, ALERT_STATUS_INDEX, CASES_INDEX, SLA_BANDS } from '../../common/constants';
import { DEFAULT_SLA_POLICY } from './sla/policy';
import { bandClause, breachQuery, thresholdInstant } from './sla/escalation';
import {
  collectReportHits,
  deriveAlertTiming,
  loadReportActivity,
  loadReportActivityCoverage,
  mergeReportHistory,
  parseSlaCurrentlyBreached,
  parseSlaEventsInPeriod,
  REPORT_ALERT_SAMPLE_SORT,
  SLA_ESCALATION_BUCKETS_MAX,
  slaCurrentlyBreachedRequest,
  slaEventsInPeriodRequest,
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

describe('SLA enforcement request builders (step 3.4)', () => {
  const now = '2026-11-21T10:00:00.000Z';

  test('currently breached: bound to now, active statuses, stamp OR due date in the past, one filter per SLA band', () => {
    const alerts = slaCurrentlyBreachedRequest('alert', now);
    expect(alerts.index).toBe(ALERT_STATUS_INDEX);
    expect(alerts.body.size).toBe(0);
    expect(alerts.body.track_total_hits).toBe(true);
    const [status, breached] = alerts.body.query.bool.filter;
    expect(status).toEqual({ terms: { status: ['open', 'in_progress'] } });
    expect(breached.bool.minimum_should_match).toBe(1);
    expect(breached.bool.should).toEqual([
      { exists: { field: 'sla.breached_at' } },
      { range: { 'reporting.sla_due_at': { lt: now } } },
    ]);
    expect(JSON.stringify(alerts.body)).not.toContain('@timestamp');
    expect(Object.keys(alerts.body.aggs.by_band.filters.filters)).toEqual([...SLA_BANDS]);
    expect(alerts.body.aggs.by_band.filters.filters.critical).toEqual(bandClause('alert', 'critical'));

    const cases = slaCurrentlyBreachedRequest('case', now);
    expect(cases.index).toBe(CASES_INDEX);
    expect(cases.body.query.bool.filter[0]).toEqual({ bool: { must_not: [{ term: { status: 'closed' } }] } });
    expect(cases.body.query.bool.filter[1].bool.should[1]).toEqual({ range: { sla_due_at: { lt: now } } });
    expect(cases.body.aggs.by_band.filters.filters.high).toEqual({ term: { severity: 'high' } });
    // Without a policy there is no missing-due fallback for cases.
    expect(cases.body.query.bool.filter[1].bool.should).toHaveLength(2);
    // A missing alias or index answers zero, never index_not_found_exception.
    for (const request of [alerts, cases]) {
      expect(request.ignore_unavailable).toBe(true);
      expect(request.allow_no_indices).toBe(true);
    }
  });

  test('currently breached cases: with a policy, a case without sla_due_at is breached once created_at + its band resolve target has passed (the scanner clause)', () => {
    const cases = slaCurrentlyBreachedRequest('case', now, DEFAULT_SLA_POLICY);
    const should = cases.body.query.bool.filter[1].bool.should;
    expect(should).toHaveLength(2 + SLA_BANDS.length);
    const expected = SLA_BANDS.map((band) => ({
      bool: {
        filter: [bandClause('case', band), { range: { created_at: { lte: thresholdInstant(DEFAULT_SLA_POLICY, band, 100, now) } } }],
        must_not: [{ exists: { field: 'sla_due_at' } }],
      },
    }));
    expect(should.slice(2)).toEqual(expected);
    // Byte-for-byte the clauses the escalation scanner's breach pass uses.
    const scanner = breachQuery('case', now, DEFAULT_SLA_POLICY).bool.filter[1].bool.should.slice(1);
    expect(should.slice(2)).toEqual(scanner);
    // Alerts never get the fallback: the due backfill materializes reporting.sla_due_at.
    expect(slaCurrentlyBreachedRequest('alert', now, DEFAULT_SLA_POLICY).body.query.bool.filter[1].bool.should).toHaveLength(2);
  });

  test('parseSlaCurrentlyBreached sums alerts and cases per band and reads the exact totals', () => {
    const alertResult = { body: { hits: { total: { value: 7 } }, aggregations: { by_band: { buckets: { critical: { doc_count: 4 }, high: { doc_count: 3 } } } } } };
    const caseResult = { body: { hits: { total: { value: 2 } }, aggregations: { by_band: { buckets: { critical: { doc_count: 1 }, low: { doc_count: 1 } } } } } };
    expect(parseSlaCurrentlyBreached(alertResult, caseResult, now)).toEqual({
      asOf: now,
      alerts: 7,
      cases: 2,
      byBand: { critical: 5, high: 3, medium: 0, low: 1 },
    });
    expect(parseSlaCurrentlyBreached(undefined, { body: {} }, now)).toEqual({
      asOf: now,
      alerts: 0,
      cases: 0,
      byBand: { critical: 0, high: 0, medium: 0, low: 0 },
    });
  });

  test('events in period: range-bound audit query on the activity alias, bounded terms buckets on the indexed from/to keywords', () => {
    const request = slaEventsInPeriodRequest({ from: '2026-11-14T00:00:00.000Z', to: now });
    expect(request.index).toBe(ACTIVITY_READ_ALIAS);
    expect(request.ignore_unavailable).toBe(true);
    expect(request.allow_no_indices).toBe(true);
    expect(request.body.size).toBe(0);
    expect(request.body.query.bool.filter).toEqual([
      { term: { event_type: 'audit' } },
      { terms: { action: ['sla_breached', 'sla_escalated'] } },
      { range: { timestamp: { gte: '2026-11-14T00:00:00.000Z', lte: now } } },
    ]);
    expect(request.body.aggs.breaches.filter).toEqual({ term: { action: 'sla_breached' } });
    expect(request.body.aggs.breaches.aggs.by_target.terms).toEqual({ field: 'target_type', size: 2 });
    expect(request.body.aggs.escalations.filter).toEqual({ term: { action: 'sla_escalated' } });
    const byEscalation = request.body.aggs.escalations.aggs.by_escalation;
    expect(byEscalation.terms).toEqual({ field: 'from', size: SLA_ESCALATION_BUCKETS_MAX, missing: '' });
    expect(SLA_ESCALATION_BUCKETS_MAX).toBe(50);
    expect(byEscalation.aggs.name.terms).toEqual({ field: 'to', size: 1 });
    // `details` is unindexed (enabled: false) and must never be aggregated.
    expect(JSON.stringify(request.body)).not.toContain('details');
  });

  test('parseSlaEventsInPeriod reads breach totals by target and escalations with their recorded names', () => {
    const result = {
      body: {
        aggregations: {
          breaches: { doc_count: 9, by_target: { buckets: [{ key: 'alert', doc_count: 6 }, { key: 'case', doc_count: 3 }] } },
          escalations: {
            doc_count: 5,
            by_escalation: {
              buckets: [
                { key: 'crit-unassigned', doc_count: 4, name: { buckets: [{ key: 'Critical unassigned', doc_count: 4 }] } },
                { key: 'stale', doc_count: 1, name: { buckets: [] } },
              ],
            },
          },
        },
      },
    };
    expect(parseSlaEventsInPeriod(result)).toEqual({
      breaches: { total: 9, alerts: 6, cases: 3 },
      escalations: {
        total: 5,
        byEscalation: [
          { id: 'crit-unassigned', name: 'Critical unassigned', count: 4 },
          { id: 'stale', name: 'stale', count: 1 },
        ],
      },
    });
    expect(parseSlaEventsInPeriod({ body: {} })).toEqual({
      breaches: { total: 0, alerts: 0, cases: 0 },
      escalations: { total: 0, byEscalation: [] },
    });
  });
});

describe('dispositions request builder and parser (step 2.4)', () => {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { dispositionsRequest, parseDispositions } = require('./report_metrics');
  const range = { from: '2026-11-14T00:00:00.000Z', to: '2026-11-21T00:00:00.000Z' };

  test('one exact, bounded aggregation over alerts closed in the range', () => {
    const request = dispositionsRequest(range);
    expect(request.index).toBe('wazuh-alert-status-v2-read');
    expect(request.ignore_unavailable).toBe(true);
    expect(request.allow_no_indices).toBe(true);
    expect(request.body.size).toBe(0);
    expect(request.body.query.bool.filter).toEqual([
      { term: { status: 'closed' } },
      { range: { 'reporting.closed_at': { gte: range.from, lte: range.to } } },
    ]);
    expect(request.body.aggs.by_disposition.terms).toEqual({ field: 'disposition', size: 5, missing: 'undetermined' });
    expect(request.body.aggs.by_rule.terms).toEqual({ field: 'rule.id', size: 25 });
    expect(request.body.aggs.by_rule.aggs.by_disposition.terms).toEqual({ field: 'disposition', size: 5, missing: 'undetermined' });
    expect(request.body.aggs.by_rule.aggs.description.terms).toEqual({ field: 'rule.description.keyword', size: 1 });
  });

  test('parses every taxonomy value (zero when absent), folds unknown keys into undetermined, and computes the rate per rule', () => {
    const result = {
      body: {
        aggregations: {
          by_disposition: { buckets: [
            { key: 'false_positive', doc_count: 6 },
            { key: 'true_positive', doc_count: 3 },
            { key: 'undetermined', doc_count: 2 },
            { key: 'legacy', doc_count: 1 },
          ] },
          by_rule: { buckets: [
            { key: '5710', doc_count: 8, description: { buckets: [{ key: 'sshd: brute force', doc_count: 8 }] }, by_disposition: { buckets: [{ key: 'false_positive', doc_count: 6 }, { key: 'true_positive', doc_count: 2 }] } },
            { key: '100002', doc_count: 4, description: { buckets: [] }, by_disposition: { buckets: [{ key: 'true_positive', doc_count: 1 }, { key: 'undetermined', doc_count: 3 }] } },
          ] },
        },
      },
    };
    expect(parseDispositions(result)).toEqual({
      dispositions: { true_positive: 3, false_positive: 6, benign: 0, duplicate: 0, undetermined: 3 },
      falsePositiveByRule: [
        { rule_id: '5710', description: 'sshd: brute force', closed: 8, false_positive: 6, rate: 0.75 },
        { rule_id: '100002', description: null, closed: 4, false_positive: 0, rate: 0 },
      ],
    });
    expect(parseDispositions({ body: {} })).toEqual({
      dispositions: { true_positive: 0, false_positive: 0, benign: 0, duplicate: 0, undetermined: 0 },
      falsePositiveByRule: [],
    });
  });
});
