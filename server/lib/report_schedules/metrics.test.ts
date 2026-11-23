import { ACTIVITY_READ_ALIAS, ALERT_STATUS_INDEX, CASES_INDEX } from '../../../common';
import { DEFAULT_SLA_POLICY, primeSlaPolicyCache } from '../sla/policy';
import { collectDispositionMetrics, collectReportMetrics, collectSlaEnforcementMetrics } from './metrics';

const range = { from: '2026-11-14T00:00:00.000Z', to: '2026-11-21T00:00:00.000Z' };
const now = '2026-11-21T10:00:00.000Z';

const empty = { body: { hits: { total: { value: 0 } }, aggregations: {} } };

/** A client that answers every search with a canned body per index and records the request. */
function clientWith(answers: Record<string, any> = {}) {
  const searches: any[] = [];
  return {
    searches,
    search: jest.fn(async (request: any) => {
      searches.push(request);
      const answer = answers[request.index];
      if (answer instanceof Error) throw answer;
      return answer || empty;
    }),
    get: jest.fn(async () => {
      throw Object.assign(new Error('not found'), { meta: { statusCode: 404 } });
    }),
  };
}

describe('collectSlaEnforcementMetrics', () => {
  test('sends the now-bound breached queries and the range-bound activity query, and parses all three', async () => {
    const client = clientWith({
      [ALERT_STATUS_INDEX]: { body: { hits: { total: { value: 3 } }, aggregations: { by_band: { buckets: { critical: { doc_count: 2 }, high: { doc_count: 1 } } } } } },
      [CASES_INDEX]: { body: { hits: { total: { value: 1 } }, aggregations: { by_band: { buckets: { high: { doc_count: 1 } } } } } },
      [ACTIVITY_READ_ALIAS]: {
        body: {
          aggregations: {
            breaches: { doc_count: 4, by_target: { buckets: [{ key: 'alert', doc_count: 3 }, { key: 'case', doc_count: 1 }] } },
            escalations: {
              doc_count: 2,
              by_escalation: { buckets: [{ key: 'crit', doc_count: 2, name: { buckets: [{ key: 'Critical unassigned', doc_count: 2 }] } }] },
            },
          },
        },
      },
    });
    const result = await collectSlaEnforcementMetrics(client, range, now);
    expect(result).toEqual({
      slaCurrentlyBreached: { asOf: now, alerts: 3, cases: 1, byBand: { critical: 2, high: 2, medium: 0, low: 0 } },
      slaBreachesInPeriod: { total: 4, alerts: 3, cases: 1 },
      slaEscalationsInPeriod: { total: 2, byEscalation: [{ id: 'crit', name: 'Critical unassigned', count: 2 }] },
    });

    expect(client.searches.map((s) => s.index)).toEqual([ALERT_STATUS_INDEX, CASES_INDEX, ACTIVITY_READ_ALIAS]);
    const [alerts, cases, events] = client.searches;
    // Currently breached is bound to `now`, never to the report range.
    for (const request of [alerts, cases]) {
      const text = JSON.stringify(request.body);
      expect(text).toContain(now);
      expect(text).not.toContain(range.from);
      expect(request.body.size).toBe(0);
      expect(request.body.track_total_hits).toBe(true);
    }
    expect(alerts.body.query.bool.filter[1].bool.should[1]).toEqual({ range: { 'reporting.sla_due_at': { lt: now } } });
    expect(cases.body.query.bool.filter[1].bool.should[1]).toEqual({ range: { sla_due_at: { lt: now } } });
    // The event counts are bound to the range and to the audit actions.
    expect(events.body.query.bool.filter).toContainEqual({ range: { timestamp: { gte: range.from, lte: range.to } } });
    expect(events.body.query.bool.filter).toContainEqual({ terms: { action: ['sla_breached', 'sla_escalated'] } });
    expect(events.body.aggs.escalations.aggs.by_escalation.terms.size).toBe(50);
  });

  test('a failed query is an error, never a silent zero', async () => {
    const client = clientWith({ [ACTIVITY_READ_ALIAS]: new Error('search_phase_execution_exception') });
    await expect(collectSlaEnforcementMetrics(client, range, now)).rejects.toThrow(
      'Exact SLA enforcement aggregation failed: search_phase_execution_exception'
    );
  });

  test('a missing activity alias or status index is asked to answer zero hits, not index_not_found_exception', async () => {
    const client = clientWith();
    await collectSlaEnforcementMetrics(client, range, now);
    expect(client.searches).toHaveLength(3);
    for (const request of client.searches) {
      expect(request.ignore_unavailable).toBe(true);
      expect(request.allow_no_indices).toBe(true);
    }
  });

  test('passes the SLA policy to the case query so cases without sla_due_at use the scanner fallback', async () => {
    const client = clientWith();
    await collectSlaEnforcementMetrics(client, range, now, DEFAULT_SLA_POLICY);
    const cases = client.searches.find((s) => s.index === CASES_INDEX);
    const should = cases.body.query.bool.filter[1].bool.should;
    expect(should).toHaveLength(6);
    expect(JSON.stringify(should.slice(2))).toContain('created_at');
    const withoutPolicy = clientWith();
    await collectSlaEnforcementMetrics(withoutPolicy, range, now);
    expect(withoutPolicy.searches.find((s) => s.index === CASES_INDEX).body.query.bool.filter[1].bool.should).toHaveLength(2);
  });
});

describe('collectReportMetrics', () => {
  beforeEach(() => primeSlaPolicyCache(DEFAULT_SLA_POLICY));

  test('carries the SLA enforcement figures next to the range-bound metrics', async () => {
    const client = clientWith();
    const metrics = await collectReportMetrics(client, range, undefined, now);
    expect(metrics.from).toBe(range.from);
    expect(metrics.slaCurrentlyBreached).toEqual({ asOf: now, alerts: 0, cases: 0, byBand: { critical: 0, high: 0, medium: 0, low: 0 } });
    expect(metrics.slaBreachesInPeriod).toEqual({ total: 0, alerts: 0, cases: 0 });
    expect(metrics.slaEscalationsInPeriod).toEqual({ total: 0, byEscalation: [] });
    const activitySearches = client.searches.filter((s) => s.index === ACTIVITY_READ_ALIAS);
    expect(activitySearches).toHaveLength(1);
    // The loaded policy reaches the case "currently breached" query (missing-due fallback).
    const caseBreached = client.searches.find((s) => s.index === CASES_INDEX && s.body?.aggs?.by_band);
    expect(caseBreached.body.query.bool.filter[1].bool.should).toHaveLength(6);
    expect(activitySearches[0].body.query.bool.filter).toContainEqual({ range: { timestamp: { gte: range.from, lte: range.to } } });
  });

  test('carries the dispositions and the false-positive rate by rule (step 2.4) from one closed-in-range aggregation', async () => {
    const client = clientWith();
    const metrics = await collectReportMetrics(client, range, undefined, now);
    expect(metrics.dispositions).toEqual({ true_positive: 0, false_positive: 0, benign: 0, duplicate: 0, undetermined: 0 });
    expect(metrics.falsePositiveByRule).toEqual([]);
    const request = client.searches.find((s) => s.body?.aggs?.by_disposition);
    expect(request.index).toBe(ALERT_STATUS_INDEX);
    expect(request.body.query.bool.filter).toEqual([
      { term: { status: 'closed' } },
      { range: { 'reporting.closed_at': { gte: range.from, lte: range.to } } },
    ]);
  });
});

describe('collectDispositionMetrics (step 2.4)', () => {
  test('parses the aggregation and fails loudly instead of answering zero on a query error', async () => {
    const client = clientWith({
      [ALERT_STATUS_INDEX]: { body: { hits: { total: { value: 4 } }, aggregations: {
        by_disposition: { buckets: [{ key: 'false_positive', doc_count: 3 }, { key: 'benign', doc_count: 1 }] },
        by_rule: { buckets: [{ key: '5710', doc_count: 4, description: { buckets: [{ key: 'sshd', doc_count: 4 }] }, by_disposition: { buckets: [{ key: 'false_positive', doc_count: 3 }, { key: 'benign', doc_count: 1 }] } }] },
      } } },
    });
    await expect(collectDispositionMetrics(client, range)).resolves.toEqual({
      dispositions: { true_positive: 0, false_positive: 3, benign: 1, duplicate: 0, undetermined: 0 },
      falsePositiveByRule: [{ rule_id: '5710', description: 'sshd', closed: 4, false_positive: 3, rate: 0.75 }],
    });
    const failing = clientWith({ [ALERT_STATUS_INDEX]: new Error('search_phase_execution_exception') });
    await expect(collectDispositionMetrics(failing, range)).rejects.toThrow('Exact disposition aggregation failed: search_phase_execution_exception');
  });
});
