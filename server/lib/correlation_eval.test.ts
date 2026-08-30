import { ALERTS_READ_ALIAS, ALERT_STATUS_INDEX, CASES_INDEX, RULES_INDEX } from '../../common';
import {
  evaluateCorrelationRules,
  evaluateRuleAtAlert,
  normalizeStoredAutomationRule,
  transitionAutomationTrigger,
} from './correlation_eval';
import * as automationCaseRouting from './automation_case_routing';

const logger = { error: jest.fn(), warn: jest.fn(), info: jest.fn() } as any;
const physicalIndex = 'wazuh-alert-status-v2-000001';
const alertSource = {
  '@timestamp': '2026-08-28T12:00:00.000Z',
  ingested_at: '2026-08-28T12:00:01.000Z',
  state_version: 4,
  status: 'open',
  assigned_to: null,
  data: { srcip: '10.0.0.1' },
  rule: { id: '5502', groups: [] },
  agent: {},
};

describe('evaluateCorrelationRules outcome contract', () => {
  beforeEach(() => jest.clearAllMocks());

  test('returns retryable failure when rules cannot be loaded', async () => {
    const client = { search: jest.fn(async () => { throw new Error('rules unavailable'); }) };

    await expect(evaluateCorrelationRules(client, [{ _id: 'a1', _source: alertSource }], logger)).resolves.toEqual(
      expect.objectContaining({
        status: 'retryable_failure',
        failures: [expect.objectContaining({ stage: 'rule_loading', message: 'rules unavailable' })],
      })
    );
  });

  test('treats an immutable queued snapshot as authoritative without loading newer rules', async () => {
    const client = { search: jest.fn() };
    const outcome = await evaluateCorrelationRules(
      client,
      [{ _id: 'a1', _source: alertSource }],
      logger,
      undefined,
      { id: 'snapshot-1', rules: [], revisions: [] }
    );
    expect(outcome).toEqual(expect.objectContaining({ status: 'terminal_success', appliedRuleIds: [] }));
    expect(client.search).not.toHaveBeenCalled();
  });

  test('returns retryable failure when any action bulk item fails', async () => {
    const rule = {
      name: 'Assign',
      enabled: true,
      match: {},
      trigger: { type: 'per_alert' },
      actions: { createCase: false, setStatus: 'in_progress', assignTo: 'tier-1' },
      safety: { acknowledgeMatchAll: true },
    };
    const client: any = {
      search: jest.fn(async (request: any) => {
        if (request.index === RULES_INDEX) return { body: { hits: { hits: [{ _id: 'rule-1', _source: rule }] } } };
        if (request.index === ALERTS_READ_ALIAS && request.body.query.ids) {
          return { body: { hits: { hits: [{ _id: 'a1', _index: physicalIndex, _source: alertSource }] } } };
        }
        throw new Error(`Unexpected search index ${request.index}`);
      }),
      bulk: jest.fn(async () => ({
        body: { errors: true, items: [{ update: { status: 429, error: { reason: 'rejected' } } }] },
      })),
      update: jest.fn(),
    };

    const outcome = await evaluateCorrelationRules(client, [{ _id: 'a1', _source: alertSource }], logger);

    expect(outcome).toEqual(
      expect.objectContaining({
        status: 'retryable_failure',
        failures: [expect.objectContaining({ stage: 'action_mutation', message: expect.stringContaining('rejected') })],
      })
    );
    expect(client.bulk).toHaveBeenCalledTimes(1);
  });

  test('fails closed when the open-case lookup cannot be verified', async () => {
    const rule = {
      name: 'Burst',
      enabled: true,
      trigger: { type: 'burst', entity: 'srcip', threshold: 1, windowMinutes: 5 },
      actions: { createCase: true },
      match: {},
    };
    const client: any = {
      search: jest.fn(async (request: any) => {
        if (request.index === RULES_INDEX) return { body: { hits: { hits: [{ _id: 'rule-1', _source: rule }] } } };
        if (request.index === ALERTS_READ_ALIAS && request.body.query.ids) {
          return { body: { hits: { hits: [{ _id: 'a1', _index: physicalIndex, _source: alertSource }] } } };
        }
        if (request.index === ALERT_STATUS_INDEX) {
          return { body: { hits: { total: { value: 1 }, hits: [{ _id: 'a1', _source: alertSource }] } } };
        }
        if (request.index === CASES_INDEX) throw new Error('case index unavailable');
        throw new Error(`Unexpected search index ${request.index}`);
      }),
      create: jest.fn(),
      update: jest.fn(),
      bulk: jest.fn(),
    };

    const outcome = await evaluateCorrelationRules(client, [{ _id: 'a1', _source: alertSource }], logger);

    expect(outcome).toEqual(
      expect.objectContaining({
        status: 'retryable_failure',
        failures: [expect.objectContaining({ stage: 'case_dedup' })],
      })
    );
    expect(client.create).not.toHaveBeenCalled();
  });
});

describe('event-time trigger evaluation', () => {
  const canonical = normalizeStoredAutomationRule({
    id: 'rule-1', name: 'Burst', enabled: true, revision: 7, match: {}, actions: { createCase: true },
    trigger: {
      type: 'burst', threshold: 2, windowMinutes: 5, routing: 'separate_by_group',
      cooldown: { durationMinutes: 5 }, rearm: { type: 'after_quiet_period', quietPeriodMinutes: 5 },
      entityExpression: { version: 1, groups: [{ id: 'source', order: 0, predicates: [{ id: 'src', order: 0, entity: 'srcip', operator: 'exists' }] }] },
    },
  });

  test('anchors the sliding window at the queued alert and excludes future alerts', () => {
    const samples = [
      { id: 'old', source: { '@timestamp': '2026-08-28T11:54:59Z', data: { srcip: '10.0.0.1' } } },
      { id: 'within', source: { '@timestamp': '2026-08-28T11:56:00Z', data: { srcip: '10.0.0.1' } } },
      { id: 'anchor', source: { '@timestamp': '2026-08-28T12:00:00Z', data: { srcip: '10.0.0.1' } } },
      { id: 'future', source: { '@timestamp': '2026-08-28T12:00:01Z', data: { srcip: '10.0.0.1' } } },
    ];
    const result = evaluateRuleAtAlert(canonical, samples[2], samples);
    expect(result[0]).toMatchObject({ triggered: true, count: 2, alertIds: ['within', 'anchor'] });
  });

  test('retains provenance for every independently matching OR group', () => {
    const multi = normalizeStoredAutomationRule({
      ...canonical,
      trigger: {
        ...canonical.trigger,
        threshold: 1,
        entityExpression: { version: 1, groups: [
          { id: 'source', order: 0, predicates: [{ id: 'src', order: 0, entity: 'srcip', operator: 'exists' }] },
          { id: 'user', order: 1, predicates: [{ id: 'usr', order: 0, entity: 'user', operator: 'exists' }] },
        ] },
      },
    });
    const anchor = { id: 'a', source: { '@timestamp': '2026-08-28T12:00:00Z', data: { srcip: '10.0.0.1', srcuser: 'ADMIN' } } };
    expect(evaluateRuleAtAlert(multi, anchor, [anchor]).map((item) => item.group.groupId)).toEqual(['source', 'user']);
  });

  test('suppresses a continuous burst and rearms after an event-time quiet period', () => {
    const evaluation = evaluateRuleAtAlert(canonical, {
      id: 'first', source: { '@timestamp': '2026-08-28T12:00:00Z', data: { srcip: '10.0.0.1' } },
    }, [
      { id: 'prior', source: { '@timestamp': '2026-08-28T11:59:00Z', data: { srcip: '10.0.0.1' } } },
      { id: 'first', source: { '@timestamp': '2026-08-28T12:00:00Z', data: { srcip: '10.0.0.1' } } },
    ])[0];
    const first = transitionAutomationTrigger(evaluation);
    const continuous = transitionAutomationTrigger({ ...evaluation, anchorAlertId: 'next', anchorTimestamp: '2026-08-28T12:01:00.000Z' }, first.state);
    const rearmed = transitionAutomationTrigger({ ...evaluation, anchorAlertId: 'later', anchorTimestamp: '2026-08-28T12:07:00.000Z' }, continuous.state);
    expect([first.fire, continuous.fire, rearmed.fire]).toEqual([true, false, true]);
  });

  test('uses ingestion time for activation while allowing late old-event arrivals', () => {
    const anchor = {
      id: 'late',
      source: { '@timestamp': '2026-08-28T11:59:00Z', ingested_at: '2026-08-28T12:05:00Z', data: { srcip: '10.0.0.1' } },
    };
    const samples = [
      { id: 'pre-activation', source: { '@timestamp': '2026-08-28T11:58:00Z', ingested_at: '2026-08-28T11:59:00Z', data: { srcip: '10.0.0.1' } } },
      { id: 'post-activation', source: { '@timestamp': '2026-08-28T11:58:30Z', ingested_at: '2026-08-28T12:01:00Z', data: { srcip: '10.0.0.1' } } },
      anchor,
    ];
    expect(evaluateRuleAtAlert(canonical, anchor, samples, false, '2026-08-28T12:00:00Z')[0]).toMatchObject({
      triggered: true,
      alertIds: ['post-activation', 'late'],
    });
  });

  test('excludes alerts admitted after the immutable cohort cutoff even when their event time is older', () => {
    const anchor = {
      id: 'anchor',
      source: { '@timestamp': '2026-08-28T12:00:00Z', ingested_at: '2026-08-28T12:05:00Z', data: { srcip: '10.0.0.1' } },
    };
    const samples = [
      { id: 'cohort', source: { '@timestamp': '2026-08-28T11:59:00Z', ingested_at: '2026-08-28T12:04:00Z', data: { srcip: '10.0.0.1' } } },
      { id: 'later-late-event', source: { '@timestamp': '2026-08-28T11:58:00Z', ingested_at: '2026-08-28T12:06:00Z', data: { srcip: '10.0.0.1' } } },
      anchor,
    ];
    expect(evaluateRuleAtAlert(
      canonical, anchor, samples, false, undefined, '2026-08-28T12:05:00Z'
    )[0]).toMatchObject({ triggered: true, count: 2, alertIds: ['cohort', 'anchor'] });
  });

  test('records subthreshold and out-of-order activity by deterministic event id', () => {
    const triggered = evaluateRuleAtAlert(canonical, {
      id: 'newer', source: { '@timestamp': '2026-08-28T12:10:00Z', data: { srcip: '10.0.0.1' } },
    }, [
      { id: 'prior', source: { '@timestamp': '2026-08-28T12:09:00Z', data: { srcip: '10.0.0.1' } } },
      { id: 'newer', source: { '@timestamp': '2026-08-28T12:10:00Z', data: { srcip: '10.0.0.1' } } },
    ])[0];
    const first = transitionAutomationTrigger(triggered);
    const lateSubthreshold = transitionAutomationTrigger({
      ...triggered, anchorAlertId: 'late-old', anchorTimestamp: '2026-08-28T12:05:00.000Z', triggered: false,
    }, first.state);
    const duplicate = transitionAutomationTrigger({
      ...triggered, anchorAlertId: 'late-old', anchorTimestamp: '2026-08-28T12:05:00.000Z', triggered: false,
    }, lateSubthreshold.state);
    expect(duplicate.state?.activities?.map((item) => item.id)).toEqual(['late-old', 'newer']);
    expect(duplicate.state?.activities).toHaveLength(2);
    expect(duplicate.state?.last_seen_at).toBe('2026-08-28T12:10:00.000Z');
  });

  test('retains an already-fired later event when an older matching event arrives', () => {
    const newer = evaluateRuleAtAlert(canonical, {
      id: 'newer', source: { '@timestamp': '2026-08-28T12:10:00Z', data: { srcip: '10.0.0.1' } },
    }, [
      { id: 'prior', source: { '@timestamp': '2026-08-28T12:09:00Z', data: { srcip: '10.0.0.1' } } },
      { id: 'newer', source: { '@timestamp': '2026-08-28T12:10:00Z', data: { srcip: '10.0.0.1' } } },
    ])[0];
    const first = transitionAutomationTrigger(newer);
    const late = transitionAutomationTrigger({
      ...newer, anchorAlertId: 'late', anchorTimestamp: '2026-08-28T12:08:00.000Z',
    }, first.state);
    expect(late.fire).toBe(false);
    expect(late.state?.fired_event_ids).toEqual(['newer']);
    expect(late.state?.activities?.map((item) => item.id)).toEqual(['late', 'newer']);
  });
});

describe('queued evidence and write fencing', () => {
  const perAlertRule = {
    id: 'queued-rule', name: 'queued', enabled: true, match: { ruleIds: ['5502'] },
    trigger: { type: 'per_alert' }, actions: { createCase: false, assignTo: 'automation-owner' },
    preconditions: { statuses: ['open'], assignment: 'unassigned' }, safety: { acknowledgeMatchAll: false },
  };

  test('rejects non-candidate controls without reading managed alert storage', async () => {
    const client: any = { search: jest.fn() };
    const control = { ...alertSource, rule: { id: 'not-5502', groups: [] } };

    const outcome = await evaluateCorrelationRules(
      client,
      [{ _id: 'control-1', _source: control }],
      logger,
      undefined,
      { id: 'snapshot', rules: [perAlertRule], revisions: [] }
    );

    expect(outcome).toEqual(expect.objectContaining({ status: 'terminal_success' }));
    expect(client.search).not.toHaveBeenCalled();
  });

  test('reserves independent immediate trigger markers concurrently within a batch', async () => {
    let activeCreates = 0;
    let peakCreates = 0;
    const second = { ...alertSource, '@timestamp': '2026-08-28T12:00:01.000Z' };
    const client: any = {
      search: jest.fn(async () => ({ body: { hits: { hits: [
        { _id: 'a1', _index: physicalIndex, _source: alertSource },
        { _id: 'a2', _index: physicalIndex, _source: second },
      ] } } })),
      create: jest.fn(async () => {
        activeCreates += 1;
        peakCreates = Math.max(peakCreates, activeCreates);
        await new Promise((resolve) => setTimeout(resolve, 10));
        activeCreates -= 1;
      }),
      get: jest.fn(async () => {
        throw Object.assign(new Error('not found'), { meta: { statusCode: 404 } });
      }),
      update: jest.fn(async () => ({})),
    };
    const noActionRule = {
      ...perAlertRule,
      actions: { createCase: false },
      preconditions: {},
    };

    const outcome = await evaluateCorrelationRules(
      client,
      [{ _id: 'a1', _source: alertSource }, { _id: 'a2', _source: second }],
      logger,
      undefined,
      { id: 'snapshot', rules: [noActionRule], revisions: [] }
    );

    expect(outcome).toEqual(expect.objectContaining({ status: 'terminal_success' }));
    expect(peakCreates).toBe(2);
  });

  test('uses bounded bulks for immediate trigger reservation and completion', async () => {
    const second = { ...alertSource, '@timestamp': '2026-08-28T12:00:01.000Z' };
    const client: any = {
      search: jest.fn(async () => ({ body: { hits: { hits: [
        { _id: 'a1', _index: physicalIndex, _source: alertSource },
        { _id: 'a2', _index: physicalIndex, _source: second },
      ] } } })),
      mget: jest.fn(),
      create: jest.fn(),
      bulk: jest.fn(async ({ body }: any) => ({ body: {
        errors: false,
        items: body.filter((item: any) => item.create || item.update).map((item: any) =>
          item.create ? { create: { status: 201 } } : { update: { status: 200 } }
        ),
      } })),
    };
    const noActionRule = {
      ...perAlertRule,
      actions: { createCase: false },
      preconditions: {},
    };

    await expect(evaluateCorrelationRules(
      client,
      [{ _id: 'a1', _source: alertSource }, { _id: 'a2', _source: second }],
      logger,
      undefined,
      { id: 'snapshot', rules: [noActionRule], revisions: [] }
    )).resolves.toEqual(expect.objectContaining({ status: 'terminal_success' }));

    expect(client.create).not.toHaveBeenCalled();
    expect(client.mget).not.toHaveBeenCalled();
    expect(client.bulk).toHaveBeenCalledTimes(2);
    expect(client.bulk.mock.calls[0][0].body.filter((item: any) => item.create)).toHaveLength(2);
    expect(client.bulk.mock.calls[1][0].body.filter((item: any) => item.update)).toHaveLength(2);
  });

  test('matches immutable queued security fields but overlays current analyst workflow state', async () => {
    const projection = { ...alertSource, rule: { id: 'changed-after-admission' }, assigned_to: 'analyst' };
    const client: any = {
      search: jest.fn(async () => ({ body: { hits: { hits: [{ _id: 'a1', _index: physicalIndex, _source: projection }] } } })),
      get: jest.fn(async () => {
        throw Object.assign(new Error('not found'), { meta: { statusCode: 404 } });
      }),
      create: jest.fn(async () => ({ body: { result: 'created' } })),
      bulk: jest.fn(),
    };
    const outcome = await evaluateCorrelationRules(client, [{ _id: 'a1', _source: alertSource }], logger, undefined, {
      id: 'snapshot', rules: [perAlertRule], revisions: [],
    });
    expect(outcome).toEqual(expect.objectContaining({ status: 'terminal_success' }));
    expect(outcome.counters.matches).toBe(1);
    expect(client.bulk).not.toHaveBeenCalled();
  });

  test('stops before a side effect when the optional execution guard loses ownership', async () => {
    const client: any = {
      search: jest.fn(async () => ({ body: { hits: { hits: [{ _id: 'a1', _index: physicalIndex, _source: alertSource }] } } })),
      get: jest.fn(), create: jest.fn(), update: jest.fn(), bulk: jest.fn(),
    };
    const outcome = await evaluateCorrelationRules(
      client, [{ _id: 'a1', _source: alertSource }], logger, undefined,
      { id: 'snapshot', rules: [perAlertRule], revisions: [] }, async () => false
    );
    expect(outcome).toEqual(expect.objectContaining({
      status: 'retryable_failure', failures: [expect.objectContaining({ stage: 'execution_state' })],
    }));
    expect(client.create).not.toHaveBeenCalled();
    expect(client.bulk).not.toHaveBeenCalled();
  });

  test('passes the execution fence through automated case routing', async () => {
    const caseRule = {
      id: 'case-rule', name: 'Case burst', enabled: true, revision: 1, match: {},
      trigger: { type: 'burst', entity: 'srcip', threshold: 1, windowMinutes: 5, routing: 'one_per_rule' },
      actions: { createCase: true }, safety: { acknowledgeMatchAll: true },
    };
    let owned = true;
    const routing = jest.spyOn(automationCaseRouting, 'applyAutomationCaseRoutes').mockImplementation(
      async (_client, _routes, _maxCreations, _maxLinks, _perRule, fence) => {
        owned = false;
        await fence!();
        throw new Error('unreachable');
      }
    );
    const client: any = {
      search: jest.fn(async (request: any) => {
        if (request.index === ALERTS_READ_ALIAS && request.body.query.ids) {
          return { body: { hits: { hits: [{ _id: 'a1', _index: physicalIndex, _source: alertSource }] } } };
        }
        if (request.index === ALERT_STATUS_INDEX) {
          return { body: { hits: { total: { value: 1 }, hits: [{ _id: 'a1', _source: alertSource }] } } };
        }
        throw new Error(`Unexpected search index ${request.index}`);
      }),
    };

    const outcome = await evaluateCorrelationRules(
      client,
      [{ _id: 'a1', _source: alertSource }],
      logger,
      undefined,
      {
        id: 'snapshot', rules: [caseRule], revisions: [],
        admissionCutoff: '2026-08-28T12:00:02.000Z',
      },
      async () => owned
    );

    expect(routing).toHaveBeenCalledWith(
      client, expect.any(Array), expect.any(Number), expect.any(Number), expect.any(Map), expect.any(Function)
    );
    expect(outcome).toEqual(expect.objectContaining({
      status: 'retryable_failure',
      failures: [expect.objectContaining({ stage: 'case_write', message: 'Automation execution ownership was lost' })],
    }));
    routing.mockRestore();
  });

  test('extends an existing burst case during cooldown without allowing another case creation', async () => {
    const caseRule = {
      id: 'case-rule', name: 'Continuous burst', enabled: true, revision: 1, match: {},
      trigger: {
        type: 'burst', entity: 'srcip', threshold: 1, windowMinutes: 5, routing: 'one_per_rule',
        cooldown: { durationMinutes: 5 },
        rearm: { type: 'after_quiet_period', quietPeriodMinutes: 5 },
      },
      actions: { createCase: true }, safety: { acknowledgeMatchAll: true },
    };
    const routing = jest.spyOn(automationCaseRouting, 'applyAutomationCaseRoutes').mockResolvedValue({
      created: 0, extended: 1, linked: 1, conflicts: [], caseIds: ['existing-case'], remainder: [],
    });
    const client: any = {
      search: jest.fn(async (request: any) => {
        if (request.index === ALERTS_READ_ALIAS && request.body.query.ids) {
          return { body: { hits: { hits: [{ _id: 'a1', _index: physicalIndex, _source: alertSource }] } } };
        }
        if (request.index === ALERT_STATUS_INDEX) {
          return { body: { hits: { total: { value: 1 }, hits: [{ _id: 'a1', _source: alertSource }] } } };
        }
        throw new Error(`Unexpected search index ${request.index}`);
      }),
      create: jest.fn(async () => ({})),
      get: jest.fn(async () => ({ body: {
        _seq_no: 4, _primary_term: 1,
        _source: {
          armed: false,
          last_seen_at: '2026-08-28T11:59:30.000Z',
          last_fired_at: '2026-08-28T11:59:30.000Z',
          last_trigger_alert_id: 'prior',
          activities: [{ id: 'prior', timestamp: '2026-08-28T11:59:30.000Z', triggered: true }],
          fired_event_ids: ['prior'],
        },
      } })),
      update: jest.fn(async () => ({})),
    };

    const outcome = await evaluateCorrelationRules(
      client, [{ _id: 'a1', _source: alertSource }], logger, undefined,
      {
        id: 'snapshot', rules: [caseRule], revisions: [],
        admissionCutoff: '2026-08-28T12:00:02.000Z',
      }
    );

    expect(outcome).toEqual(expect.objectContaining({
      status: 'terminal_success', counters: expect.objectContaining({ caseCreations: 0, caseLinks: 1 }),
    }));
    expect(routing).toHaveBeenCalledWith(
      client,
      [expect.objectContaining({ alertIds: ['a1'] })],
      0,
      expect.any(Number),
      new Map([['case-rule', 0]]),
      expect.any(Function)
    );
    routing.mockRestore();
  });

  test('shares one historical window read across same-rule burst anchors in a worker batch', async () => {
    const burstRule = {
      id: 'shared-window', name: 'Shared burst window', enabled: true, revision: 1, match: {},
      trigger: { type: 'burst', entity: 'srcip', threshold: 1, windowMinutes: 5, routing: 'one_per_rule' },
      actions: { createCase: false }, safety: { acknowledgeMatchAll: true },
    };
    const secondSource = {
      ...alertSource, '@timestamp': '2026-08-28T12:00:01.000Z', ingested_at: '2026-08-28T12:00:01.500Z',
    };
    const client: any = {
      search: jest.fn(async (request: any) => {
        if (request.index === ALERTS_READ_ALIAS && request.body.query.ids) {
          return { body: { hits: { hits: [
            { _id: 'a1', _index: physicalIndex, _source: alertSource },
            { _id: 'a2', _index: physicalIndex, _source: secondSource },
          ] } } };
        }
        if (request.index === ALERT_STATUS_INDEX) {
          return { body: { hits: { total: { value: 2 }, hits: [
            { _id: 'a1', _source: alertSource }, { _id: 'a2', _source: secondSource },
          ] } } };
        }
        throw new Error(`Unexpected search index ${request.index}`);
      }),
    };

    await expect(evaluateCorrelationRules(
      client,
      [{ _id: 'a2', _source: secondSource }, { _id: 'a1', _source: alertSource }],
      logger,
      undefined,
      {
        id: 'snapshot', rules: [burstRule], revisions: [],
        admissionCutoff: '2026-08-28T12:00:02.000Z',
      }
    )).resolves.toEqual(expect.objectContaining({ status: 'terminal_success' }));

    expect(client.search.mock.calls.filter((call: any[]) => call[0].body?.track_total_hits === true)).toHaveLength(1);
  });

  test('reserves same-entity burst state once for a worker batch', async () => {
    const burstRule = {
      id: 'batched-state', name: 'Batched state', enabled: true, revision: 1, match: {},
      trigger: {
        type: 'burst', entity: 'srcip', threshold: 1, windowMinutes: 5, routing: 'one_per_rule',
        cooldown: { durationMinutes: 5 },
        rearm: { type: 'after_quiet_period', quietPeriodMinutes: 5 },
      },
      actions: { createCase: false }, safety: { acknowledgeMatchAll: true },
    };
    const secondSource = {
      ...alertSource, '@timestamp': '2026-08-28T12:00:01.000Z', ingested_at: '2026-08-28T12:00:01.500Z',
    };
    const client: any = {
      search: jest.fn(async (request: any) => {
        if (request.body.query.ids) return { body: { hits: { hits: [
          { _id: 'a1', _index: physicalIndex, _source: alertSource },
          { _id: 'a2', _index: physicalIndex, _source: secondSource },
        ] } } };
        return { body: { hits: { total: { value: 2 }, hits: [
          { _id: 'a1', _source: alertSource }, { _id: 'a2', _source: secondSource },
        ] } } };
      }),
      bulk: jest.fn(async ({ body }: any) => ({ body: {
        errors: false,
        items: body.filter((item: any) => item.create || item.update).map((item: any) =>
          item.create ? { create: { status: 201 } } : { update: { status: 200 } }
        ),
      } })),
      mget: jest.fn(),
      get: jest.fn(async () => { throw Object.assign(new Error('missing'), { meta: { statusCode: 404 } }); }),
      create: jest.fn(async () => ({})),
      update: jest.fn(async () => ({})),
    };

    await expect(evaluateCorrelationRules(
      client,
      [{ _id: 'a2', _source: secondSource }, { _id: 'a1', _source: alertSource }],
      logger,
      undefined,
      {
        id: 'snapshot', rules: [burstRule], revisions: [],
        admissionCutoff: '2026-08-28T12:00:02.000Z',
      }
    )).resolves.toEqual(expect.objectContaining({ status: 'terminal_success' }));

    expect(client.bulk.mock.calls[0][0].body.filter((item: any) => item.create)).toHaveLength(2);
    expect(client.get).toHaveBeenCalledTimes(1);
    expect(client.create).toHaveBeenCalledTimes(1);
    expect(client.create.mock.calls[0][0].body.activities.map((item: any) => item.id)).toEqual(['a1', 'a2']);
    expect(client.update).not.toHaveBeenCalled();
  });

  test('never substitutes processing time for a missing queued event timestamp', async () => {
    const client: any = {
      search: jest.fn(async () => ({ body: { hits: { hits: [{ _id: 'a1', _index: physicalIndex, _source: alertSource }] } } })),
      bulk: jest.fn(),
    };
    const outcome = await evaluateCorrelationRules(client, [{
      _id: 'a1', _source: { ...alertSource, '@timestamp': undefined },
    }], logger, undefined, { id: 'snapshot', rules: [perAlertRule], revisions: [] });
    expect(outcome).toEqual(expect.objectContaining({
      status: 'retryable_failure',
      failures: [expect.objectContaining({ stage: 'window', message: expect.stringContaining('no valid @timestamp') })],
    }));
    expect(client.bulk).not.toHaveBeenCalled();
  });

  test('adds the admission cutoff to burst searches and fails closed when legacy queued work lacks it', async () => {
    const burstRule = {
      id: 'burst', name: 'burst', enabled: true, match: {},
      trigger: { type: 'burst', threshold: 3, windowMinutes: 5 },
      actions: { createCase: false }, safety: { acknowledgeMatchAll: true },
    };
    const client: any = {
      search: jest.fn(async (request: any) => {
        if (request.index === ALERTS_READ_ALIAS) {
          return { body: { hits: { hits: [{ _id: 'a1', _index: physicalIndex, _source: alertSource }] } } };
        }
        if (request.index === ALERT_STATUS_INDEX) {
          return { body: { hits: { total: { value: 1 }, hits: [{ _id: 'a1', _source: alertSource }] } } };
        }
        throw new Error(`Unexpected search index ${request.index}`);
      }),
      get: jest.fn(async () => { throw Object.assign(new Error('not found'), { meta: { statusCode: 404 } }); }),
      create: jest.fn().mockResolvedValue({}),
      update: jest.fn().mockResolvedValue({}),
    };
    const snapshot = {
      id: 'snapshot', rules: [burstRule], revisions: [], admission_cutoff: '2026-08-28T12:05:00.000Z',
    };

    await expect(evaluateCorrelationRules(client, [{ _id: 'a1', _source: alertSource }], logger, undefined, snapshot))
      .resolves.toEqual(expect.objectContaining({ status: 'terminal_success' }));
    const windowRequest = client.search.mock.calls.find(
      (call: any[]) => call[0].index === ALERT_STATUS_INDEX && call[0].body?.query?.bool?.must
    )[0];
    expect(windowRequest.body.query.bool.must).toContainEqual({
      range: { ingested_at: { lte: '2026-08-28T12:05:00.000Z' } },
    });

    client.search.mockClear();
    const legacy = await evaluateCorrelationRules(
      client, [{ _id: 'a1', _source: alertSource }], logger, undefined,
      { id: 'legacy-snapshot', rules: [burstRule], revisions: [] }
    );
    expect(legacy).toEqual(expect.objectContaining({
      status: 'retryable_failure',
      failures: [expect.objectContaining({ stage: 'window', message: expect.stringContaining('no valid admission cutoff') })],
    }));
    expect(client.search.mock.calls.some(
      (call: any[]) => call[0].index === ALERT_STATUS_INDEX && call[0].body?.query?.bool?.must
    )).toBe(false);
  });
});
