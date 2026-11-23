// The SLA policy read (step 3.1) is mocked so the mocked clients' get() counts stay about automation state.
jest.mock('./sla/policy', () => { const actual = jest.requireActual('./sla/policy'); return { ...actual, getSlaPolicy: jest.fn(async () => actual.DEFAULT_SLA_POLICY) }; });
import { ALERTS_READ_ALIAS, ALERT_STATUS_INDEX, CASES_INDEX, NOTIFICATIONS_INDEX, RULES_INDEX } from '../../common';
import { invalidateNotificationSettingsCache, primeNotificationSettingsCache } from './notifications/settings';
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

  test('counts and logs a task list that could not be applied to a created case (step 2.2)', async () => {
    const caseRule = {
      id: 'case-rule', name: 'Case burst', enabled: true, revision: 1, match: {},
      trigger: { type: 'burst', entity: 'srcip', threshold: 1, windowMinutes: 5, routing: 'one_per_rule' },
      actions: { createCase: true, caseSeverity: 'high', applyTaskListId: 'pb-0123456789abcdef' }, safety: { acknowledgeMatchAll: true },
    };
    const routing = jest.spyOn(automationCaseRouting, 'applyAutomationCaseRoutes').mockResolvedValue({
      created: 1, extended: 0, linked: 1, conflicts: [], caseIds: ['case-1'], remainder: [],
      taskListsApplied: 0, taskListErrors: ['case-1: Task list pb-0123456789abcdef is disabled'],
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
      // No trigger state yet (first burst); the progress marker created by the
      // reservation reads back empty.
      get: jest.fn(async ({ id }: any) => {
        if (String(id).startsWith('trigger-state:')) throw Object.assign(new Error('not found'), { meta: { statusCode: 404 } });
        return { body: { found: true, _source: {} } };
      }),
      update: jest.fn(async () => ({})),
    };
    logger.warn.mockClear();

    const outcome = await evaluateCorrelationRules(
      client, [{ _id: 'a1', _source: alertSource }], logger, undefined,
      { id: 'snapshot', rules: [caseRule], revisions: [], admissionCutoff: '2026-08-28T12:00:02.000Z' }
    );

    expect(outcome).toEqual(expect.objectContaining({
      status: 'terminal_success',
      counters: expect.objectContaining({ caseCreations: 1, taskListsApplied: 0, taskListFailures: 1 }),
    }));
    expect(routing).toHaveBeenCalledWith(
      client,
      [expect.objectContaining({ applyTaskListId: 'pb-0123456789abcdef', alertIds: ['a1'] })],
      1,
      expect.any(Number),
      expect.any(Map),
      expect.any(Function)
    );
    expect(logger.warn).toHaveBeenCalledWith(
      'wazuh-alert-manager: automation task list not applied: case-1: Task list pb-0123456789abcdef is disabled'
    );
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
      created: 0, extended: 1, linked: 1, conflicts: [], caseIds: ['existing-case'], remainder: [], taskListsApplied: 0, taskListErrors: [],
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

describe('disposition written with an automated close (step 2.4)', () => {
  test('the close action carries the disposition; the script stores it and names it on the close history row', async () => {
    const rule = {
      name: 'Close scanner noise',
      enabled: true,
      match: {},
      trigger: { type: 'per_alert' },
      actions: { createCase: false, setStatus: 'closed', disposition: 'false_positive' },
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
      bulk: jest.fn(async () => ({ body: { errors: false, items: [{ update: { status: 200, result: 'updated' } }] } })),
      update: jest.fn(),
      index: jest.fn(),
      get: jest.fn(async () => { throw { meta: { statusCode: 404 } }; }),
    };

    const outcome = await evaluateCorrelationRules(client, [{ _id: 'a1', _source: alertSource }], logger);
    expect(outcome.status).toBe('terminal_success');
    const operation = client.bulk.mock.calls[0][0].body[1];
    const actions = operation.script.params.actions;
    expect(actions.find((a: any) => a.field === 'status')).toEqual({
      marker: 'status:rule-1:a1', field: 'status', value: 'closed', rule: 'rule-1', disposition: 'false_positive',
    });
    // No separate disposition action: the status action carries it, so the
    // `rule:<id> -> closed` history row names the outcome like a manual close.
    expect(actions.find((a: any) => a.field === 'disposition')).toBeUndefined();
    expect(actions.find((a: any) => a.field === 'reporting')).toEqual(expect.objectContaining({ merge: true }));
    expect(operation.script.source).toContain('if (action.disposition != null) { ctx._source.disposition = action.disposition; row.disposition = action.disposition; }');
    expect(operation.script.source).toContain('ctx._source.history.add(row)');
  });
});

describe('notify action (step 1.4)', () => {
  const channels = {
    enabled: true,
    channels: [
      { id: 'slack', name: 'SOC Slack', kind: 'indexer_channel', enabled: true, events: [] },
      { id: 'old', name: 'Retired hook', kind: 'webhook', enabled: false, events: [] },
    ],
  } as any;
  const rule = {
    name: 'Notify SOC',
    enabled: true,
    match: {},
    trigger: { type: 'per_alert' },
    actions: { createCase: false, setStatus: 'in_progress', notify: { channelIds: ['slack', 'old', 'ghost'] } },
    safety: { acknowledgeMatchAll: true },
  };
  interface NotifyClientOptions {
    alertWrite?: 'updated' | 'noop';
    /** The `_source` the second (re-read) ids search answers; default: the first one. */
    reread?: any;
    /** The stored alert as the first ids search answers it. */
    stored?: any;
    /** Forced outbox bulk behaviour. */
    outbox?: (request: any) => Promise<any>;
    /** Forced notification_settings read. */
    settings?: () => Promise<any>;
  }
  const notifyClient = (options: NotifyClientOptions = {}) => {
    const written = new Set<string>();
    let idsSearches = 0;
    const client: any = {
      search: jest.fn(async (request: any) => {
        if (request.index === RULES_INDEX) return { body: { hits: { hits: [{ _id: 'rule-1', _source: rule }] } } };
        if (request.index === ALERTS_READ_ALIAS && request.body.query.ids) {
          idsSearches += 1;
          const source = idsSearches > 1 && options.reread ? options.reread : options.stored || alertSource;
          return { body: { hits: { hits: [{ _id: 'a1', _index: physicalIndex, _source: source }] } } };
        }
        throw new Error(`Unexpected search index ${request.index}`);
      }),
      bulk: jest.fn(async (request: any) => {
        if (request.body?.[0]?.create?._index === NOTIFICATIONS_INDEX) {
          if (options.outbox) return options.outbox(request);
          const items: any[] = [];
          for (let position = 0; position < request.body.length; position += 2) {
            const id = request.body[position].create._id;
            if (written.has(id)) items.push({ create: { _id: id, status: 409, error: { type: 'version_conflict_engine_exception' } } });
            else { written.add(id); items.push({ create: { _id: id, status: 201 } }); }
          }
          return { body: { errors: false, items } };
        }
        const alertWrite = request.body?.[0]?.update?._index === physicalIndex;
        return { body: { errors: false, items: [{ update: { status: 200, result: alertWrite ? options.alertWrite || 'updated' : 'updated' } }] } };
      }),
      update: jest.fn(),
      get: jest.fn(async (request: any) => {
        if (request.id === 'notification_settings' && options.settings) return options.settings();
        throw { meta: { statusCode: 404 } };
      }),
      index: jest.fn(async () => ({})),
    };
    return client;
  };
  const outboxWrites = (client: any) => client.bulk.mock.calls
    .map((call: any[]) => call[0])
    .filter((request: any) => request.body?.[0]?.create?._index === NOTIFICATIONS_INDEX)
    .flatMap((request: any) => request.body.filter((_: any, index: number) => index % 2 === 1));

  beforeEach(() => primeNotificationSettingsCache(channels));
  afterEach(() => invalidateNotificationSettingsCache());

  test('enqueues one rule.action entry per enabled channel under the idempotent id, with the applied outcome in the payload, and counts unknown, disabled and duplicate targets as skipped', async () => {
    const client = notifyClient();

    const first = await evaluateCorrelationRules(client, [{ _id: 'a1', _source: alertSource }], logger);
    expect(first.status).toBe('terminal_success');
    expect(first.counters).toMatchObject({ statusChanges: 1, notificationsEnqueued: 1, notificationsSkipped: 2 });
    expect(first.appliedRuleIds).toEqual(['rule-1']);
    const writes = outboxWrites(client);
    expect(writes).toHaveLength(1);
    expect(writes[0]).toMatchObject({
      id: 'notify:rule-1:a1:slack',
      event: 'rule.action',
      channel_id: 'slack',
      channel_kind: 'indexer_channel',
      target_type: 'alert',
      target_id: 'a1',
      status: 'pending',
    });
    expect(writes[0].subject).toBe('[Wazuh Alert Manager] Automation rule fired: Notify SOC');
    expect(writes[0].payload).toMatchObject({
      event: 'rule.action',
      actor: 'correlation-rule',
      rule: { id: 'rule-1', name: 'Notify SOC' },
      actions: { status: 'in_progress' },
      alert: { id: 'a1', status: 'in_progress', rule: { id: '5502' } },
    });
    expect(writes[0].payload.actions.assignee).toBeUndefined();
    expect(writes[0].payload.actions.caseId).toBeUndefined();
    expect(writes[0].payload.alert.data).toBeUndefined();
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('ghost, old'));
    // The alert was not re-read: its bulk item was applied, the snapshot plus the applied actions is current.
    expect(client.search.mock.calls.filter((call: any[]) => call[0].index === ALERTS_READ_ALIAS)).toHaveLength(1);

    // A re-evaluation of the same event (queue retry, second replica) never duplicates.
    const second = await evaluateCorrelationRules(client, [{ _id: 'a1', _source: alertSource }], logger);
    expect(second.status).toBe('terminal_success');
    expect(second.counters).toMatchObject({ notificationsEnqueued: 0, notificationsSkipped: 3 });
    expect(outboxWrites(client)).toHaveLength(2);
  });

  test('a status the script did not apply (analyst edit won) is not claimed, and the payload carries the re-read live alert, not the stale snapshot', async () => {
    const client = notifyClient({
      alertWrite: 'noop',
      reread: { ...alertSource, state_version: 5, status: 'closed', assigned_to: 'analyst-7', updated_by: 'analyst-7' },
    });
    const outcome = await evaluateCorrelationRules(client, [{ _id: 'a1', _source: alertSource }], logger);
    expect(outcome.status).toBe('terminal_success');
    expect(outcome.counters).toMatchObject({ skippedBySafety: 1, notificationsEnqueued: 1 });
    expect(client.search.mock.calls.filter((call: any[]) => call[0].index === ALERTS_READ_ALIAS)).toHaveLength(2);
    const payload = outboxWrites(client)[0].payload;
    expect(payload.actions).toEqual({});
    expect(payload.alert.status).toBe('closed');
    expect(payload.alert.assigned_to).toBe('analyst-7');
  });

  test('a failed re-read of a noop alert is a retryable notification_enqueue failure and nothing is written', async () => {
    const client = notifyClient({ alertWrite: 'noop' });
    const search = client.search;
    let idsSearches = 0;
    client.search = jest.fn(async (request: any) => {
      if (request.index === ALERTS_READ_ALIAS && request.body.query.ids && ++idsSearches > 1) throw new Error('alias unavailable');
      return search(request);
    });
    const outcome = await evaluateCorrelationRules(client, [{ _id: 'a1', _source: alertSource }], logger);
    expect(outcome).toEqual(expect.objectContaining({
      status: 'retryable_failure',
      failures: [expect.objectContaining({ stage: 'notification_enqueue', message: expect.stringContaining('alias unavailable') })],
    }));
    expect(outboxWrites(client)).toHaveLength(0);
  });

  test('a replay after a later-stage failure reports the status the first attempt applied, read from the action markers', async () => {
    // The first attempt stored the status and its marker; the planner now sees
    // the status satisfied and writes nothing, but the rule did act.
    const client = notifyClient({
      stored: { ...alertSource, state_version: 5, status: 'in_progress', automation_action_markers: ['status:rule-1:a1', 'reporting:rule-1:a1'] },
    });
    const outcome = await evaluateCorrelationRules(client, [{ _id: 'a1', _source: alertSource }], logger);
    expect(outcome.status).toBe('terminal_success');
    expect(outcome.counters).toMatchObject({ statusChanges: 0, notificationsEnqueued: 1 });
    expect(client.bulk.mock.calls.filter((call: any[]) => call[0].body?.[0]?.update)).toHaveLength(0);
    const payload = outboxWrites(client)[0].payload;
    expect(payload.actions).toEqual({ status: 'in_progress' });
    expect(payload.alert.status).toBe('in_progress');
  });

  test('an outbox bulk item failure is a retryable notification_enqueue failure (the ids make the replay safe)', async () => {
    const client = notifyClient({
      outbox: async (request: any) => ({ body: { errors: true, items: [{ create: { _id: request.body[0].create._id, status: 503, error: { reason: 'outbox unavailable' } } }] } }),
    });
    const outcome = await evaluateCorrelationRules(client, [{ _id: 'a1', _source: alertSource }], logger);
    expect(outcome).toEqual(expect.objectContaining({
      status: 'retryable_failure',
      failures: [expect.objectContaining({ stage: 'notification_enqueue', ruleId: 'rule-1', alertId: 'a1', message: expect.stringContaining('outbox unavailable') })],
    }));
    expect(outcome.counters).toMatchObject({ notificationsEnqueued: 0 });
  });

  test('an outbox transport failure is a retryable notification_enqueue failure', async () => {
    const client = notifyClient({ outbox: async () => { throw new Error('connection reset'); } });
    const outcome = await evaluateCorrelationRules(client, [{ _id: 'a1', _source: alertSource }], logger);
    expect(outcome).toEqual(expect.objectContaining({
      status: 'retryable_failure',
      failures: [expect.objectContaining({ stage: 'notification_enqueue', message: 'connection reset' })],
    }));
  });

  test('a failed notification settings read is a retryable notification_enqueue failure with no outbox write, never a final skip', async () => {
    invalidateNotificationSettingsCache();
    const client = notifyClient({ settings: async () => { throw new Error('meta index unavailable'); } });
    const outcome = await evaluateCorrelationRules(client, [{ _id: 'a1', _source: alertSource }], logger);
    expect(outcome).toEqual(expect.objectContaining({
      status: 'retryable_failure',
      failures: [expect.objectContaining({ stage: 'notification_enqueue', message: 'meta index unavailable' })],
    }));
    expect(outcome.counters).toMatchObject({ notificationsEnqueued: 0, notificationsSkipped: 0 });
    expect(outboxWrites(client)).toHaveLength(0);
    expect(logger.warn).not.toHaveBeenCalledWith(expect.stringContaining('disabled in Settings > Notifications'));
  });

  test('every target is skipped, nothing is written and the rule is not claimed as applied while notifications are disabled globally', async () => {
    primeNotificationSettingsCache({ ...channels, enabled: false });
    const client = notifyClient({ stored: { ...alertSource, status: 'in_progress', automation_action_markers: ['status:rule-1:a1'] } });
    const outcome = await evaluateCorrelationRules(client, [{ _id: 'a1', _source: alertSource }], logger);
    expect(outcome.status).toBe('terminal_success');
    expect(outcome.counters).toMatchObject({ statusChanges: 0, notificationsEnqueued: 0, notificationsSkipped: 3 });
    expect(outcome.appliedRuleIds).toEqual([]);
    expect(outboxWrites(client)).toHaveLength(0);
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('disabled in Settings > Notifications'));
  });

  test('a rule without the action reads no settings and writes no outbox entry', async () => {
    invalidateNotificationSettingsCache();
    const client = notifyClient();
    client.search = jest.fn(async (request: any) => {
      if (request.index === RULES_INDEX) return { body: { hits: { hits: [{ _id: 'rule-1', _source: { ...rule, actions: { createCase: false, setStatus: 'in_progress' } } }] } } };
      if (request.index === ALERTS_READ_ALIAS && request.body.query.ids) {
        return { body: { hits: { hits: [{ _id: 'a1', _index: physicalIndex, _source: alertSource }] } } };
      }
      throw new Error(`Unexpected search index ${request.index}`);
    });
    const outcome = await evaluateCorrelationRules(client, [{ _id: 'a1', _source: alertSource }], logger);
    expect(outcome.status).toBe('terminal_success');
    expect(outcome.counters).toMatchObject({ notificationsEnqueued: 0, notificationsSkipped: 0 });
    expect(outboxWrites(client)).toHaveLength(0);
    expect(client.get).not.toHaveBeenCalledWith(expect.objectContaining({ id: 'notification_settings' }));
  });
});
