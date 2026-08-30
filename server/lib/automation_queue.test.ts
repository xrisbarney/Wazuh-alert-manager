import { createHash } from 'crypto';
import {
  automationEventId,
  automationExecutionId,
  automationAdmissionLane,
  automationWorkerLeaseId,
  automationQueueHealth,
  activateAutomationEvents,
  enqueueAutomationEvents,
  reconcileAutomationAdmissions,
  ensureAutomationSettings,
  retryAutomationDlqEvent,
  retryDelayMs,
  runAutomationWorkerOnce,
  runAutomationWorkerBatchOnce,
  chunkBulkPairs,
} from './automation_queue';
import {
  AUTOMATION_DLQ_INDEX,
  AUTOMATION_EXECUTIONS_INDEX,
  AUTOMATION_QUEUE_INDEX,
  AUTOMATION_WORKER_LEASE_ID,
} from '../../common';

const logger: any = { debug: jest.fn(), info: jest.fn(), warn: jest.fn(), error: jest.fn() };
const notFound = () => Object.assign(new Error('not found'), { meta: { statusCode: 404 } });
const success = {
  status: 'terminal_success' as const,
  counters: { matches: 1, statusChanges: 1 },
  appliedRuleIds: ['rule-1'],
} as any;
const snapshotRules = [{ actions: { setStatus: 'closed' }, enabled: true, id: 'rule-1', revision: 3 }];
const snapshotId = createHash('sha256').update(JSON.stringify(snapshotRules)).digest('hex');

function queueHit(attempts = 0, state = 'pending') {
  return {
    _id: 'alert-1',
    _seq_no: 4,
    _primary_term: 2,
    _source: {
      event_id: 'alert-1',
      alert_uid: 'alert-1',
      state,
      attempts,
      enqueued_at: '2026-08-28T00:00:00.000Z',
      available_at: '2026-08-28T00:00:00.000Z',
      admission_cutoff: '2026-08-28T00:00:01.000Z',
      ruleset_snapshot: snapshotId,
      rule_revisions: [{ id: 'rule-1', revision: 3 }],
      payload: { alert_uid: 'alert-1', rule: { id: '5502' } },
    },
  };
}

function workerClient(hit = queueHit(), executionSource?: any) {
  let seq = 10;
  const docs = new Map<string, any>();
  docs.set(`${AUTOMATION_QUEUE_INDEX}/${hit._id}`, {
    _seq_no: hit._seq_no,
    _primary_term: hit._primary_term,
    _source: { ...hit._source },
  });
  docs.set(`${AUTOMATION_EXECUTIONS_INDEX}/automation-ruleset:${hit._source.ruleset_snapshot}`, {
    _seq_no: 1,
    _primary_term: 1,
    _source: {
      document_type: 'ruleset_snapshot', snapshot_sha256: hit._source.ruleset_snapshot,
      rules_snapshot: snapshotRules, rule_revisions: [{ id: 'rule-1', revision: 3 }],
    },
  });
  if (executionSource) {
    docs.set(`${AUTOMATION_EXECUTIONS_INDEX}/${automationExecutionId(hit._source.event_id, hit._source.ruleset_snapshot)}`, {
      _seq_no: 3,
      _primary_term: 1,
      _source: { ...executionSource },
    });
  }
  const get = jest.fn(async ({ index, id }: any) => {
    const doc = docs.get(`${index}/${id}`);
    if (!doc) throw notFound();
    return { body: { ...doc, _source: { ...doc._source } } };
  });
  const client: any = {
    get,
    create: jest.fn(async ({ index, id, body }: any) => {
      const key = `${index}/${id}`;
      if (docs.has(key)) throw Object.assign(new Error('conflict'), { meta: { statusCode: 409 } });
      docs.set(key, { _seq_no: seq++, _primary_term: 1, _source: { ...body } });
      return { body: { result: 'created' } };
    }),
    search: jest.fn(async ({ index }: any) => {
      if (index !== AUTOMATION_QUEUE_INDEX) return { body: { hits: { hits: [] }, aggregations: { states: { buckets: [] } } } };
      const doc = docs.get(`${AUTOMATION_QUEUE_INDEX}/${hit._id}`);
      return { body: { hits: { hits: doc ? [{ _id: hit._id, ...doc }] : [] } } };
    }),
    update: jest.fn(async ({ index, id, body }: any) => {
      const key = `${index}/${id}`;
      const current = docs.get(key) || { _seq_no: seq++, _primary_term: 1, _source: {} };
      const next = { _seq_no: seq++, _primary_term: current._primary_term, _source: { ...current._source, ...body.doc } };
      docs.set(key, next);
      return { body: { _seq_no: next._seq_no, _primary_term: next._primary_term } };
    }),
    delete: jest.fn(async ({ index, id }: any) => { docs.delete(`${index}/${id}`); }),
    mget: jest.fn(async ({ index, body }: any) => ({ body: { docs: (body.docs || body.ids.map((id: string) => ({ _index: index, _id: id }))).map((item: any) => {
      const key = `${item._index}/${item._id}`;
      const doc = docs.get(key);
      return doc
        ? { _index: item._index, _id: item._id, found: true, ...doc, _source: { ...doc._source } }
        : { _index: item._index, _id: item._id, found: false };
    }) } })),
    indices: { refresh: jest.fn(async () => undefined) },
    bulk: jest.fn(async ({ body }: any) => {
      const items: any[] = [];
      for (let offset = 0; offset < body.length; offset += 2) {
        const action = body[offset];
        const payload = body[offset + 1];
        const kind = Object.keys(action)[0];
        const metadata = action[kind];
        const key = `${metadata._index}/${metadata._id}`;
        const current = docs.get(key);
        if (kind === 'create' && current) {
          items.push({ create: { status: 409, error: { type: 'version_conflict_engine_exception' } } });
          continue;
        }
        if (kind === 'create' || kind === 'index') {
          docs.set(key, { _seq_no: seq++, _primary_term: 1, _source: { ...payload } });
          items.push({ [kind]: { status: 201, result: 'created' } });
          continue;
        }
        if (kind === 'update') {
          const source = { ...(current?._source || {}) };
          if (payload.doc) Object.assign(source, payload.doc);
          if (payload.script) {
            const params = payload.script.params;
            const owned = source.state === params.state && source.holder_id === params.holder &&
              source.fencing_generation === params.generation && source.lease_token === params.token;
            if (!owned) {
              items.push({ update: { status: 200, result: 'noop' } });
              continue;
            }
            Object.assign(source, params.doc);
          }
          docs.set(key, { _seq_no: seq++, _primary_term: current?._primary_term || 1, _source: source });
          items.push({ update: { status: 200, result: 'updated' } });
        }
      }
      return { body: { errors: items.some((item) => (Object.values(item)[0] as any)?.error), items } };
    }),
  };
  client.docs = docs;
  return client;
}

describe('durable automation queue', () => {
  test('retries idempotent staged activation on bounded OCC conflicts', async () => {
    const client: any = {
      bulk: jest.fn().mockResolvedValue({
        body: { errors: false, items: [{ update: { status: 200, result: 'updated' } }] },
      }),
    };

    await expect(activateAutomationEvents(client, [{ alert_uid: 'a' }])).resolves.toBe(1);

    expect(client.bulk.mock.calls[0][0].body[0]).toEqual({
      update: { _index: AUTOMATION_QUEUE_INDEX, _id: 'a', retry_on_conflict: 3 },
    });
  });

  test('keeps alerts matching the same rule on one worker lane', () => {
    const snapshot: any = {
      id: 'snapshot', revisions: [], rules: [{
        id: 'rule-a', enabled: true, revision: 1, name: 'A', priority: 1, sortOrder: 0,
        processingMode: 'continue', match: { agentNames: ['agent-a'], agentNamesMode: 'any' },
        trigger: { type: 'per_alert', entityExpression: { version: 1, groups: [] } },
        actions: { createCase: false, setStatus: 'closed' }, preconditions: {}, safety: {},
      }],
    };

    expect(automationAdmissionLane(snapshot, { alert_uid: 'one', agent: { name: 'agent-a' } }))
      .toBe(automationAdmissionLane(snapshot, { alert_uid: 'two', agent: { name: 'agent-a' } }));
  });

  test('treats a conflicting settings create as successful convergence', async () => {
    const client: any = {
      search: jest.fn().mockResolvedValue({ body: { hits: { total: { value: 0 } } } }),
      create: jest.fn().mockRejectedValue(Object.assign(new Error('conflict'), { meta: { statusCode: 409 } })),
    };

    await expect(ensureAutomationSettings(client)).resolves.toBeUndefined();
  });

  test('uses stable event/execution ids and validates every enqueue bulk item', async () => {
    const events = [
      { alert_uid: 'a', rule: { id: '5502' } },
      { alert_uid: 'b', rule: { id: '5502' } },
      { alert_uid: 'c', rule: { id: '5502' } },
    ];
    const client: any = {
      get: jest.fn().mockRejectedValue(notFound()),
      search: jest.fn(async ({ index }: any) => index === AUTOMATION_QUEUE_INDEX
        ? { body: { aggregations: { states: { buckets: [] } } } }
        : { body: { hits: { total: { value: 1 }, hits: [{ _id: 'rule-1', _source: {
          name: 'original', enabled: true, revision: 3, match: { ruleIds: ['5502'] },
          trigger: { type: 'per_alert' }, actions: { createCase: false, setStatus: 'closed' },
        } }] } } }),
      create: jest.fn().mockResolvedValue({ body: { result: 'created' } }),
      bulk: jest
        .fn()
        .mockResolvedValueOnce({
          body: {
            errors: true,
            items: [
              { create: { status: 201 } },
              { create: { status: 409, error: { type: 'version_conflict_engine_exception' } } },
              { create: { status: 429, error: { type: 'rejected_execution_exception' } } },
            ],
          },
        })
        .mockResolvedValueOnce({ body: { errors: false, items: [{ index: { status: 201 } }] } }),
    };

    await expect(enqueueAutomationEvents(client, events)).resolves.toEqual({
      enqueued: 1,
      deferred: 0,
      duplicates: 1,
      failed: 1,
      candidateAlertUids: ['a', 'b', 'c'],
    });
    expect(automationEventId('a')).toBe('a');
    expect(automationExecutionId('a', 'snapshot')).toBe('event:a:rules:snapshot');
    expect(client.create).toHaveBeenCalledTimes(1);
    expect(client.create.mock.calls[0][0]).toEqual(expect.objectContaining({
      index: AUTOMATION_EXECUTIONS_INDEX,
      id: expect.stringMatching(/^automation-ruleset:[a-f0-9]{64}$/),
      body: expect.objectContaining({ document_type: 'ruleset_snapshot', rules_snapshot: expect.any(Array) }),
    }));
    expect(client.bulk.mock.calls[0][0].body[1].rules_snapshot).toBeUndefined();
    expect(client.bulk.mock.calls[1][0].body[0].index._index).toBe(AUTOMATION_DLQ_INDEX);
    expect(client.bulk.mock.calls[1][0].body[1].alert_uid).toBe('c');
    const queued = client.bulk.mock.calls[0][0].body[1];
    expect(queued.rules_snapshot).toBeUndefined();
    expect(queued.event_timestamp).toEqual(expect.any(String));
    expect(queued.rule_revisions).toEqual([{ id: 'rule-1', revision: 3 }]);
    expect(queued.admission_cutoff).toEqual(expect.any(String));
    expect(Number.isFinite(Date.parse(queued.admission_cutoff))).toBe(true);
  });

  test('does not create queue writes for alerts outside the immutable ruleset', async () => {
    const client: any = {
      search: jest.fn().mockResolvedValue({ body: { hits: { total: { value: 1 }, hits: [{
        _id: 'rule-1',
        _source: {
          name: 'candidate only', enabled: true, revision: 1, match: { ruleIds: ['5502'] },
          trigger: { type: 'per_alert' }, actions: { createCase: false, setStatus: 'closed' },
        },
      }] } } }),
      create: jest.fn(),
      bulk: jest.fn(),
    };

    await expect(enqueueAutomationEvents(client, [{ alert_uid: 'control', rule: { id: '9999' } }]))
      .resolves.toEqual({
        enqueued: 0, deferred: 0, duplicates: 0, failed: 0, candidateAlertUids: [],
      });
    expect(client.create).not.toHaveBeenCalled();
    expect(client.bulk).not.toHaveBeenCalled();
  });

  test('acknowledges the queue only after evaluation and execution completion', async () => {
    const client: any = workerClient();
    const evaluator = jest.fn(async () => success);

    await expect(runAutomationWorkerOnce(client, logger, 'worker-1', 120, evaluator)).resolves.toBe(true);

    expect(evaluator).toHaveBeenCalledWith(
      client,
      [{ _id: 'alert-1', _source: expect.objectContaining({ alert_uid: 'alert-1' }) }],
      logger,
      undefined,
      {
        id: snapshotId,
        rules: snapshotRules,
        revisions: [{ id: 'rule-1', revision: 3 }],
        admission_cutoff: '2026-08-28T00:00:01.000Z',
      },
      expect.objectContaining({ assertOwned: expect.any(Function), check: expect.any(Function) })
    );
    const stateUpdates = client.update.mock.calls.map((call: any[]) => call[0].body?.doc?.state).filter(Boolean);
    expect(stateUpdates).toEqual(['claimed', 'completed', 'completed']);
    const executionCompletion = client.update.mock.calls.find((call: any[]) => call[0].body?.doc?.state === 'completed');
    expect(executionCompletion[0].body.doc).toEqual(
      expect.objectContaining({ applied_rule_ids: ['rule-1'], counters: success.counters })
    );
  });

  test('carries the admission-time definitions when a rule changes while the event is queued', async () => {
    const client: any = workerClient();
    const evaluator = jest.fn(async (_client: any, _hits: any, _logger: any, _limits?: any, snapshot?: any) => {
      expect(snapshot.rules[0].actions.setStatus).toBe('closed');
      expect(snapshot.revisions).toEqual([{ id: 'rule-1', revision: 3 }]);
      return success;
    });

    // A live rule may now be revision 4/open; the worker must only carry the
    // revision 3/closed definition stored on the admission and queue records.
    client.liveRule = { id: 'rule-1', revision: 4, actions: { setStatus: 'open' } };
    await expect(runAutomationWorkerOnce(client, logger, 'worker-1', 120, evaluator)).resolves.toBe(true);

    expect(evaluator).toHaveBeenCalledTimes(1);
    const execution = client.docs.get(
      `${AUTOMATION_EXECUTIONS_INDEX}/${automationExecutionId('alert-1', snapshotId)}`
    )._source;
    expect(execution.rule_revisions).toEqual([{ id: 'rule-1', revision: 3 }]);
  });

  test('rejects over-limit automation without classifying it as ingestion-unsafe', async () => {
    const client: any = {
      search: jest.fn().mockResolvedValue({
        body: { hits: { total: { value: 201 }, hits: new Array(200).fill(null).map((_, id) => ({
          _id: `rule-${id}`, _source: { enabled: true, revision: 1 },
        })) } },
      }),
      bulk: jest.fn(),
    };

    const error = await enqueueAutomationEvents(client, [{ alert_uid: 'new-alert' }]).catch((value) => value);
    expect(error).toEqual(expect.objectContaining({ automationRulesOverLimit: true }));
    expect(error.automationAdmissionUnsafe).toBeUndefined();
    expect(client.bulk).not.toHaveBeenCalled();
  });

  test('does not evaluate an event whose deterministic execution is already completed', async () => {
    const client: any = workerClient(queueHit(), {
      state: 'completed',
      event_id: 'alert-1',
      holder_id: 'old-worker',
    });
    const evaluator = jest.fn();

    await expect(runAutomationWorkerOnce(client, logger, 'worker-1', 120, evaluator)).resolves.toBe(true);

    expect(evaluator).not.toHaveBeenCalled();
    expect(client.update.mock.calls.some((call: any[]) => call[0].body?.doc?.state === 'completed')).toBe(true);
  });

  test('fails closed when the referenced immutable snapshot is missing', async () => {
    const client: any = workerClient();
    client.docs.delete(`${AUTOMATION_EXECUTIONS_INDEX}/automation-ruleset:${snapshotId}`);
    const evaluator = jest.fn();

    await expect(runAutomationWorkerOnce(client, logger, 'worker-1', 120, evaluator)).resolves.toBe(false);

    expect(evaluator).not.toHaveBeenCalled();
    const states = client.update.mock.calls.map((call: any[]) => call[0].body?.doc?.state).filter(Boolean);
    expect(states).toContain('retry');
  });

  test('uses bounded exponential retry and sends exhausted work to the DLQ', async () => {
    expect(retryDelayMs(1)).toBe(5000);
    expect(retryDelayMs(8)).toBe(300000);
    expect(retryDelayMs(100)).toBe(300000);

    const client: any = workerClient(queueHit(7));
    const evaluator = jest.fn(async () => {
      return {
        status: 'retryable_failure' as const,
        counters: {},
        appliedRuleIds: [],
        failures: [{ stage: 'action_mutation', message: 'action failed' }],
      } as any;
    });

    await expect(runAutomationWorkerOnce(client, logger, 'worker-1', 120, evaluator)).resolves.toBe(false);

    expect(client.bulk).toHaveBeenCalledTimes(1);
    expect(client.bulk.mock.calls[0][0].body[0].index._index).toBe(AUTOMATION_DLQ_INDEX);
    const states = client.update.mock.calls.map((call: any[]) => call[0].body?.doc?.state).filter(Boolean);
    expect(states).toContain('dlq');
  });

  test('releases transient failures into retry without writing the DLQ', async () => {
    const client: any = workerClient(queueHit(1));
    const evaluator = jest.fn(async () => {
      return {
        status: 'retryable_failure' as const,
        counters: {},
        appliedRuleIds: [],
        failures: [{ stage: 'rule_loading', message: 'temporary failure' }],
      } as any;
    });

    await expect(runAutomationWorkerOnce(client, logger, 'worker-1', 120, evaluator)).resolves.toBe(false);

    expect(client.bulk).not.toHaveBeenCalled();
    const retryUpdates = client.update.mock.calls
      .map((call: any[]) => call[0].body?.doc)
      .filter((doc: any) => doc?.state === 'retry');
    expect(retryUpdates).toHaveLength(2);
    expect(retryUpdates[1].available_at).toEqual(expect.any(String));
  });

  test('claim query includes expired claimed items for replica failover', async () => {
    const client: any = workerClient();
    await runAutomationWorkerOnce(client, logger, 'worker-1', 120, jest.fn(async () => success));

    const query = client.search.mock.calls[0][0].body.query;
    expect(client.search.mock.calls[0][0].body.sort).toEqual([
      { available_at: 'asc' },
      { event_timestamp: { order: 'asc', missing: '_last', unmapped_type: 'date' } },
      { enqueued_at: 'asc' },
      { event_id: 'asc' },
    ]);
    expect(query.bool.should).toContainEqual({
      bool: { must: [{ term: { state: 'claimed' } }, { range: { lease_expires_at: { lte: expect.any(String) } } }] },
    });
  });

  test('refreshes worker, queue, and execution leases during evaluation longer than 120 seconds', async () => {
    jest.useFakeTimers();
    const client: any = workerClient();
    const evaluator = jest.fn(async () => {
      jest.advanceTimersByTime(130000);
      await Promise.resolve();
      await Promise.resolve();
      return success;
    });

    await expect(runAutomationWorkerOnce(client, logger, 'worker-1', 120, evaluator)).resolves.toBe(true);

    const leaseRefreshes = client.update.mock.calls.filter((call: any[]) =>
      call[0].body?.doc?.lease_expires_at && !call[0].body?.doc?.state
    );
    expect(leaseRefreshes.map((call: any[]) => call[0].index)).toEqual(expect.arrayContaining([
      AUTOMATION_QUEUE_INDEX,
      AUTOMATION_EXECUTIONS_INDEX,
    ]));
    jest.useRealTimers();
  });

  test('aborts acknowledgment when a heartbeat observes execution lease loss', async () => {
    jest.useFakeTimers();
    const client: any = workerClient();
    const evaluator = jest.fn(async () => {
      const key = `${AUTOMATION_EXECUTIONS_INDEX}/${automationExecutionId('alert-1', snapshotId)}`;
      const execution = client.docs.get(key);
      client.docs.set(key, { ...execution, _source: { ...execution._source, lease_token: 'successor-token' } });
      jest.advanceTimersByTime(40000);
      await Promise.resolve();
      await Promise.resolve();
      return success;
    });

    await expect(runAutomationWorkerOnce(client, logger, 'worker-1', 120, evaluator)).resolves.toBe(false);
    const queue = client.docs.get(`${AUTOMATION_QUEUE_INDEX}/alert-1`)._source;
    expect(queue.state).toBe('claimed');
    jest.useRealTimers();
  });

  test.each([
    ['worker', AUTOMATION_EXECUTIONS_INDEX, AUTOMATION_WORKER_LEASE_ID],
    ['claim', AUTOMATION_QUEUE_INDEX, 'alert-1'],
    ['execution', AUTOMATION_EXECUTIONS_INDEX, automationExecutionId('alert-1', snapshotId)],
  ])('rejects an expired %s lease before evaluator side effects', async (_lease, index, id) => {
    const client: any = workerClient();
    const sideEffect = jest.fn();
    const evaluator = jest.fn(async (_client: any, _hits: any, _logger: any, _limits: any, _snapshot: any, guard: any) => {
      const key = `${index}/${id}`;
      const current = client.docs.get(key);
      client.docs.set(key, {
        ...current,
        _source: { ...current._source, lease_expires_at: '2000-01-01T00:00:00.000Z' },
      });
      await guard.assertOwned();
      sideEffect();
      return success;
    });

    await expect(runAutomationWorkerOnce(client, logger, 'worker-1', 120, evaluator)).resolves.toBe(false);

    expect(sideEffect).not.toHaveBeenCalled();
    const evaluatorError = await evaluator.mock.results[0].value.catch((value: any) => value);
    expect(evaluatorError).toEqual(expect.objectContaining({ ownershipLost: true }));
  });

  test('a successor global lease prevents evaluator side effects', async () => {
    const client: any = workerClient();
    const sideEffect = jest.fn();
    const evaluator = jest.fn(async (_client: any, _hits: any, _logger: any, _limits: any, _snapshot: any, guard: any) => {
      const key = `${AUTOMATION_EXECUTIONS_INDEX}/${AUTOMATION_WORKER_LEASE_ID}`;
      const current = client.docs.get(key);
      client.docs.set(key, { ...current, _source: {
        ...current._source,
        holder_id: 'worker-2',
        fencing_generation: Number(current._source.fencing_generation) + 1,
        lease_token: 'successor-token',
        lease_expires_at: new Date(Date.now() + 120000).toISOString(),
      } });
      await guard.assertOwned();
      sideEffect();
      return success;
    });

    await expect(runAutomationWorkerOnce(client, logger, 'worker-1', 120, evaluator)).resolves.toBe(false);

    expect(sideEffect).not.toHaveBeenCalled();
    const evaluatorError = await evaluator.mock.results[0].value.catch((value: any) => value);
    expect(evaluatorError).toEqual(expect.objectContaining({ ownershipLost: true }));
  });

  test('takes over expired work with a higher fencing generation', async () => {
    const hit = queueHit(1, 'claimed');
    hit._source.holder_id = 'dead-worker';
    hit._source.fencing_generation = 7;
    hit._source.lease_token = 'dead-token';
    hit._source.lease_expires_at = '2000-01-01T00:00:00.000Z';
    const client: any = workerClient(hit);
    client.docs.set(`${AUTOMATION_EXECUTIONS_INDEX}/automation-worker-lease`, {
      _seq_no: 1,
      _primary_term: 1,
      _source: {
        state: 'lease', holder_id: 'dead-worker', fencing_generation: 7, lease_token: 'dead-token',
        lease_expires_at: '2000-01-01T00:00:00.000Z',
      },
    });

    await expect(runAutomationWorkerOnce(client, logger, 'worker-2', 120, jest.fn(async () => success))).resolves.toBe(true);
    const lease = client.docs.get(`${AUTOMATION_EXECUTIONS_INDEX}/automation-worker-lease`)._source;
    expect(lease.fencing_generation).toBe(8);
  });

  test('uses independent bounded cluster-wide leases for concurrent worker lanes', async () => {
    const client: any = workerClient();
    const laneLease = automationWorkerLeaseId(1);

    await expect(runAutomationWorkerOnce(
      client,
      logger,
      'worker-lane-1',
      120,
      jest.fn(async () => success),
      laneLease
    )).resolves.toBe(true);

    expect(laneLease).toBe(`${AUTOMATION_WORKER_LEASE_ID}:1`);
    expect(client.docs.get(`${AUTOMATION_EXECUTIONS_INDEX}/${laneLease}`)._source.holder_id)
      .toBe('worker-lane-1');
    expect(() => automationWorkerLeaseId(8)).toThrow(/between 0 and 7/);
  });

  test('claims, evaluates, and acknowledges a durable batch under one lane fence', async () => {
    const client: any = workerClient();
    const evaluator = jest.fn(async () => success);

    await expect(runAutomationWorkerBatchOnce(client, logger, 'batch-worker', 0, 120, 64, evaluator))
      .resolves.toBe(true);

    expect(evaluator).toHaveBeenCalledWith(
      client,
      [{ _id: 'alert-1', _source: expect.objectContaining({ alert_uid: 'alert-1' }) }],
      logger,
      undefined,
      expect.objectContaining({ id: snapshotId, admission_cutoff: '2026-08-28T00:00:01.000Z' }),
      expect.objectContaining({ assertOwned: expect.any(Function) })
    );
    expect(client.docs.get(`${AUTOMATION_QUEUE_INDEX}/alert-1`)._source.state).toBe('completed');
    expect(client.docs.get(
      `${AUTOMATION_EXECUTIONS_INDEX}/${automationExecutionId('alert-1', snapshotId)}`
    )._source.state).toBe('completed');
    expect(client.mget.mock.calls[0][0]).not.toHaveProperty('seq_no_primary_term');
  });

  test('manual DLQ retry resets attempts and is idempotent after resolution', async () => {
    const dlqHit = {
      _id: 'execution:alert-1', _seq_no: 2, _primary_term: 1,
      _source: { event_id: 'alert-1', ruleset_snapshot: 'snapshot-1', payload: { alert_uid: 'alert-1' } },
    };
    const client: any = {
      search: jest.fn().mockResolvedValueOnce({ body: { hits: { hits: [dlqHit] } } })
        .mockResolvedValueOnce({ body: { hits: { hits: [] } } }),
      get: jest.fn()
        .mockResolvedValueOnce({ body: { _seq_no: 3, _primary_term: 1, _source: { state: 'dlq', attempts: 8 } } })
        .mockResolvedValueOnce({ body: { _source: { state: 'retry', attempts: 0 } } }),
      update: jest.fn().mockResolvedValue({}),
      delete: jest.fn().mockResolvedValue({}),
    };

    await expect(retryAutomationDlqEvent(client, 'alert-1')).resolves.toEqual({
      eventId: 'alert-1', state: 'retry', attempts: 0,
    });
    expect(client.update.mock.calls[0][0].body.doc.attempts).toBe(0);
    expect(client.update.mock.calls[1][0].body.doc.attempts).toBe(0);
    await expect(retryAutomationDlqEvent(client, 'alert-1')).resolves.toEqual({
      eventId: 'alert-1', state: 'retry', idempotent: true,
    });
  });

  test('reconciles only bounded unfinished admission markers with their original rule revisions', async () => {
    const client: any = {
      get: jest.fn().mockRejectedValue(notFound()),
      search: jest.fn(async ({ index, body }: any) => {
        if (index === AUTOMATION_EXECUTIONS_INDEX) return { body: { hits: { hits: [{ _source: {
          event_id: 'new-alert', state: 'admission_pending', admission_reason: 'first_ingestion',
          payload: { alert_uid: 'new-alert' },
          ruleset_snapshot: 'old-snapshot',
          rule_revisions: [{ id: 'rule-old', revision: 7 }],
          admission_cutoff: '2026-08-28T00:00:02.000Z',
        } }] } } };
        return { body: { aggregations: { states: { buckets: [] } } } };
      }),
      bulk: jest.fn()
        .mockResolvedValueOnce({ body: { errors: false, items: [{ create: { status: 201 } }] } })
        .mockResolvedValueOnce({ body: { errors: false, items: [{ update: { status: 200 } }] } }),
    };

    await expect(reconcileAutomationAdmissions(client)).resolves.toEqual({
      enqueued: 1, deferred: 0, duplicates: 0, failed: 0,
    });

    const recoveryQuery = client.search.mock.calls[0][0].body;
    expect(recoveryQuery).toEqual(expect.objectContaining({
      size: 100,
      query: { term: { state: 'admission_pending' } },
    }));
    expect(JSON.stringify(recoveryQuery)).not.toContain('wazuh-alert-status');
    expect(client.bulk.mock.calls[0][0].body[1]).toEqual(expect.objectContaining({
      alert_uid: 'new-alert', ruleset_snapshot: 'old-snapshot',
      rule_revisions: [{ id: 'rule-old', revision: 7 }],
      admission_cutoff: '2026-08-28T00:00:02.000Z',
    }));
    expect(client.bulk.mock.calls[0][0].body[1].rules_snapshot).toBeUndefined();
  });

  test('chunks bulk metadata/source pairs by action count without splitting pairs', () => {
    const body = Array.from({ length: 501 }, (_, id) => [
      { create: { _index: AUTOMATION_QUEUE_INDEX, _id: String(id) } },
      { event_id: String(id), payload: { alert_uid: String(id) } },
    ]).reduce((all: any[], pair) => all.concat(pair), []);
    const chunks = chunkBulkPairs(body);
    expect(chunks.map((chunk) => chunk.length / 2)).toEqual([500, 1]);
    expect(chunks.every((chunk) => chunk.length % 2 === 0)).toBe(true);
  });

  test('requests an exact backlog count for queue health and admission gating', async () => {
    const client: any = {
      search: jest.fn().mockResolvedValue({ body: {
        hits: { total: { value: 100000, relation: 'eq' } },
        aggregations: {
          oldest: { value: null }, retries: { doc_count: 7 },
          states: { buckets: [{ key: 'pending', doc_count: 98616 }] },
          max_fencing_generation: { value: 1 },
        },
      } }),
      count: jest.fn().mockResolvedValue({ body: { count: 0 } }),
      get: jest.fn().mockRejectedValue(notFound()),
    };

    const health = await automationQueueHealth(client);

    expect(client.search.mock.calls[0][0].body.track_total_hits).toBe(true);
    expect(health.lag).toBe(100000);
    expect(health.admissionOpen).toBe(false);
  });
});
