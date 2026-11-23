import { ALERTS_READ_ALIAS, META_INDEX, SLA_DUE_BACKFILL_DOC_ID } from '../../../common';
import {
  beginSlaDueBackfill,
  buildDueBackfillScript,
  dueBackfillQuery,
  readSlaDueBackfillStatus,
  runSlaDueBackfill,
  sanitizeBackfillError,
  scheduleSlaDueBackfill,
  SLA_DUE_BACKFILL_LEASE_ID,
  SLA_DUE_BACKFILL_LEASE_TTL_MS,
} from './due_backfill';
import { DEFAULT_SLA_POLICY } from './policy';

const policy = {
  targets: {
    critical: { resolveMinutes: 30, assignMinutes: 5 },
    high: { resolveMinutes: 120, assignMinutes: 20 },
    medium: { resolveMinutes: 600, assignMinutes: 60 },
    low: { resolveMinutes: 2880, assignMinutes: 240 },
  },
  escalations: [],
};

type UpdateResult = any | Error | Array<any | Error>;

interface ClientOptions {
  leaseHeldBy?: string;
  /** Answer the update_by_query as a task; `polls` = the number of `tasks.get` calls before `completed`. */
  task?: { polls: number; updatedWhileRunning?: number; error?: any };
}

/**
 * Test double. `updateResult` is the final body of one pass (an Error to
 * throw), or an array with one entry per pass. Without `task` the client
 * answers the update_by_query inline (no task id); with it the call returns a
 * task id and `tasks.get` reports the run.
 */
function clientWith(updateResult: UpdateResult = { updated: 42, version_conflicts: 0, failures: [] }, opts: ClientOptions = {}) {
  const docs = new Map<string, any>();
  if (opts.leaseHeldBy) {
    docs.set(`lease:${SLA_DUE_BACKFILL_LEASE_ID}`, {
      document_type: 'lease', lease_id: SLA_DUE_BACKFILL_LEASE_ID, holder_id: opts.leaseHeldBy,
      expires_at: new Date(Date.now() + 60000).toISOString(), updated_at: new Date().toISOString(),
    });
  }
  const results: Array<any | Error> = Array.isArray(updateResult) ? [...updateResult] : [updateResult];
  const nextResult = () => (results.length > 1 ? results.shift() : results[0]);
  let taskSeq = 0;
  const tasks = new Map<string, { result: any | Error; polls: number }>();
  const client: any = {
    docs,
    get: jest.fn(async ({ id }: any) => {
      if (!docs.has(id)) throw Object.assign(new Error('not found'), { meta: { statusCode: 404 } });
      return { body: { _id: id, _source: docs.get(id), _seq_no: 1, _primary_term: 1 } };
    }),
    index: jest.fn(async ({ id, body }: any) => {
      docs.set(id, body);
      return { body: { result: 'created' } };
    }),
    create: jest.fn(async ({ id, body }: any) => {
      if (docs.has(id)) throw Object.assign(new Error('exists'), { meta: { statusCode: 409 } });
      docs.set(id, body);
      return { body: { result: 'created' } };
    }),
    update: jest.fn(async ({ id, body }: any) => {
      docs.set(id, { ...(docs.get(id) || {}), ...(body?.doc || {}) });
      return { body: { result: 'updated' } };
    }),
    delete: jest.fn(async ({ id }: any) => {
      docs.delete(id);
      return { body: { result: 'deleted' } };
    }),
    updateByQuery: jest.fn(async () => {
      const result = nextResult();
      if (!opts.task) {
        if (result instanceof Error) throw result;
        return { body: result };
      }
      const id = `node:${++taskSeq}`;
      tasks.set(id, { result, polls: opts.task.polls });
      return { body: { task: id } };
    }),
    tasks: {
      get: jest.fn(async ({ task_id }: any) => {
        const task = tasks.get(task_id)!;
        if (task.polls > 0) {
          task.polls -= 1;
          return { body: { completed: false, task: { status: { updated: opts.task?.updatedWhileRunning ?? 0 } } } };
        }
        if (task.result instanceof Error) return { body: { completed: true, error: { type: 'script_exception', reason: task.result.message } } };
        return { body: { completed: true, task: { status: { updated: task.result.updated } }, response: task.result } };
      }),
      cancel: jest.fn(async () => ({ body: {} })),
    },
  };
  return client;
}

const logger = { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() };
let tick = 0;
const now = () => `2026-11-21T10:${String(tick++).padStart(2, '0')}:00.000Z`;
const fast = { now, holder: 'h1', pollIntervalMs: 1 };

describe('SLA due-date backfill (step 3.2)', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    tick = 0;
  });

  test('the painless script recomputes both due fields from @timestamp and the band for either family', () => {
    const script = buildDueBackfillScript(policy);
    expect(script.lang).toBe('painless');
    expect(script.params.targets).toEqual({
      critical: { resolve: 30 * 60000, assign: 5 * 60000 },
      high: { resolve: 120 * 60000, assign: 20 * 60000 },
      medium: { resolve: 600 * 60000, assign: 60 * 60000 },
      low: { resolve: 2880 * 60000, assign: 240 * 60000 },
    });
    // Band floors are the plugin's one severity model.
    expect(script.params.floors).toEqual({ critical: 12, high: 7, medium: 4 });
    // 5.0 labels (and their aliases) map onto the SLA bands; informational counts as low.
    expect(script.params.labelBands).toMatchObject({ informational: 'low', low: 'low', medium: 'medium', high: 'high', critical: 'critical', severe: 'critical' });
    expect(script.source).toContain('ctx._source.rule.level');
    expect(script.source).toContain('ctx._source.severity_label');
    expect(script.source).toContain("ctx._source['@timestamp']");
    expect(script.source).toContain('ctx._source.reporting.sla_due_at = due');
    expect(script.source).toContain('ctx._source.reporting.assign_due_at = assign');
    // Records without a severity or timestamp, and unchanged ones, are no-ops.
    expect(script.source).toContain("ctx.op = 'noop'");
  });

  test('without a policy the built-in targets apply', () => {
    const script = buildDueBackfillScript(null);
    expect(script.params.targets.critical).toEqual({ resolve: 60 * 60000, assign: 15 * 60000 });
    expect(buildDueBackfillScript(DEFAULT_SLA_POLICY).params.targets).toEqual(script.params.targets);
  });

  test('submits one update_by_query task over the live alert alias for open/in_progress alerts only and records the run', async () => {
    const client = clientWith({ updated: 42, version_conflicts: 0, failures: [] });
    const result = await runSlaDueBackfill(client, logger, policy, { ...fast, policyVersion: '2026-11-21T09:00:00.000Z' });

    expect(client.updateByQuery).toHaveBeenCalledTimes(1);
    const request = client.updateByQuery.mock.calls[0][0];
    expect(request.index).toBe(ALERTS_READ_ALIAS); // through assertManagedWriteTarget
    expect(request.conflicts).toBe('proceed');
    expect(request.wait_for_completion).toBe(false);
    expect(request.requests_per_second).toBe(500);
    expect(request.body.query).toEqual(dueBackfillQuery());
    expect(request.body.query).toEqual({ bool: { filter: [{ terms: { status: ['open', 'in_progress'] } }] } });
    expect(request.body.script).toEqual(buildDueBackfillScript(policy));

    expect(result).toEqual({
      status: 'completed',
      started_at: '2026-11-21T10:00:00.000Z',
      finished_at: '2026-11-21T10:01:00.000Z',
      heartbeat_at: null,
      updated: 42,
      failures: 0,
      version_conflicts: 0,
      policy_version: '2026-11-21T09:00:00.000Z',
      error: null,
    });
    // Status doc: written as "running" first, then with the outcome; lease released.
    const statusWrites = client.index.mock.calls.filter(([req]: any[]) => req.id === SLA_DUE_BACKFILL_DOC_ID);
    expect(statusWrites).toHaveLength(2);
    expect(statusWrites[0][0]).toMatchObject({ index: META_INDEX, refresh: 'wait_for', body: { status: 'running', finished_at: null } });
    expect(statusWrites[1][0].body).toMatchObject({ document_type: 'sla_due_backfill', status: 'completed', updated: 42 });
    expect(client.docs.has(`lease:${SLA_DUE_BACKFILL_LEASE_ID}`)).toBe(false);
    expect(await readSlaDueBackfillStatus(client)).toEqual(result);
  });

  test('a long task is polled through the tasks API: progress and heartbeat recorded, lease renewed, HTTP call never awaited', async () => {
    const client = clientWith({ updated: 30000, version_conflicts: 0, failures: [] }, { task: { polls: 3, updatedWhileRunning: 12000 } });
    const started = await beginSlaDueBackfill(client, logger, policy, fast);
    expect(started.status.status).toBe('running');
    const result = await started.completion;
    expect(result.status).toBe('completed');
    expect(result.updated).toBe(30000);
    expect(client.tasks.get).toHaveBeenCalledTimes(4);
    expect(client.tasks.get.mock.calls[0][0]).toEqual({ task_id: 'node:1' });
    // Three progress writes (refresh: false) between the running and the final write.
    const progressWrites = client.index.mock.calls.filter(([req]: any[]) => req.id === SLA_DUE_BACKFILL_DOC_ID && req.refresh === false);
    expect(progressWrites).toHaveLength(3);
    expect(progressWrites[0][0].body).toMatchObject({ status: 'running', updated: 12000 });
    expect(progressWrites[0][0].body.heartbeat_at).toMatch(/^2026-11-21T10:/);
    // The lease was renewed on every poll (update with if_seq_no on the lease doc).
    const renewals = client.update.mock.calls.filter(([req]: any[]) => req.id === `lease:${SLA_DUE_BACKFILL_LEASE_ID}`);
    expect(renewals.length).toBeGreaterThanOrEqual(3);
    expect(client.docs.has(`lease:${SLA_DUE_BACKFILL_LEASE_ID}`)).toBe(false);
  });

  test('a task that ends in error is recorded failed with a sanitised message', async () => {
    const client = clientWith(new Error('runtime error in wazuh-alert-status-v2-000001'), { task: { polls: 1 } });
    const result = await runSlaDueBackfill(client, logger, policy, fast);
    expect(result.status).toBe('failed');
    expect(result.error).toBe('script_exception');
    expect(result.error).not.toContain('wazuh-alert-status');
    expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('wazuh-alert-status-v2-000001'));
  });

  test('documents that changed concurrently are re-run in a bounded number of passes', async () => {
    const client = clientWith([
      { updated: 40, version_conflicts: 2, failures: [] },
      { updated: 2, version_conflicts: 0, failures: [] },
    ]);
    const result = await runSlaDueBackfill(client, logger, policy, fast);
    expect(client.updateByQuery).toHaveBeenCalledTimes(2);
    expect(result).toMatchObject({ status: 'completed', updated: 42, version_conflicts: 0, failures: 0, error: null });
  });

  test('conflicts left after the last pass make the run partial, never completed', async () => {
    const client = clientWith({ updated: 1, version_conflicts: 1, failures: [] });
    const result = await runSlaDueBackfill(client, logger, policy, { ...fast, maxPasses: 3 });
    expect(client.updateByQuery).toHaveBeenCalledTimes(3);
    expect(result).toMatchObject({ status: 'partial', updated: 3, version_conflicts: 1, failures: 0 });
    expect(result.error).toMatch(/run the backfill again/);
    expect(client.docs.get(SLA_DUE_BACKFILL_DOC_ID)).toMatchObject({ status: 'partial' });
  });

  test('bulk failures stop the passes and record the run failed', async () => {
    const client = clientWith({ updated: 5, version_conflicts: 3, failures: [{ id: 'x' }] });
    const result = await runSlaDueBackfill(client, logger, policy, fast);
    expect(client.updateByQuery).toHaveBeenCalledTimes(1);
    expect(result).toMatchObject({ status: 'failed', updated: 5, failures: 1, version_conflicts: 3, error: '1 document(s) failed to update' });
  });

  test('a thrown client error is recorded on the status doc (sanitised) and returned, never thrown', async () => {
    const client = clientWith(Object.assign(new Error('Request timed out'), { name: 'TimeoutError' }));
    const result = await runSlaDueBackfill(client, logger, policy, fast);
    expect(result.status).toBe('failed');
    expect(result.error).toBe('request timed out');
    expect(result.finished_at).toBe('2026-11-21T10:01:00.000Z');
    expect(client.docs.get(SLA_DUE_BACKFILL_DOC_ID)).toMatchObject({ status: 'failed', error: 'request timed out' });
    expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('Request timed out'));
    expect(client.docs.has(`lease:${SLA_DUE_BACKFILL_LEASE_ID}`)).toBe(false);
  });

  test('sanitizeBackfillError never echoes the raw message', () => {
    expect(sanitizeBackfillError(new Error('index wazuh-alert-status-v2-000001 blocked'))).toBe('unexpected error');
    expect(sanitizeBackfillError(Object.assign(new Error('x'), { meta: { statusCode: 403, body: { error: { type: 'security_exception', reason: 'no permissions for [indices:data/write/update/byquery] on wazuh-alert-status-v2-read' } } } }))).toBe('security_exception (HTTP 403)');
    expect(sanitizeBackfillError(Object.assign(new Error('x'), { meta: { statusCode: 503 } }))).toBe('request failed (HTTP 503)');
    expect(sanitizeBackfillError(Object.assign(new Error('x'), { name: 'ConnectionError' }))).toBe('connection failed');
  });

  test('a run that cannot take the lease is skipped and writes nothing', async () => {
    const client = clientWith(undefined, { leaseHeldBy: 'other-replica' });
    const result = await runSlaDueBackfill(client, logger, policy, fast);
    expect(result.status).toBe('skipped');
    expect(client.updateByQuery).not.toHaveBeenCalled();
    expect(client.index).not.toHaveBeenCalled();
    expect(client.docs.get(`lease:${SLA_DUE_BACKFILL_LEASE_ID}`).holder_id).toBe('other-replica');
  });

  test('readSlaDueBackfillStatus answers null before the first run and reports a dead run as failed', async () => {
    expect(await readSlaDueBackfillStatus(clientWith())).toBeNull();
    const client = clientWith();
    const startedAt = '2026-11-21T08:00:00.000Z';
    client.docs.set(SLA_DUE_BACKFILL_DOC_ID, {
      document_type: 'sla_due_backfill', status: 'running', started_at: startedAt, finished_at: null,
      heartbeat_at: '2026-11-21T08:05:00.000Z', updated: 10, failures: 0, version_conflicts: 0, policy_version: null, error: null,
    });
    // Fresh heartbeat: still running.
    const fresh = await readSlaDueBackfillStatus(client, () => new Date(Date.parse('2026-11-21T08:05:00.000Z') + SLA_DUE_BACKFILL_LEASE_TTL_MS - 1).toISOString());
    expect(fresh).toMatchObject({ status: 'running', updated: 10 });
    // Heartbeat older than the lease TTL: the process died.
    const stale = await readSlaDueBackfillStatus(client, () => new Date(Date.parse('2026-11-21T08:05:00.000Z') + SLA_DUE_BACKFILL_LEASE_TTL_MS + 1).toISOString());
    expect(stale).toMatchObject({ status: 'failed', error: expect.stringContaining('stale run') });
  });

  test('beginSlaDueBackfill resolves with the running status before the task finishes', async () => {
    const client = clientWith({ updated: 1, version_conflicts: 0, failures: [] }, { task: { polls: 2 } });
    const started = await beginSlaDueBackfill(client, logger, policy, { ...fast, pollIntervalMs: 20 });
    expect(started.status).toMatchObject({ status: 'running', updated: 0, finished_at: null });
    expect(client.docs.get(SLA_DUE_BACKFILL_DOC_ID)).toMatchObject({ status: 'running' });
    expect(client.tasks.get).not.toHaveBeenCalled();
    const finished = await started.completion;
    expect(finished.status).toBe('completed');
  });

  test('scheduleSlaDueBackfill never rejects', async () => {
    const client = clientWith();
    client.index.mockRejectedValue(new Error('meta unavailable'));
    expect(() => scheduleSlaDueBackfill(client, logger, policy, fast)).not.toThrow();
    for (let i = 0; i < 5; i += 1) await new Promise((resolve) => setTimeout(resolve, 2));
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('could not record the backfill'));
  });
});
