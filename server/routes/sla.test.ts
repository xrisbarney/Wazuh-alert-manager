import { API_ROOT, ACTIVITY_WRITE_ALIAS, META_INDEX, SLA_POLICY_DOC_ID } from '../../common';
import { defineSlaRoutes, policyAuditSummary, slaPolicyBodySchema } from './sla';
import { DEFAULT_SLA_POLICY, getSlaPolicy, invalidateSlaPolicyCache } from '../lib/sla/policy';

jest.mock('../lib/authorization', () => ({ requirePluginAdmin: jest.fn(), isPluginAdmin: jest.fn(() => false) }));
jest.mock('../lib/identity', () => ({
  trustedIdentity: jest.fn(async () => ({ name: 'analyst', source: 'security_plugin', roles: [], securityRoles: ['kibana_user'], backendRoles: [] })),
}));
jest.mock('../lib/sla/due_backfill', () => ({
  readSlaDueBackfillStatus: jest.fn(),
  beginSlaDueBackfill: jest.fn(),
  scheduleSlaDueBackfill: jest.fn(),
}));
jest.mock('../lib/sla/escalation', () => ({
  getSlaEscalationRuntime: jest.fn(() => ({ enabled: true, tickSeconds: 60 })),
  readSlaEscalationStatus: jest.fn(),
}));

// eslint-disable-next-line @typescript-eslint/no-var-requires
const escalationModule = require('../lib/sla/escalation');

// eslint-disable-next-line @typescript-eslint/no-var-requires
const dueBackfill = require('../lib/sla/due_backfill');

// eslint-disable-next-line @typescript-eslint/no-var-requires
const requirePluginAdmin: jest.Mock = require('../lib/authorization').requirePluginAdmin;
// eslint-disable-next-line @typescript-eslint/no-var-requires
const isPluginAdmin: jest.Mock = require('../lib/authorization').isPluginAdmin;

function forbidden() {
  const error: any = new Error('Administrator permission is required for this operation.');
  error.statusCode = 403;
  throw error;
}

function clientWith(settings: any | null) {
  const writes: any[] = [];
  const client = {
    get: jest.fn(async (req: any) => {
      if (req.index === META_INDEX && req.id === SLA_POLICY_DOC_ID && settings !== null) return { body: { _source: settings } };
      throw Object.assign(new Error('not found'), { meta: { statusCode: 404 } });
    }),
    index: jest.fn(async (req: any) => {
      writes.push(req);
      if (req.index === META_INDEX) settings = req.body;
      return { body: { result: 'created' } };
    }),
    writes,
  };
  return client;
}

function response() {
  return {
    ok: jest.fn((r: any) => ({ kind: 'ok', ...r })),
    accepted: jest.fn((r: any) => ({ kind: 'accepted', ...r })),
    badRequest: jest.fn((r: any) => ({ kind: 'badRequest', ...r })),
    forbidden: jest.fn((r: any) => ({ kind: 'forbidden', ...r })),
    notFound: jest.fn((r: any) => ({ kind: 'notFound', ...r })),
    customError: jest.fn((r: any) => ({ kind: 'customError', ...r })),
  };
}

function routes() {
  const router: any = { get: jest.fn(), post: jest.fn(), put: jest.fn() };
  defineSlaRoutes(router);
  const find = (method: 'get' | 'put' | 'post', path = '/sla/policy') => {
    const registration = router[method].mock.calls.find(([config]: any[]) => config.path === `${API_ROOT}${path}`);
    expect(registration).toBeDefined();
    return registration as [any, any];
  };
  return {
    getPolicy: find('get'),
    putPolicy: find('put'),
    getBackfill: find('get', '/sla/backfill'),
    postBackfill: find('post', '/sla/backfill'),
    getEscalationStatus: find('get', '/sla/escalation/status'),
  };
}

const context = (client: any) => ({ core: { opensearch: { client: { asCurrentUser: client } } } });

const targets = {
  critical: { resolveMinutes: 30, assignMinutes: 5 },
  high: { resolveMinutes: 120, assignMinutes: 20 },
  medium: { resolveMinutes: 600, assignMinutes: 60 },
  low: { resolveMinutes: 2880, assignMinutes: 240 },
};

describe('SLA policy routes', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    invalidateSlaPolicyCache();
    requirePluginAdmin.mockResolvedValue({ name: 'admin', isPluginAdmin: true });
  });

  test('GET is open to any signed-in user and answers the defaults when nothing is stored', async () => {
    const { getPolicy } = routes();
    expect(getPolicy[0].validate).toBe(false);
    requirePluginAdmin.mockImplementation(forbidden);
    const out = await getPolicy[1](context(clientWith(null)), {}, response());
    expect(out.kind).toBe('ok');
    expect(out.body.policy).toEqual({ targets: DEFAULT_SLA_POLICY.targets, escalations: [] });
    expect(out.body.defaults).toEqual(DEFAULT_SLA_POLICY);
    expect(out.body.updated_by).toBeUndefined();
    expect(requirePluginAdmin).not.toHaveBeenCalled();
  });

  test('PUT validates its body with @osd/config-schema and is administrator-only', async () => {
    const { putPolicy } = routes();
    expect(putPolicy[0].validate.body).toBe(slaPolicyBodySchema);
    expect(() => slaPolicyBodySchema.validate({ targets })).not.toThrow();
    expect(() => slaPolicyBodySchema.validate({ targets: { ...targets, low: { resolveMinutes: 0, assignMinutes: 1 } } })).toThrow();
    expect(() => slaPolicyBodySchema.validate({ targets: { critical: targets.critical } })).toThrow();
    expect(() => slaPolicyBodySchema.validate({ targets, escalations: [{ id: 'x' }] })).toThrow();
    expect(() => slaPolicyBodySchema.validate({ targets, extra: 1 })).toThrow();
    const validated: any = slaPolicyBodySchema.validate({
      targets,
      escalations: [{ id: 'e1', name: 'Nudge', target: 'alert', thresholdPercent: 50, condition: 'unassigned', actions: { assignTo: 'oncall' } }],
    });
    expect(validated.escalations[0].enabled).toBe(true);

    requirePluginAdmin.mockImplementation(forbidden);
    const client = clientWith(null);
    const out = await putPolicy[1](context(client), { body: { targets, escalations: [] } }, response());
    expect(out.kind).toBe('forbidden');
    expect(client.index).not.toHaveBeenCalled();
  });

  test('PUT replaces the policy, audits it, invalidates the cache and GET reads it back', async () => {
    const { putPolicy, getPolicy } = routes();
    const client = clientWith(null);
    // Warm the cache with the defaults so the test proves the PUT invalidates it.
    expect((await getSlaPolicy(client)).targets.critical.resolveMinutes).toBe(60);
    const out = await putPolicy[1](context(client), { body: { targets, escalations: [] } }, response());
    expect(out.kind).toBe('ok');
    expect(out.body.policy).toEqual({ targets, escalations: [] });
    expect(out.body.updated_by).toBe('admin');
    expect(out.body.defaults).toEqual(DEFAULT_SLA_POLICY);
    const meta = client.writes.find((w) => w.index === META_INDEX);
    expect(meta).toMatchObject({ id: SLA_POLICY_DOC_ID, refresh: 'wait_for' });
    expect(meta.body.targets).toEqual(targets);
    const audit = client.writes.find((w) => w.index === ACTIVITY_WRITE_ALIAS);
    expect(audit.body).toMatchObject({
      action: 'sla_policy_updated',
      user: 'admin',
      target_type: 'system',
      target_id: SLA_POLICY_DOC_ID,
      from: 'critical=60/15,high=240/60,medium=1440/360,low=4320/1080;escalations=0',
      to: 'critical=30/5,high=120/20,medium=600/60,low=2880/240;escalations=0',
    });
    expect((await getSlaPolicy(client)).targets.critical.resolveMinutes).toBe(30);
    const read = await getPolicy[1](context(client), {}, response());
    expect(read.body.policy.targets).toEqual(targets);
    expect(read.body.updated_by).toBe('admin');
    // The due-date backfill is scheduled fire-and-forget with the saved policy (step 3.2).
    expect(dueBackfill.scheduleSlaDueBackfill).toHaveBeenCalledTimes(1);
    const [scheduledClient, , scheduledPolicy, scheduledOptions] = dueBackfill.scheduleSlaDueBackfill.mock.calls[0];
    expect(scheduledClient).toBe(client);
    expect(scheduledPolicy.targets).toEqual(targets);
    expect(scheduledOptions.policyVersion).toBe(out.body.updated_at);
  });

  test('a PUT whose targets equal the stored ones (escalation-only edit, no-op save) schedules no backfill', async () => {
    const { putPolicy } = routes();
    const stored = { targets, escalations: [], updated_at: '2026-11-21T09:00:00.000Z', updated_by: 'admin' };
    const client = clientWith(stored);
    const escalations = [{ id: 'e1', name: 'Nudge', target: 'alert', thresholdPercent: 50, condition: 'unassigned', actions: { assignTo: 'oncall' }, enabled: true }];
    const out = await putPolicy[1](context(client), { body: { targets: { ...targets, low: { ...targets.low } }, escalations } }, response());
    expect(out.kind).toBe('ok');
    expect(out.body.policy.escalations).toHaveLength(1);
    expect(dueBackfill.scheduleSlaDueBackfill).not.toHaveBeenCalled();
    // A changed band does schedule it.
    const changed = { ...targets, low: { resolveMinutes: 1440, assignMinutes: 240 } };
    await putPolicy[1](context(client), { body: { targets: changed, escalations } }, response());
    expect(dueBackfill.scheduleSlaDueBackfill).toHaveBeenCalledTimes(1);
    expect(dueBackfill.scheduleSlaDueBackfill.mock.calls[0][2].targets).toEqual(changed);
  });

  test('a rejected PUT schedules no backfill', async () => {
    const { putPolicy } = routes();
    requirePluginAdmin.mockImplementation(forbidden);
    await putPolicy[1](context(clientWith(null)), { body: { targets, escalations: [] } }, response());
    expect(dueBackfill.scheduleSlaDueBackfill).not.toHaveBeenCalled();
  });

  test('GET /sla/backfill answers the last run (null before the first) to any signed-in user', async () => {
    const { getBackfill } = routes();
    expect(getBackfill[0].validate).toBe(false);
    requirePluginAdmin.mockImplementation(forbidden);
    dueBackfill.readSlaDueBackfillStatus.mockResolvedValueOnce(null);
    const none = await getBackfill[1](context(clientWith(null)), {}, response());
    expect(none).toMatchObject({ kind: 'ok', body: { status: null } });
    const status = { status: 'completed', started_at: 'a', finished_at: 'b', updated: 3, failures: 0, policy_version: 'v' };
    dueBackfill.readSlaDueBackfillStatus.mockResolvedValueOnce(status);
    const last = await getBackfill[1](context(clientWith(null)), {}, response());
    expect(last.body.status).toEqual(status);
    expect(requirePluginAdmin).not.toHaveBeenCalled();
  });

  test('POST /sla/backfill is administrator-only, starts the backfill under the stored policy and answers 202 without waiting', async () => {
    const { postBackfill } = routes();
    requirePluginAdmin.mockImplementation(forbidden);
    const denied = await postBackfill[1](context(clientWith(null)), {}, response());
    expect(denied.kind).toBe('forbidden');
    expect(dueBackfill.beginSlaDueBackfill).not.toHaveBeenCalled();

    requirePluginAdmin.mockResolvedValue({ name: 'admin', isPluginAdmin: true });
    const stored = { targets, escalations: [], updated_at: '2026-11-21T09:00:00.000Z', updated_by: 'admin' };
    const client = clientWith(stored);
    const running = { status: 'running', started_at: 'a', finished_at: null, updated: 0, failures: 0, version_conflicts: 0, policy_version: stored.updated_at, error: null };
    let finish: (value: any) => void = () => undefined;
    const completion = new Promise((resolve) => {
      finish = resolve;
    });
    dueBackfill.beginSlaDueBackfill.mockResolvedValueOnce({ status: running, completion });
    const out = await postBackfill[1](context(client), {}, response());
    expect(out).toMatchObject({ kind: 'accepted', body: { status: running } });
    finish({ ...running, status: 'completed' });
    const [runClient, , runPolicy, runOptions] = dueBackfill.beginSlaDueBackfill.mock.calls[0];
    expect(runClient).toBe(client);
    expect(runPolicy.targets).toEqual(targets);
    expect(runOptions.policyVersion).toBe(stored.updated_at);

    // A run that could not take the lease is answered 200 `skipped` (nothing started).
    const skipped = { ...running, status: 'skipped', finished_at: 'a', error: 'due-date backfill already running elsewhere' };
    dueBackfill.beginSlaDueBackfill.mockResolvedValueOnce({ status: skipped, completion: Promise.resolve(skipped) });
    const again = await postBackfill[1](context(client), {}, response());
    expect(again).toMatchObject({ kind: 'ok', body: { status: skipped } });
  });

  test('PUT answers 400 on a semantic error and writes nothing', async () => {
    const { putPolicy } = routes();
    const client = clientWith(null);
    const out = await putPolicy[1](
      context(client),
      { body: { targets, escalations: [{ id: 'e1', name: 'Raise', target: 'alert', thresholdPercent: 50, condition: 'any', actions: { raiseSeverity: true }, enabled: true }] } },
      response()
    );
    expect(out.kind).toBe('badRequest');
    expect(out.body.message).toMatch(/cases only/);
    expect(client.index).not.toHaveBeenCalled();
  });

  test('an invalid stored document answers the defaults flagged storedInvalid and PUT can repair it', async () => {
    const { getPolicy, putPolicy } = routes();
    const client = clientWith({ targets: { critical: { resolveMinutes: 'soon', assignMinutes: 5 } }, escalations: [] });
    const read = await getPolicy[1](context(client), {}, response());
    expect(read.kind).toBe('ok');
    expect(read.body.storedInvalid).toBe(true);
    expect(read.body.policy.targets).toEqual(DEFAULT_SLA_POLICY.targets);

    const out = await putPolicy[1](context(client), { body: { targets, escalations: [] } }, response());
    expect(out.kind).toBe('ok');
    expect(out.body.storedInvalid).toBeUndefined();
    expect(out.body.policy.targets.critical.resolveMinutes).toBe(30);
    const audit = client.writes.find((w: any) => w.index === ACTIVITY_WRITE_ALIAS);
    expect(audit.body.from).toBe('unreadable');
    const after = await getPolicy[1](context(client), {}, response());
    expect(after.body.storedInvalid).toBeUndefined();
    expect(after.body.policy.targets.critical.resolveMinutes).toBe(30);
  });

  test('policyAuditSummary', () => {
    expect(policyAuditSummary({ ...DEFAULT_SLA_POLICY, escalations: [{} as any, {} as any] })).toBe(
      'critical=60/15,high=240/60,medium=1440/360,low=4320/1080;escalations=2'
    );
  });
});

describe('GET /sla/escalation/status (step 3.3)', () => {
  beforeEach(() => jest.clearAllMocks());

  test("answers the stored status plus this replica's runtime for any signed-in user, without the lease holder", async () => {
    const status = {
      last_tick_at: '2026-11-21T12:00:00.000Z',
      holder: 'host-1',
      breached_alerts: 2,
      breached_cases: 1,
      escalated: 3,
      errors: [{ at: '2026-11-21T12:00:00.000Z', message: 'alert a1: failure (HTTP 500)' }],
      capped: false,
    };
    escalationModule.readSlaEscalationStatus.mockResolvedValue(status);
    escalationModule.getSlaEscalationRuntime.mockReturnValue({ enabled: true, tickSeconds: 30 });
    isPluginAdmin.mockReturnValue(false);
    const client = clientWith(null);
    const [, handler] = routes().getEscalationStatus;
    const res = response();
    const result: any = await handler(context(client), {}, res);
    expect(result.kind).toBe('ok');
    const { holder, ...publicStatus } = status;
    expect(result.body).toEqual({ enabled: true, tickSeconds: 30, status: publicStatus });
    expect(result.body.status.holder).toBeUndefined();
    expect(escalationModule.readSlaEscalationStatus).toHaveBeenCalledWith(client);
    expect(requirePluginAdmin).not.toHaveBeenCalled();
  });

  test('a plugin administrator also gets the lease holder', async () => {
    const status = { last_tick_at: '2026-11-21T12:00:00.000Z', holder: 'host-1', breached_alerts: 0, breached_cases: 0, escalated: 0, errors: [], capped: false };
    escalationModule.readSlaEscalationStatus.mockResolvedValue(status);
    escalationModule.getSlaEscalationRuntime.mockReturnValue({ enabled: true, tickSeconds: 60 });
    isPluginAdmin.mockReturnValue(true);
    const [, handler] = routes().getEscalationStatus;
    const result: any = await handler(context(clientWith(null)), {}, response());
    expect(result.body.status).toEqual(status);
  });

  test('a scanner never started on this replica answers enabled null', async () => {
    escalationModule.readSlaEscalationStatus.mockResolvedValue(null);
    escalationModule.getSlaEscalationRuntime.mockReturnValue({ enabled: null, tickSeconds: 60 });
    const [, handler] = routes().getEscalationStatus;
    const result: any = await handler(context(clientWith(null)), {}, response());
    expect(result.body).toEqual({ enabled: null, tickSeconds: 60, status: null });
  });

  test('a disabled scanner with no tick yet answers status null', async () => {
    escalationModule.readSlaEscalationStatus.mockResolvedValue(null);
    escalationModule.getSlaEscalationRuntime.mockReturnValue({ enabled: false, tickSeconds: 60 });
    const [, handler] = routes().getEscalationStatus;
    const result: any = await handler(context(clientWith(null)), {}, response());
    expect(result.body).toEqual({ enabled: false, tickSeconds: 60, status: null });
  });

  test('a storage failure is a 500', async () => {
    escalationModule.readSlaEscalationStatus.mockRejectedValue(Object.assign(new Error('meta unavailable'), { meta: { statusCode: 503 } }));
    const [, handler] = routes().getEscalationStatus;
    const result: any = await handler(context(clientWith(null)), {}, response());
    expect(result.kind).toBe('customError');
    expect(result.statusCode).toBe(503);
  });
});
