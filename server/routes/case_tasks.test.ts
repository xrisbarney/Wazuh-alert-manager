import { ACTIVITY_WRITE_ALIAS, API_ROOT, CASE_TASKS_MAX, CaseTask } from '../../common';
import {
  canRemoveTask,
  createTaskBodySchema,
  defineCaseTaskRoutes,
  listCaseTasks,
  mutateCaseTasks,
  updateTaskBodySchema,
} from './case_tasks';
import { addTask } from '../lib/case_tasks';

jest.mock('../lib/identity', () => ({ trustedIdentity: jest.fn() }));
// Attribution for POST/PUT follows the other case writers: the resolved name, trusted or not.
jest.mock('../lib/opensearch', () => ({
  getCurrentUsername: jest.fn(async (context: any, request: any) => (await require('../lib/identity').trustedIdentity(context, request)).name),
}));
jest.mock('../lib/case_index_resolution', () => ({ resolveCase: jest.fn() }));

const trustedIdentity: jest.Mock = require('../lib/identity').trustedIdentity;
const resolveCase: jest.Mock = require('../lib/case_index_resolution').resolveCase;

const ANALYST = { name: 'analyst', roles: [], securityRoles: ['readall'], backendRoles: [], source: 'security_plugin' };
const ADMIN = { name: 'admin', roles: [], securityRoles: ['all_access'], backendRoles: [], source: 'security_plugin' };
const ANONYMOUS = { name: 'dashboard_user', roles: [], securityRoles: [], backendRoles: [], source: 'anonymous' };
const CASE_INDEX = 'wazuh-alert-manager-v2-cases-000001';
const NOW = '2026-11-21T10:00:00.000Z';

function task(id: string, order: number, extra: Partial<CaseTask> = {}): CaseTask {
  return { id, title: `Task ${id}`, owner: null, due_at: null, done: false, done_by: null, done_at: null, created_by: 'analyst', created_at: NOW, order, ...extra };
}

function routes() {
  const router: any = { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() };
  defineCaseTaskRoutes(router);
  const find = (method: 'get' | 'post' | 'put' | 'delete', path: string) => {
    const registration = router[method].mock.calls.find(([config]: any[]) => config.path === `${API_ROOT}${path}`);
    expect(registration).toBeDefined();
    return registration!;
  };
  return {
    list: find('get', '/cases/{id}/tasks'),
    create: find('post', '/cases/{id}/tasks'),
    update: find('put', '/cases/{id}/tasks/{taskId}'),
    remove: find('delete', '/cases/{id}/tasks/{taskId}'),
  };
}

function response() {
  return {
    ok: jest.fn((v: any) => ({ kind: 'ok', ...v })),
    custom: jest.fn((v: any) => ({ kind: 'custom', ...v })),
    notFound: jest.fn((v: any) => ({ kind: 'notFound', ...v })),
    forbidden: jest.fn((v: any) => ({ kind: 'forbidden', ...v })),
    badRequest: jest.fn((v: any) => ({ kind: 'badRequest', ...v })),
    customError: jest.fn((v: any) => ({ kind: 'customError', ...v })),
  };
}

function contextWith(client: any) {
  return { core: { opensearch: { client: { asCurrentUser: client } } } } as any;
}

function conflict() {
  const error: any = new Error('version conflict');
  error.meta = { statusCode: 409 };
  return error;
}

/** A case store whose document the mocked resolveCase reads back after every update. */
function caseStore(source: Record<string, any>) {
  const state: { source: Record<string, any>; seqNo: number; primaryTerm: number } = { source: { status: 'open', assigned_to: null, ...source }, seqNo: 7, primaryTerm: 1 };
  resolveCase.mockImplementation(async (_client: any, id: string) => ({
    id,
    index: CASE_INDEX,
    source: JSON.parse(JSON.stringify(state.source)),
    seqNo: state.seqNo,
    primaryTerm: state.primaryTerm,
  }));
  const client: any = {
    update: jest.fn(async ({ body }: any) => {
      const fields = body.script.params.fields;
      state.source = { ...state.source, ...fields, history: [...(state.source.history || []), body.script.params.entry] };
      state.seqNo += 1;
      return { body: { result: 'updated' } };
    }),
    // Realtime GET used by the 409 retry path.
    get: jest.fn(async () => ({
      body: { _source: JSON.parse(JSON.stringify(state.source)), _seq_no: state.seqNo, _primary_term: state.primaryTerm },
    })),
    index: jest.fn(async () => ({ body: { result: 'created' } })),
  };
  return { client, state };
}

beforeEach(() => {
  resolveCase.mockReset();
  trustedIdentity.mockReset();
  trustedIdentity.mockResolvedValue(ANALYST);
});

describe('schemas and helpers', () => {
  test('create needs a title and forbids unknown keys; update is all-optional with bounded order', () => {
    expect(createTaskBodySchema.validate({ title: 'Collect logs' })).toEqual({ title: 'Collect logs' });
    expect(createTaskBodySchema.validate({ title: 'x', owner: null, dueAt: null })).toEqual({ title: 'x', owner: null, dueAt: null });
    expect(() => createTaskBodySchema.validate({})).toThrow();
    expect(() => createTaskBodySchema.validate({ title: '' })).toThrow();
    expect(() => createTaskBodySchema.validate({ title: 'x', done: true })).toThrow();
    expect(updateTaskBodySchema.validate({})).toEqual({});
    expect(updateTaskBodySchema.validate({ done: true, order: 3 })).toEqual({ done: true, order: 3 });
    expect(() => updateTaskBodySchema.validate({ order: CASE_TASKS_MAX + 1 })).toThrow();
    expect(() => updateTaskBodySchema.validate({ order: -1 })).toThrow();
  });

  test('every route validates its params', () => {
    const { list, create, update, remove } = routes();
    for (const [config] of [list, create, update, remove]) {
      expect(config.validate.params).toBeDefined();
    }
    expect(create[0].validate.body).toBe(createTaskBodySchema);
    expect(update[0].validate.body).toBe(updateTaskBodySchema);
  });

  test('listCaseTasks sorts by order and derives counts from the list, not the stored pair', () => {
    const result = listCaseTasks({ tasks: [task('b', 3, { done: true }), task('a', 1)], task_counts: { open: 9, done: 9 } });
    expect(result.tasks.map((t) => t.id)).toEqual(['a', 'b']);
    expect(result.counts).toEqual({ open: 1, done: 1 });
    expect(result.limit).toBe(CASE_TASKS_MAX);
    expect(listCaseTasks({})).toEqual({ tasks: [], counts: { open: 0, done: 0 }, limit: CASE_TASKS_MAX });
  });

  test('canRemoveTask: author, case assignee or admin; never anonymous', () => {
    const t = task('a', 0, { created_by: 'alice' });
    expect(canRemoveTask({ ...ANALYST, name: 'alice' } as any, t, { assigned_to: null })).toBe(true);
    expect(canRemoveTask({ ...ANALYST, name: 'bob' } as any, t, { assigned_to: 'bob' })).toBe(true);
    expect(canRemoveTask(ADMIN as any, t, { assigned_to: null })).toBe(true);
    expect(canRemoveTask({ ...ANALYST, name: 'carol' } as any, t, { assigned_to: 'bob' })).toBe(false);
    expect(canRemoveTask({ ...ANONYMOUS, name: 'alice' } as any, t, { assigned_to: 'alice' })).toBe(false);
  });
});

describe('mutateCaseTasks (optimistic concurrency)', () => {
  test('writes tasks, counts, updated_* and a history entry fenced on seq_no / primary_term', async () => {
    const { client } = caseStore({ tasks: [] });
    const outcome = await mutateCaseTasks(
      client,
      'case-1',
      'analyst',
      (tasks) => addTask(tasks, { title: 'Collect logs' }, 'analyst', NOW, 'tid000000001'),
      (r) => ({ action: 'task_added', to: r.task.title }),
      NOW
    );
    expect(outcome.result.task.id).toBe('tid000000001');
    expect(client.update).toHaveBeenCalledTimes(1);
    const call = client.update.mock.calls[0][0];
    expect(call).toMatchObject({ index: CASE_INDEX, id: 'case-1', refresh: 'wait_for', if_seq_no: 7, if_primary_term: 1 });
    expect(call.body.script.params.fields).toEqual({
      tasks: [expect.objectContaining({ id: 'tid000000001', order: 0 })],
      task_counts: { open: 1, done: 0 },
      updated_at: NOW,
      updated_by: 'analyst',
    });
    expect(call.body.script.params.entry).toMatchObject({ user: 'analyst', action: 'task_added', to: 'Collect logs', from: null });
    expect(call.body.script.source).toContain('ctx._source.history.add(params.entry)');
  });

  test('retries once on 409 with a realtime GET of the same document, then surfaces 409', async () => {
    const { client, state } = caseStore({ tasks: [task('a', 0)] });
    const original = client.update.getMockImplementation();
    client.update
      .mockImplementationOnce(async () => {
        // Someone else added a task between our read and our write, with
        // refresh:false: the alias search would still answer the stale token.
        state.source.tasks = [task('a', 0), task('b', 1)];
        state.seqNo = 8;
        resolveCase.mockResolvedValue({ id: 'case-1', index: CASE_INDEX, source: { status: 'open', tasks: [task('a', 0)] }, seqNo: 7, primaryTerm: 1 });
        throw conflict();
      })
      .mockImplementationOnce(original);

    const outcome = await mutateCaseTasks(
      client,
      'case-1',
      'analyst',
      (tasks) => addTask(tasks, { title: 'third' }, 'analyst', NOW, 'tid000000003'),
      () => ({ action: 'task_added' }),
      NOW
    );
    expect(resolveCase).toHaveBeenCalledTimes(1);
    expect(client.get).toHaveBeenCalledTimes(1);
    expect(client.get).toHaveBeenCalledWith({ index: CASE_INDEX, id: 'case-1' });
    expect(client.update).toHaveBeenCalledTimes(2);
    expect(client.update.mock.calls[0][0].if_seq_no).toBe(7);
    // The retry carries the GET's token, not the (stale) search one.
    expect(client.update.mock.calls[1][0]).toMatchObject({ index: CASE_INDEX, if_seq_no: 8, if_primary_term: 1 });
    // The retry saw the concurrent task and appended after it.
    expect(outcome.result.tasks.map((t) => t.id)).toEqual(['a', 'b', 'tid000000003']);
    expect(outcome.result.task.order).toBe(2);

    client.update.mockImplementation(async () => { throw conflict(); });
    client.get.mockClear();
    await expect(
      mutateCaseTasks(client, 'case-1', 'analyst', (tasks) => addTask(tasks, { title: 'x' }, 'analyst', NOW), () => ({ action: 'task_added' }), NOW)
    ).rejects.toMatchObject({ statusCode: 409, message: expect.stringContaining('changed by someone else') });
    // One GET for the single retry; no third attempt.
    expect(client.get).toHaveBeenCalledTimes(1);
  });

  test('a closed case seen only by the realtime re-read refuses the retry with 409', async () => {
    const { client, state } = caseStore({ tasks: [task('a', 0)] });
    client.update.mockImplementationOnce(async () => {
      state.source.status = 'closed';
      state.seqNo = 8;
      throw conflict();
    });
    await expect(
      mutateCaseTasks(client, 'case-1', 'analyst', (tasks) => addTask(tasks, { title: 'x' }, 'analyst', NOW), () => ({ action: 'task_added' }), NOW)
    ).rejects.toMatchObject({ statusCode: 409, message: 'Case is closed' });
    expect(client.update).toHaveBeenCalledTimes(1);
  });

  test('a no-op mutation writes nothing: no history row, no updated_* bump', async () => {
    const { client } = caseStore({ tasks: [task('a', 0)] });
    const outcome = await mutateCaseTasks(
      client,
      'case-1',
      'analyst',
      (tasks) => ({ tasks, task: tasks[0], counts: { open: 1, done: 0 }, transition: 'unchanged' }),
      () => ({ action: 'task_updated' }),
      NOW
    );
    expect(outcome.result.task.id).toBe('a');
    expect(client.update).not.toHaveBeenCalled();
  });

  test('a closed case refuses every task write with 409', async () => {
    const { client } = caseStore({ status: 'closed', tasks: [task('a', 0)] });
    await expect(
      mutateCaseTasks(client, 'case-1', 'analyst', (tasks) => addTask(tasks, { title: 'x' }, 'analyst', NOW), () => ({ action: 'task_added' }), NOW)
    ).rejects.toMatchObject({ statusCode: 409, message: 'Case is closed' });
    expect(client.update).not.toHaveBeenCalled();
  });

  test('a non-conflict failure is not retried', async () => {
    const { client } = caseStore({ tasks: [] });
    client.update.mockRejectedValue(Object.assign(new Error('boom'), { meta: { statusCode: 500 } }));
    await expect(
      mutateCaseTasks(client, 'case-1', 'analyst', (tasks) => addTask(tasks, { title: 'x' }, 'analyst', NOW), () => ({ action: 'task_added' }), NOW)
    ).rejects.toThrow('boom');
    expect(client.update).toHaveBeenCalledTimes(1);
  });
});

describe('task routes', () => {
  test('list returns the sorted checklist with counts and 404 for an unknown case', async () => {
    const { list } = routes();
    const { client } = caseStore({ tasks: [task('b', 1, { done: true }), task('a', 0)] });
    const res = response();
    const result: any = await list[1](contextWith(client), { params: { id: 'case-1' } }, res);
    expect(result.kind).toBe('ok');
    expect(result.body.tasks.map((t: CaseTask) => t.id)).toEqual(['a', 'b']);
    expect(result.body.counts).toEqual({ open: 1, done: 1 });

    resolveCase.mockRejectedValue(Object.assign(new Error('Case missing was not found.'), { statusCode: 404 }));
    const missing: any = await list[1](contextWith(client), { params: { id: 'missing' } }, response());
    expect(missing.kind).toBe('notFound');
  });

  test('create answers 200 with the task and counts, writes the case and a task_added activity event', async () => {
    const { create } = routes();
    const { client, state } = caseStore({ tasks: [] });
    const res = response();
    const result: any = await create[1](
      contextWith(client),
      { params: { id: 'case-1' }, body: { title: 'Collect logs', owner: 'bob', dueAt: '2026-11-22T00:00:00Z' } },
      res
    );
    expect(result.kind).toBe('ok');
    expect(res.custom).not.toHaveBeenCalled();
    // One alias read per mutation: no standalone resolveCase before mutateCaseTasks.
    expect(resolveCase).toHaveBeenCalledTimes(1);
    expect(result.body.task).toMatchObject({ title: 'Collect logs', owner: 'bob', due_at: '2026-11-22T00:00:00.000Z', done: false, created_by: 'analyst', order: 0 });
    expect(result.body.task.id).toMatch(/^[0-9a-z]{12}$/);
    expect(result.body.counts).toEqual({ open: 1, done: 0 });
    expect(state.source.tasks).toHaveLength(1);
    expect(state.source.task_counts).toEqual({ open: 1, done: 0 });
    expect(state.source.history[0]).toMatchObject({ action: 'task_added', to: 'Collect logs', user: 'analyst' });

    expect(client.index).toHaveBeenCalledTimes(1);
    const activity = client.index.mock.calls[0][0];
    expect(activity.index).toBe(ACTIVITY_WRITE_ALIAS);
    expect(activity.body).toMatchObject({
      target_type: 'case',
      case_id: 'case-1',
      user: 'analyst',
      action: 'task_added',
      to: 'Collect logs',
      details: { task_id: result.body.task.id, title: 'Collect logs' },
    });
  });

  test('create is 409 at the cap and on a closed case, 400 on a bad due date; an anonymous identity is attributed like other case writes', async () => {
    const { create } = routes();
    const full = Array.from({ length: CASE_TASKS_MAX }, (_, i) => task(`t${i}`, i));
    const { client } = caseStore({ tasks: full });
    const capped: any = await create[1](contextWith(client), { params: { id: 'case-1' }, body: { title: 'one more' } }, response());
    expect(capped.kind).toBe('customError');
    expect(capped.statusCode).toBe(409);
    expect(capped.body.message).toContain(`${CASE_TASKS_MAX} tasks`);
    expect(client.update).not.toHaveBeenCalled();
    expect(client.index).not.toHaveBeenCalled();

    const closed = caseStore({ status: 'closed', tasks: [] });
    const refused: any = await create[1](contextWith(closed.client), { params: { id: 'case-1' }, body: { title: 'x' } }, response());
    expect(refused.kind).toBe('customError');
    expect(refused.statusCode).toBe(409);
    expect(refused.body.message).toBe('Case is closed');

    const open = caseStore({ tasks: [] });
    const bad: any = await create[1](contextWith(open.client), { params: { id: 'case-1' }, body: { title: 'x', dueAt: 'soon' } }, response());
    expect(bad.kind).toBe('badRequest');

    trustedIdentity.mockResolvedValue(ANONYMOUS);
    const anon: any = await create[1](contextWith(open.client), { params: { id: 'case-1' }, body: { title: 'x' } }, response());
    expect(anon.kind).toBe('ok');
    expect(anon.body.task.created_by).toBe('dashboard_user');
    expect(open.client.update).toHaveBeenCalledTimes(1);
  });

  test('done transitions stamp the trusted identity and emit task_completed / task_reopened; field edits emit task_updated', async () => {
    const { update } = routes();
    const { client, state } = caseStore({ tasks: [task('a', 0), task('b', 1)] });
    trustedIdentity.mockResolvedValue({ ...ANALYST, name: 'carol' });

    const done: any = await update[1](contextWith(client), { params: { id: 'case-1', taskId: 'a' }, body: { done: true } }, response());
    expect(done.kind).toBe('ok');
    expect(done.body.task).toMatchObject({ id: 'a', done: true, done_by: 'carol' });
    expect(typeof done.body.task.done_at).toBe('string');
    expect(done.body.counts).toEqual({ open: 1, done: 1 });
    expect(client.index.mock.calls[0][0].body).toMatchObject({ action: 'task_completed', user: 'carol', details: { task_id: 'a', title: 'Task a' } });
    expect(state.source.history[0]).toMatchObject({ action: 'task_completed', user: 'carol' });

    const reopened: any = await update[1](contextWith(client), { params: { id: 'case-1', taskId: 'a' }, body: { done: false } }, response());
    expect(reopened.body.task).toMatchObject({ id: 'a', done: false, done_by: null, done_at: null });
    expect(client.index.mock.calls[1][0].body).toMatchObject({ action: 'task_reopened', details: { task_id: 'a' } });

    const edited: any = await update[1](contextWith(client), { params: { id: 'case-1', taskId: 'b' }, body: { title: 'Renamed', owner: 'dave' } }, response());
    expect(edited.body.task).toMatchObject({ id: 'b', title: 'Renamed', owner: 'dave', done: false });
    expect(client.index.mock.calls[2][0].body).toMatchObject({ action: 'task_updated', from: 'Task b', to: 'Renamed', details: { task_id: 'b', title: 'Renamed' } });

    // A no-op patch answers ok but writes nothing: no case update, no history row, no activity event.
    const historyBefore = state.source.history.length;
    const updatedAtBefore = state.source.updated_at;
    const noop: any = await update[1](contextWith(client), { params: { id: 'case-1', taskId: 'b' }, body: { done: false } }, response());
    expect(noop.kind).toBe('ok');
    expect(noop.body.task).toMatchObject({ id: 'b', title: 'Renamed', done: false });
    expect(client.update).toHaveBeenCalledTimes(3);
    expect(state.source.history).toHaveLength(historyBefore);
    expect(state.source.updated_at).toBe(updatedAtBefore);
    const empty: any = await update[1](contextWith(client), { params: { id: 'case-1', taskId: 'b' }, body: {} }, response());
    expect(empty.kind).toBe('ok');
    expect(client.update).toHaveBeenCalledTimes(3);
    expect(client.index).toHaveBeenCalledTimes(3);

    // An anonymous identity is attributed (done_by) like every other case write.
    trustedIdentity.mockResolvedValue(ANONYMOUS);
    const anon: any = await update[1](contextWith(client), { params: { id: 'case-1', taskId: 'b' }, body: { done: true } }, response());
    expect(anon.kind).toBe('ok');
    expect(anon.body.task).toMatchObject({ id: 'b', done: true, done_by: 'dashboard_user' });
    trustedIdentity.mockResolvedValue({ ...ANALYST, name: 'carol' });

    const unknown: any = await update[1](contextWith(client), { params: { id: 'case-1', taskId: 'zzz' }, body: { done: true } }, response());
    expect(unknown.kind).toBe('notFound');
  });

  test('update on a closed case is 409 and writes nothing', async () => {
    const { update } = routes();
    const { client } = caseStore({ status: 'closed', tasks: [task('a', 0)] });
    const result: any = await update[1](contextWith(client), { params: { id: 'case-1', taskId: 'a' }, body: { done: true } }, response());
    expect(result.statusCode).toBe(409);
    expect(client.update).not.toHaveBeenCalled();
    expect(client.index).not.toHaveBeenCalled();
  });

  test('update surfaces a persistent version conflict as 409 after one retry', async () => {
    const { update } = routes();
    const { client } = caseStore({ tasks: [task('a', 0)] });
    client.update.mockImplementation(async () => { throw conflict(); });
    const result: any = await update[1](contextWith(client), { params: { id: 'case-1', taskId: 'a' }, body: { done: true } }, response());
    expect(result.kind).toBe('customError');
    expect(result.statusCode).toBe(409);
    expect(client.update).toHaveBeenCalledTimes(2);
    expect(client.get).toHaveBeenCalledTimes(1);
    expect(client.index).not.toHaveBeenCalled();
  });

  test('delete is allowed for the author, the case assignee and an admin; refused for others and anonymous', async () => {
    const { remove } = routes();
    const tasks = [task('a', 0, { created_by: 'alice' }), task('b', 1, { created_by: 'alice' }), task('c', 2, { created_by: 'alice' })];

    const other = caseStore({ tasks, assigned_to: 'bob' });
    trustedIdentity.mockResolvedValue({ ...ANALYST, name: 'carol' });
    const refused: any = await remove[1](contextWith(other.client), { params: { id: 'case-1', taskId: 'a' } }, response());
    expect(refused.kind).toBe('forbidden');
    expect(other.client.update).not.toHaveBeenCalled();

    trustedIdentity.mockResolvedValue({ ...ANONYMOUS, name: 'alice' });
    const anon: any = await remove[1](contextWith(other.client), { params: { id: 'case-1', taskId: 'a' } }, response());
    expect(anon.kind).toBe('forbidden');

    trustedIdentity.mockResolvedValue({ ...ANALYST, name: 'alice' });
    const byAuthor: any = await remove[1](contextWith(other.client), { params: { id: 'case-1', taskId: 'a' } }, response());
    expect(byAuthor.kind).toBe('ok');
    expect(byAuthor.body).toEqual({ deleted: true, counts: { open: 2, done: 0 } });
    expect(other.state.source.tasks.map((t: CaseTask) => [t.id, t.order])).toEqual([['b', 0], ['c', 1]]);
    expect(other.client.index.mock.calls[0][0].body).toMatchObject({ action: 'task_removed', from: 'Task a', details: { task_id: 'a', title: 'Task a' } });
    expect(other.state.source.history[0]).toMatchObject({ action: 'task_removed', from: 'Task a' });

    trustedIdentity.mockResolvedValue({ ...ANALYST, name: 'bob' });
    const byAssignee: any = await remove[1](contextWith(other.client), { params: { id: 'case-1', taskId: 'b' } }, response());
    expect(byAssignee.kind).toBe('ok');

    trustedIdentity.mockResolvedValue(ADMIN);
    const byAdmin: any = await remove[1](contextWith(other.client), { params: { id: 'case-1', taskId: 'c' } }, response());
    expect(byAdmin.kind).toBe('ok');
    expect(byAdmin.body.counts).toEqual({ open: 0, done: 0 });

    const missing: any = await remove[1](contextWith(other.client), { params: { id: 'case-1', taskId: 'c' } }, response());
    expect(missing.kind).toBe('notFound');
  });

  test('delete on a closed case is 409 even for an admin', async () => {
    const { remove } = routes();
    const { client } = caseStore({ status: 'closed', tasks: [task('a', 0)] });
    trustedIdentity.mockResolvedValue(ADMIN);
    const result: any = await remove[1](contextWith(client), { params: { id: 'case-1', taskId: 'a' } }, response());
    expect(result.statusCode).toBe(409);
    expect(client.update).not.toHaveBeenCalled();
  });
});
