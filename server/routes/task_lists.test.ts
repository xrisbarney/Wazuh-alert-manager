import { ACTIVITY_WRITE_ALIAS, API_ROOT, TASK_LISTS_INDEX, TASK_LISTS_MAX, TASK_LIST_TASKS_MAX } from '../../common';
import { defineTaskListRoutes, taskListBodySchema } from './task_lists';
import { toStoredTaskList, validateTaskListInput } from '../lib/task_lists';

jest.mock('../lib/authorization', () => ({ requirePluginAdmin: jest.fn(), isPluginAdmin: jest.fn(() => false) }));
jest.mock('../lib/opensearch', () => ({ getCurrentUsername: jest.fn(async () => 'analyst') }));
jest.mock('../lib/case_index_resolution', () => ({ resolveCase: jest.fn() }));

const requirePluginAdmin: jest.Mock = require('../lib/authorization').requirePluginAdmin;
const resolveCase: jest.Mock = require('../lib/case_index_resolution').resolveCase;

const ADMIN = { name: 'admin', roles: [], securityRoles: ['all_access'], backendRoles: [], source: 'security_plugin' };
const NOW = '2026-11-21T10:00:00.000Z';
const CASE_INDEX = 'wazuh-alert-manager-v2-cases-000001';

function forbidden() {
  const error: any = new Error('Administrator permission is required for this operation.');
  error.statusCode = 403;
  throw error;
}

function response() {
  return {
    ok: jest.fn((r: any) => ({ kind: 'ok', ...r })),
    badRequest: jest.fn((r: any) => ({ kind: 'badRequest', ...r })),
    forbidden: jest.fn((r: any) => ({ kind: 'forbidden', ...r })),
    notFound: jest.fn((r: any) => ({ kind: 'notFound', ...r })),
    customError: jest.fn((r: any) => ({ kind: 'customError', ...r })),
  };
}

function routes() {
  const router: any = { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() };
  defineTaskListRoutes(router);
  const find = (method: 'get' | 'post' | 'put' | 'delete', path: string) => {
    const registration = router[method].mock.calls.find(([config]: any[]) => config.path === `${API_ROOT}${path}`);
    expect(registration).toBeDefined();
    return registration as [any, any];
  };
  return {
    list: find('get', '/task-lists'),
    read: find('get', '/task-lists/{id}'),
    create: find('post', '/task-lists'),
    update: find('put', '/task-lists/{id}'),
    remove: find('delete', '/task-lists/{id}'),
    apply: find('post', '/cases/{id}/task-lists/{taskListId}/apply'),
  };
}

/** TaskList index + activity writes + one case document (for the apply route). */
function clientWith(taskLists: Record<string, any> = {}, caseSource: Record<string, any> | null = { status: 'open' }) {
  const docs = new Map<string, any>(Object.entries(taskLists));
  const activity: any[] = [];
  const caseState = { source: caseSource, seqNo: 1, primaryTerm: 1 };
  resolveCase.mockImplementation(async (_client: any, id: string) => {
    if (!caseState.source) throw Object.assign(new Error(`Case ${id} was not found.`), { statusCode: 404 });
    return { id, index: CASE_INDEX, source: JSON.parse(JSON.stringify(caseState.source)), seqNo: caseState.seqNo, primaryTerm: caseState.primaryTerm };
  });
  const client: any = {
    search: jest.fn(async ({ body }: any) => {
      const hits = Array.from(docs.entries())
        .filter(([, source]) => !body.query.term || source.enabled === body.query.term.enabled)
        .map(([_id, _source]) => ({ _id, _source }));
      return { body: { hits: { total: { value: hits.length }, hits } } };
    }),
    get: jest.fn(async ({ index, id }: any) => {
      if (index === TASK_LISTS_INDEX) {
        if (!docs.has(id)) throw Object.assign(new Error('not found'), { meta: { statusCode: 404 } });
        return { body: { found: true, _source: docs.get(id) } };
      }
      return { body: { _source: caseState.source, _seq_no: caseState.seqNo, _primary_term: caseState.primaryTerm } };
    }),
    create: jest.fn(async ({ id, body }: any) => {
      docs.set(id, body);
      return { body: { result: 'created' } };
    }),
    index: jest.fn(async (req: any) => {
      if (req.index === ACTIVITY_WRITE_ALIAS) activity.push(req.body);
      else docs.set(req.id, req.body);
      return { body: { result: 'created' } };
    }),
    delete: jest.fn(async ({ id }: any) => {
      docs.delete(id);
      return { body: { result: 'deleted' } };
    }),
    update: jest.fn(async ({ body }: any) => {
      caseState.source = { ...caseState.source, ...body.script.params.fields };
      caseState.seqNo += 1;
      return { body: { result: 'updated' } };
    }),
    docs,
    activity,
    caseState,
  };
  return client;
}

const context = (client: any) => ({ core: { opensearch: { client: { asCurrentUser: client } } } }) as any;
const stored = (id: string, input: any) => toStoredTaskList(id, validateTaskListInput(input), 'admin', NOW);
const SAMPLE = { name: 'Phishing triage', tasks: [{ title: 'Pull headers', owner: 'bob', dueOffsetMinutes: 60 }, { title: 'Block sender' }] };

beforeEach(() => {
  requirePluginAdmin.mockReset();
  requirePluginAdmin.mockResolvedValue(ADMIN);
  resolveCase.mockReset();
});

describe('schema', () => {
  test('body needs a name and 1..TASK_LIST_TASKS_MAX tasks, defaults enabled and forbids unknown keys', () => {
    expect(taskListBodySchema.validate(SAMPLE)).toEqual({ ...SAMPLE, enabled: true });
    expect(() => taskListBodySchema.validate({ name: 'x', tasks: [] })).toThrow();
    expect(() => taskListBodySchema.validate({ name: '', tasks: [{ title: 't' }] })).toThrow();
    expect(() => taskListBodySchema.validate({ name: 'x', tasks: [{ title: 't', dueOffsetMinutes: 0 }] })).toThrow();
    expect(() => taskListBodySchema.validate({ name: 'x', tasks: [{ title: 't', extra: 1 }] })).toThrow();
    expect(() => taskListBodySchema.validate({ name: 'x', tasks: [{ title: 't' }], id: 'pb-1' })).toThrow();
    expect(() => taskListBodySchema.validate({ name: 'x', tasks: Array.from({ length: TASK_LIST_TASKS_MAX + 1 }, () => ({ title: 't' })) })).toThrow();
  });

  test('every route validates its request shape', () => {
    const all = routes();
    for (const [config] of Object.values(all)) expect(config.validate).toBeTruthy();
    expect(all.create[0].validate.body).toBe(taskListBodySchema);
    expect(all.update[0].validate.body).toBe(taskListBodySchema);
    expect(all.apply[0].validate.params).toBeDefined();
  });
});

describe('reads', () => {
  test('GET /task-lists answers every user with the list and limit; enabled=true filters', async () => {
    const client = clientWith({ 'pb-a': stored('pb-a', SAMPLE), 'pb-b': stored('pb-b', { ...SAMPLE, name: 'Off', enabled: false }) });
    const { list, read } = routes();
    const out = await list[1](context(client), { query: {} }, response());
    expect(out.kind).toBe('ok');
    expect(out.body.limit).toBe(TASK_LISTS_MAX);
    expect(out.body.taskLists.map((p: any) => p.id)).toEqual(['pb-b', 'pb-a']);
    expect(out.body.taskLists[1].tasks[0]).toEqual({ title: 'Pull headers', owner: 'bob', dueOffsetMinutes: 60, order: 0 });
    const enabled = await list[1](context(client), { query: { enabled: true } }, response());
    expect(enabled.body.taskLists.map((p: any) => p.id)).toEqual(['pb-a']);
    expect(requirePluginAdmin).not.toHaveBeenCalled();

    const one = await read[1](context(client), { params: { id: 'pb-a' } }, response());
    expect(one.kind).toBe('ok');
    expect(one.body.taskList.name).toBe('Phishing triage');
    const missing = await read[1](context(client), { params: { id: 'pb-x' } }, response());
    expect(missing.kind).toBe('notFound');
  });
});

describe('admin writes', () => {
  test('POST/PUT/DELETE are refused for non-administrators before any read or write', async () => {
    requirePluginAdmin.mockImplementation(forbidden);
    const client = clientWith({ 'pb-a': stored('pb-a', SAMPLE) });
    const { create, update, remove } = routes();
    expect((await create[1](context(client), { body: SAMPLE }, response())).kind).toBe('forbidden');
    expect((await update[1](context(client), { params: { id: 'pb-a' }, body: SAMPLE }, response())).kind).toBe('forbidden');
    expect((await remove[1](context(client), { params: { id: 'pb-a' } }, response())).kind).toBe('forbidden');
    expect(client.create).not.toHaveBeenCalled();
    expect(client.index).not.toHaveBeenCalled();
    expect(client.delete).not.toHaveBeenCalled();
    expect(client.search).not.toHaveBeenCalled();
  });

  test('POST creates with the admin as actor and audits task_list_created on system/task_list:<id>', async () => {
    const client = clientWith();
    const { create } = routes();
    const out = await create[1](context(client), { body: SAMPLE }, response());
    expect(out.kind).toBe('ok');
    expect(out.body.taskList).toMatchObject({ name: 'Phishing triage', enabled: true, created_by: 'admin', updated_by: 'admin' });
    expect(out.body.taskList.id).toMatch(/^pb-[0-9a-f]{16}$/);
    expect(client.create).toHaveBeenCalledWith(expect.objectContaining({ index: TASK_LISTS_INDEX, id: out.body.taskList.id }));
    expect(client.activity).toHaveLength(1);
    expect(client.activity[0]).toMatchObject({ target_type: 'system', target_id: `task_list:${out.body.taskList.id}`, action: 'task_list_created', user: 'admin', to: 'Phishing triage' });
    const dup = await create[1](context(client), { body: { ...SAMPLE, name: 'PHISHING TRIAGE' } }, response());
    expect(dup.kind).toBe('customError');
    expect(dup.statusCode).toBe(409);
  });

  test('PUT replaces and audits task_list_updated with from/to names; unknown id is 404', async () => {
    const client = clientWith({ 'pb-a': stored('pb-a', SAMPLE) });
    const { update } = routes();
    const out = await update[1](context(client), { params: { id: 'pb-a' }, body: { name: 'Mail triage', tasks: [{ title: 'Only one' }], enabled: false } }, response());
    expect(out.kind).toBe('ok');
    expect(out.body.taskList).toMatchObject({ id: 'pb-a', name: 'Mail triage', enabled: false, created_by: 'admin' });
    expect(out.body.taskList.tasks).toHaveLength(1);
    expect(client.activity[0]).toMatchObject({ action: 'task_list_updated', target_id: 'task_list:pb-a', from: 'Phishing triage', to: 'Mail triage' });
    expect((await update[1](context(client), { params: { id: 'pb-zz' }, body: SAMPLE }, response())).kind).toBe('notFound');
  });

  test('DELETE removes and audits task_list_deleted; unknown id is 404', async () => {
    const client = clientWith({ 'pb-a': stored('pb-a', SAMPLE) });
    const { remove } = routes();
    const out = await remove[1](context(client), { params: { id: 'pb-a' } }, response());
    expect(out).toMatchObject({ kind: 'ok', body: { deleted: true } });
    expect(client.delete).toHaveBeenCalledWith(expect.objectContaining({ index: TASK_LISTS_INDEX, id: 'pb-a' }));
    expect(client.activity[0]).toMatchObject({ action: 'task_list_deleted', target_id: 'task_list:pb-a', from: 'Phishing triage' });
    expect((await remove[1](context(client), { params: { id: 'pb-a' } }, response())).kind).toBe('notFound');
  });
});

describe('POST /cases/{id}/task-lists/{taskListId}/apply', () => {
  test('any signed-in user applies an enabled task list: tasks appended, marker written, task_list_applied event', async () => {
    const client = clientWith({ 'pb-a': stored('pb-a', SAMPLE) }, { status: 'open', tasks: [] });
    const { apply } = routes();
    const out = await apply[1](context(client), { params: { id: 'case-1', taskListId: 'pb-a' } }, response());
    expect(out.kind).toBe('ok');
    expect(out.body).toEqual({ applied: true, task_list_id: 'pb-a', tasks_added: 2, counts: { open: 2, done: 0 } });
    expect(requirePluginAdmin).not.toHaveBeenCalled();
    expect(client.caseState.source.tasks).toHaveLength(2);
    expect(client.caseState.source.tasks[0]).toMatchObject({ title: 'Pull headers', owner: 'bob', created_by: 'analyst' });
    expect(client.caseState.source.applied_task_lists).toEqual([expect.objectContaining({ task_list_id: 'pb-a', applied_by: 'analyst' })]);
    expect(client.activity).toEqual([expect.objectContaining({ action: 'task_list_applied', case_id: 'case-1', details: { task_list_id: 'pb-a', name: 'Phishing triage', tasks_added: 2 } })]);

    const again = await apply[1](context(client), { params: { id: 'case-1', taskListId: 'pb-a' } }, response());
    expect(again.kind).toBe('ok');
    expect(again.body).toEqual({ applied: false, reason: 'already_applied', task_list_id: 'pb-a', tasks_added: 0, counts: { open: 2, done: 0 } });
    expect(client.update).toHaveBeenCalledTimes(1);
    expect(client.activity).toHaveLength(1);
  });

  test('404 for an unknown task list or case, 409 for a disabled task list or a closed case, nothing written', async () => {
    const { apply } = routes();
    const unknownTaskList = clientWith({}, { status: 'open' });
    expect((await apply[1](context(unknownTaskList), { params: { id: 'case-1', taskListId: 'pb-x' } }, response())).kind).toBe('notFound');
    const unknownCase = clientWith({ 'pb-a': stored('pb-a', SAMPLE) }, null);
    expect((await apply[1](context(unknownCase), { params: { id: 'case-x', taskListId: 'pb-a' } }, response())).kind).toBe('notFound');
    const disabled = clientWith({ 'pb-a': stored('pb-a', { ...SAMPLE, enabled: false }) }, { status: 'open' });
    const off = await apply[1](context(disabled), { params: { id: 'case-1', taskListId: 'pb-a' } }, response());
    expect(off).toMatchObject({ kind: 'customError', statusCode: 409 });
    const closed = clientWith({ 'pb-a': stored('pb-a', SAMPLE) }, { status: 'closed' });
    const shut = await apply[1](context(closed), { params: { id: 'case-1', taskListId: 'pb-a' } }, response());
    expect(shut).toMatchObject({ kind: 'customError', statusCode: 409 });
    for (const client of [unknownTaskList, unknownCase, disabled, closed]) {
      expect(client.update).not.toHaveBeenCalled();
      expect(client.activity).toEqual([]);
    }
  });

  test('409 with the overflow count when the case cannot take the tasks', async () => {
    const tasks = Array.from({ length: 99 }, (_, i) => ({ id: `t${i}`.padEnd(12, '0'), title: `T${i}`, done: false, created_by: 'x', created_at: NOW, order: i }));
    const client = clientWith({ 'pb-a': stored('pb-a', SAMPLE) }, { status: 'open', tasks });
    const { apply } = routes();
    const out = await apply[1](context(client), { params: { id: 'case-1', taskListId: 'pb-a' } }, response());
    expect(out).toMatchObject({ kind: 'customError', statusCode: 409 });
    expect(out.body.message).toContain('101 tasks');
    expect(client.update).not.toHaveBeenCalled();
  });
});
