import { ACTIVITY_WRITE_ALIAS, CASE_TASKS_MAX, CaseTask, TASK_LISTS_INDEX, TASK_LISTS_MAX, TASK_LIST_TASKS_MAX, TaskList } from '../../common';
import {
  applyTaskListTasks,
  applyTaskListToCase,
  assertUniqueTaskListName,
  createTaskList,
  deleteTaskList,
  fromStoredTaskList,
  getTaskList,
  isTaskListId,
  listTaskLists,
  newTaskListId,
  toStoredTaskList,
  updateTaskList,
  validateTaskListInput,
} from './task_lists';

jest.mock('./case_index_resolution', () => ({ resolveCase: jest.fn() }));
const resolveCase: jest.Mock = require('./case_index_resolution').resolveCase;

const NOW = '2026-11-21T10:00:00.000Z';
const CASE_INDEX = 'wazuh-alert-manager-v2-cases-000001';

function taskList(extra: Partial<TaskList> = {}): TaskList {
  return {
    id: 'pb-1',
    name: 'Phishing triage',
    description: '',
    tasks: [
      { title: 'Pull the mail headers', owner: 'bob', dueOffsetMinutes: 60, order: 0 },
      { title: 'Block the sender', owner: null, dueOffsetMinutes: null, order: 1 },
    ],
    enabled: true,
    created_by: 'admin',
    created_at: NOW,
    updated_by: 'admin',
    updated_at: NOW,
    ...extra,
  };
}

function task(id: string, order: number, extra: Partial<CaseTask> = {}): CaseTask {
  return { id, title: `Task ${id}`, owner: null, due_at: null, done: false, done_by: null, done_at: null, created_by: 'analyst', created_at: NOW, order, ...extra };
}

/** In-memory task list index: `search`, `get`, `create`, `index`, `delete`. */
function taskListStore(initial: Record<string, any> = {}, options: { missingIndex?: boolean } = {}) {
  const docs = new Map<string, any>(Object.entries(initial));
  const missing = () => Object.assign(new Error('index_not_found_exception'), { meta: { statusCode: 404, body: { error: { type: 'index_not_found_exception' } } } });
  const client: any = {
    search: jest.fn(async ({ index, body }: any) => {
      expect(index).toBe(TASK_LISTS_INDEX);
      if (options.missingIndex) throw missing();
      const hits = Array.from(docs.entries())
        .filter(([, source]) => !body.query.term || source.enabled === body.query.term.enabled)
        .map(([_id, _source]) => ({ _id, _source }));
      return { body: { hits: { total: { value: hits.length }, hits } } };
    }),
    get: jest.fn(async ({ id }: any) => {
      if (options.missingIndex) throw missing();
      if (!docs.has(id)) throw Object.assign(new Error('not found'), { meta: { statusCode: 404 } });
      return { body: { found: true, _source: docs.get(id) } };
    }),
    create: jest.fn(async ({ id, body }: any) => {
      if (docs.has(id)) throw Object.assign(new Error('conflict'), { meta: { statusCode: 409 } });
      docs.set(id, body);
      return { body: { result: 'created' } };
    }),
    index: jest.fn(async ({ id, body }: any) => {
      docs.set(id, body);
      return { body: { result: 'updated' } };
    }),
    delete: jest.fn(async ({ id }: any) => {
      docs.delete(id);
      return { body: { result: 'deleted' } };
    }),
    docs,
  };
  return client;
}

describe('validateTaskListInput', () => {
  test('normalises names, titles, owners and offsets and renumbers order', () => {
    const out = validateTaskListInput({
      name: '  Phishing\n triage ',
      description: ' Steps\nfor mail ',
      tasks: [
        { title: ' Pull\tthe headers ', owner: ' bob ', dueOffsetMinutes: 60 },
        { title: 'Block sender', owner: '', dueOffsetMinutes: null },
        { title: 'Notify', dueOffsetMinutes: '15' },
      ],
    });
    expect(out).toEqual({
      name: 'Phishing triage',
      description: 'Steps\nfor mail',
      enabled: true,
      tasks: [
        { title: 'Pull the headers', owner: 'bob', dueOffsetMinutes: 60, order: 0 },
        { title: 'Block sender', owner: null, dueOffsetMinutes: null, order: 1 },
        { title: 'Notify', owner: null, dueOffsetMinutes: 15, order: 2 },
      ],
    });
    expect(validateTaskListInput({ name: 'x', tasks: [{ title: 't' }], enabled: false }).enabled).toBe(false);
  });

  test('refuses an empty name, no tasks, too many tasks, bad offsets and non-boolean enabled with 400', () => {
    const status = (input: any) => {
      try {
        validateTaskListInput(input);
        return null;
      } catch (e: any) {
        return e.statusCode;
      }
    };
    expect(status({ name: '', tasks: [{ title: 't' }] })).toBe(400);
    expect(status({ name: 'x'.repeat(121), tasks: [{ title: 't' }] })).toBe(400);
    expect(status({ name: 'x', tasks: [] })).toBe(400);
    expect(status({ name: 'x' })).toBe(400);
    expect(status({ name: 'x', tasks: Array.from({ length: TASK_LIST_TASKS_MAX + 1 }, () => ({ title: 't' })) })).toBe(400);
    expect(status({ name: 'x', tasks: [{ title: '' }] })).toBe(400);
    expect(status({ name: 'x', tasks: [{ title: 't', dueOffsetMinutes: 0 }] })).toBe(400);
    expect(status({ name: 'x', tasks: [{ title: 't', dueOffsetMinutes: 525601 }] })).toBe(400);
    expect(status({ name: 'x', tasks: [{ title: 't', dueOffsetMinutes: 1.5 }] })).toBe(400);
    expect(status({ name: 'x', tasks: [{ title: 't', dueOffsetMinutes: true }] })).toBe(400);
    expect(status({ name: 'x', tasks: [{ title: 't', owner: 42 }] })).toBe(400);
    expect(status({ name: 'x', tasks: [{ title: 't' }], enabled: 'yes' })).toBe(400);
    expect(status({ name: 'x', tasks: [{ title: 't', dueOffsetMinutes: 525600 }] })).toBeNull();
  });
});

describe('storage shape', () => {
  test('round-trips camelCase <-> snake_case and keeps the original creator on update', () => {
    const fields = validateTaskListInput({ name: 'P', tasks: [{ title: 'a', dueOffsetMinutes: 5 }, { title: 'b' }] });
    const stored = toStoredTaskList('pb-1', fields, 'admin', NOW);
    expect(stored.tasks).toEqual([
      { title: 'a', owner: null, due_offset_minutes: 5, order: 0 },
      { title: 'b', owner: null, due_offset_minutes: null, order: 1 },
    ]);
    expect(fromStoredTaskList('pb-1', stored)).toEqual({
      id: 'pb-1', name: 'P', description: '', enabled: true,
      tasks: [{ title: 'a', owner: null, dueOffsetMinutes: 5, order: 0 }, { title: 'b', owner: null, dueOffsetMinutes: null, order: 1 }],
      created_by: 'admin', created_at: NOW, updated_by: 'admin', updated_at: NOW,
    });
    const later = toStoredTaskList('pb-1', fields, 'other', '2026-11-22T00:00:00.000Z', fromStoredTaskList('pb-1', stored));
    expect(later).toMatchObject({ created_by: 'admin', created_at: NOW, updated_by: 'other', updated_at: '2026-11-22T00:00:00.000Z' });
  });

  test('a stored document is read defensively: malformed tasks dropped, order restored, bad docs null', () => {
    expect(fromStoredTaskList('pb-1', null)).toBeNull();
    expect(fromStoredTaskList('pb-1', { tasks: [] })).toBeNull();
    expect(fromStoredTaskList('', { name: 'x' })).toBeNull();
    const read = fromStoredTaskList('pb-1', {
      name: 'x', enabled: 'nope',
      tasks: [{ title: 'second', order: 5 }, 'junk', { title: '', order: 0 }, { title: 'first', order: 1, due_offset_minutes: -3, owner: '' }],
    })!;
    expect(read.enabled).toBe(true);
    expect(read.tasks).toEqual([
      { title: 'first', owner: null, dueOffsetMinutes: null, order: 0 },
      { title: 'second', owner: null, dueOffsetMinutes: null, order: 1 },
    ]);
  });

  test('ids are pb-<16 hex> and the id guard accepts only safe route ids', () => {
    expect(newTaskListId()).toMatch(/^pb-[0-9a-f]{16}$/);
    expect(isTaskListId('pb-0123456789abcdef')).toBe(true);
    expect(isTaskListId('a'.repeat(64))).toBe(true);
    expect(isTaskListId('a'.repeat(65))).toBe(false);
    expect(isTaskListId('-leading')).toBe(false);
    expect(isTaskListId('has space')).toBe(false);
    expect(isTaskListId('')).toBe(false);
    expect(isTaskListId(12)).toBe(false);
  });
});

describe('CRUD over the task lists index', () => {
  test('list sorts by name ignoring case, filters enabled, and treats a missing index as empty', async () => {
    const client = taskListStore({
      'pb-b': toStoredTaskList('pb-b', validateTaskListInput({ name: 'beta', tasks: [{ title: 't' }], enabled: false }), 'admin', NOW),
      'pb-a': toStoredTaskList('pb-a', validateTaskListInput({ name: 'Alpha', tasks: [{ title: 't' }] }), 'admin', NOW),
      'pb-c': toStoredTaskList('pb-c', validateTaskListInput({ name: 'charlie', tasks: [{ title: 't' }] }), 'admin', NOW),
      junk: { enabled: true },
    });
    expect((await listTaskLists(client)).map((p) => p.name)).toEqual(['Alpha', 'beta', 'charlie']);
    expect((await listTaskLists(client, { enabledOnly: true })).map((p) => p.id)).toEqual(['pb-a', 'pb-c']);
    expect(client.search.mock.calls[1][0].body.query).toEqual({ term: { enabled: true } });
    expect(client.search.mock.calls[0][0].body.size).toBe(TASK_LISTS_MAX + 1);
    expect(await listTaskLists(taskListStore({}, { missingIndex: true }))).toEqual([]);
  });

  test('get answers 404 for an unknown id, an unsafe id and a missing index', async () => {
    const client = taskListStore({ 'pb-a': toStoredTaskList('pb-a', validateTaskListInput({ name: 'A', tasks: [{ title: 't' }] }), 'admin', NOW) });
    expect((await getTaskList(client, 'pb-a')).name).toBe('A');
    await expect(getTaskList(client, 'pb-zzz')).rejects.toMatchObject({ statusCode: 404 });
    await expect(getTaskList(client, '../x')).rejects.toMatchObject({ statusCode: 404 });
    expect(client.get).toHaveBeenCalledTimes(2);
    await expect(getTaskList(taskListStore({}, { missingIndex: true }), 'pb-a')).rejects.toMatchObject({ statusCode: 404 });
  });

  test('create writes with op_type create on the managed index, refuses duplicate names (case-insensitive) and the cap', async () => {
    const client = taskListStore();
    const created = await createTaskList(client, { name: 'Phishing', tasks: [{ title: 'a' }] }, 'admin', NOW, 'pb-x');
    expect(created).toMatchObject({ id: 'pb-x', name: 'Phishing', enabled: true, created_by: 'admin' });
    expect(client.create).toHaveBeenCalledWith(expect.objectContaining({ index: TASK_LISTS_INDEX, id: 'pb-x', refresh: 'wait_for' }));
    await expect(createTaskList(client, { name: ' phishing ', tasks: [{ title: 'a' }] }, 'admin', NOW)).rejects.toMatchObject({ statusCode: 409 });
    for (let i = 1; i < TASK_LISTS_MAX; i += 1) client.docs.set(`pb-${i}`, toStoredTaskList(`pb-${i}`, validateTaskListInput({ name: `P${i}`, tasks: [{ title: 't' }] }), 'admin', NOW));
    await expect(createTaskList(client, { name: 'one more', tasks: [{ title: 'a' }] }, 'admin', NOW)).rejects.toMatchObject({ statusCode: 409 });
    expect(client.create).toHaveBeenCalledTimes(1);
  });

  test('update replaces the document, keeps the creator, allows keeping its own name and refuses another task list\'s name; delete answers 404 when unknown', async () => {
    const client = taskListStore({
      'pb-a': toStoredTaskList('pb-a', validateTaskListInput({ name: 'A', tasks: [{ title: 't' }] }), 'admin', NOW),
      'pb-b': toStoredTaskList('pb-b', validateTaskListInput({ name: 'B', tasks: [{ title: 't' }] }), 'admin', NOW),
    });
    const { taskList: updated, previous } = await updateTaskList(client, 'pb-a', { name: 'a', tasks: [{ title: 'x', dueOffsetMinutes: 10 }], enabled: false }, 'other', '2026-11-22T00:00:00.000Z');
    expect(previous.name).toBe('A');
    expect(updated).toMatchObject({ id: 'pb-a', name: 'a', enabled: false, created_by: 'admin', updated_by: 'other' });
    expect(client.index).toHaveBeenCalledWith(expect.objectContaining({ index: TASK_LISTS_INDEX, id: 'pb-a', refresh: 'wait_for' }));
    await expect(updateTaskList(client, 'pb-a', { name: 'b', tasks: [{ title: 'x' }] }, 'other')).rejects.toMatchObject({ statusCode: 409 });
    await expect(updateTaskList(client, 'pb-missing', { name: 'z', tasks: [{ title: 'x' }] }, 'other')).rejects.toMatchObject({ statusCode: 404 });
    expect((await deleteTaskList(client, 'pb-b')).name).toBe('B');
    expect(client.delete).toHaveBeenCalledWith(expect.objectContaining({ index: TASK_LISTS_INDEX, id: 'pb-b', refresh: 'wait_for' }));
    await expect(deleteTaskList(client, 'pb-b')).rejects.toMatchObject({ statusCode: 404 });
    expect(() => assertUniqueTaskListName([updated], 'A', 'pb-a')).not.toThrow();
    expect(() => assertUniqueTaskListName([updated], 'A')).toThrow(/already exists/);
  });
});

describe('applyTaskListTasks (pure)', () => {
  test('appends the tasks after the existing ones with due_at = now + offset, owner and actor carried over', () => {
    let n = 0;
    const result = applyTaskListTasks([task('existing', 0)], {}, taskList(), 'carol', NOW, () => `id-${++n}`);
    expect(result.transition).toBe('applied');
    expect(result.added).toHaveLength(2);
    expect(result.tasks.map((t) => [t.id, t.order])).toEqual([['existing', 0], ['id-1', 1], ['id-2', 2]]);
    expect(result.tasks[1]).toMatchObject({ title: 'Pull the mail headers', owner: 'bob', due_at: '2026-11-21T11:00:00.000Z', created_by: 'carol', created_at: NOW, done: false });
    expect(result.tasks[2]).toMatchObject({ title: 'Block the sender', owner: null, due_at: null });
    expect(result.counts).toEqual({ open: 3, done: 0 });
    expect(result.appliedTaskLists).toEqual([{ task_list_id: 'pb-1', applied_at: NOW, applied_by: 'carol' }]);
  });

  test('is idempotent per task list per case and keeps earlier markers', () => {
    const source = { applied_task_lists: [{ task_list_id: 'pb-0', applied_at: NOW, applied_by: 'x' }, { task_list_id: 'pb-1', applied_at: NOW, applied_by: 'x' }] };
    const result = applyTaskListTasks([task('a', 0)], source, taskList(), 'carol', NOW);
    expect(result.transition).toBe('unchanged');
    expect(result.added).toEqual([]);
    expect(result.tasks).toHaveLength(1);
    expect(result.appliedTaskLists).toHaveLength(2);
    const other = applyTaskListTasks([task('a', 0)], source, taskList({ id: 'pb-2' }), 'carol', NOW);
    expect(other.transition).toBe('applied');
    expect(other.appliedTaskLists.map((m) => m.task_list_id)).toEqual(['pb-0', 'pb-1', 'pb-2']);
  });

  test('refuses with 409 and the overflow count when the cap would be exceeded, applying nothing', () => {
    const existing = Array.from({ length: CASE_TASKS_MAX - 1 }, (_, i) => task(`t${i}`, i));
    expect(() => applyTaskListTasks(existing, {}, taskList(), 'carol', NOW)).toThrow(
      expect.objectContaining({ statusCode: 409, message: expect.stringContaining(`${CASE_TASKS_MAX + 1} tasks`) })
    );
    const fits = applyTaskListTasks(existing.slice(0, CASE_TASKS_MAX - 2), {}, taskList(), 'carol', NOW);
    expect(fits.tasks).toHaveLength(CASE_TASKS_MAX);
  });

  test('a malformed applied_task_lists list is ignored and an unparsable now yields no due date', () => {
    const result = applyTaskListTasks([], { applied_task_lists: 'junk' }, taskList(), 'carol', NOW);
    expect(result.transition).toBe('applied');
    const noDue = applyTaskListTasks([], {}, taskList(), 'carol', 'not-a-date');
    expect(noDue.tasks.every((t) => t.due_at === null)).toBe(true);
  });
});

describe('applyTaskListToCase', () => {
  function caseStore(source: Record<string, any>) {
    const state: { source: Record<string, any>; seqNo: number; primaryTerm: number } = { source: { status: 'open', ...source }, seqNo: 3, primaryTerm: 1 };
    resolveCase.mockImplementation(async (_client: any, id: string) => ({ id, index: CASE_INDEX, source: JSON.parse(JSON.stringify(state.source)), seqNo: state.seqNo, primaryTerm: state.primaryTerm }));
    const client: any = {
      update: jest.fn(async ({ body }: any) => {
        state.source = { ...state.source, ...body.script.params.fields, history: [...(state.source.history || []), body.script.params.entry] };
        state.seqNo += 1;
        return { body: { result: 'updated' } };
      }),
      get: jest.fn(async () => ({ body: { _source: JSON.parse(JSON.stringify(state.source)), _seq_no: state.seqNo, _primary_term: state.primaryTerm } })),
      index: jest.fn(async () => ({ body: { result: 'created' } })),
    };
    return { client, state };
  }

  beforeEach(() => resolveCase.mockReset());

  test('writes tasks, task_counts and applied_task_lists in one fenced update and one task_list_applied event', async () => {
    const { client, state } = caseStore({ tasks: [task('a', 0)] });
    const out = await applyTaskListToCase(client, 'case-1', taskList(), 'carol', NOW);
    expect(out).toEqual({ applied: true, task_list_id: 'pb-1', tasks_added: 2, counts: { open: 3, done: 0 } });
    const update = client.update.mock.calls[0][0];
    expect(update).toMatchObject({ index: CASE_INDEX, id: 'case-1', refresh: 'wait_for', if_seq_no: 3, if_primary_term: 1 });
    expect(update.body.script.params.fields).toMatchObject({
      applied_task_lists: [{ task_list_id: 'pb-1', applied_at: NOW, applied_by: 'carol' }],
      task_counts: { open: 3, done: 0 },
      updated_by: 'carol',
      updated_at: NOW,
    });
    expect(update.body.script.params.fields.tasks).toHaveLength(3);
    expect(update.body.script.params.entry).toMatchObject({ user: 'carol', action: 'task_list_applied', to: 'Phishing triage' });
    expect(client.index).toHaveBeenCalledTimes(1);
    expect(client.index.mock.calls[0][0]).toMatchObject({ index: ACTIVITY_WRITE_ALIAS });
    expect(client.index.mock.calls[0][0].body).toMatchObject({
      target_type: 'case', target_id: 'case-1', case_id: 'case-1', user: 'carol', action: 'task_list_applied', source: 'user',
      details: { task_list_id: 'pb-1', name: 'Phishing triage', tasks_added: 2 },
    });
    expect(state.source.applied_task_lists).toHaveLength(1);

    const again = await applyTaskListToCase(client, 'case-1', taskList(), 'carol', NOW);
    expect(again).toEqual({ applied: false, reason: 'already_applied', task_list_id: 'pb-1', tasks_added: 0, counts: { open: 3, done: 0 } });
    expect(client.update).toHaveBeenCalledTimes(1);
    expect(client.index).toHaveBeenCalledTimes(1);
  });

  test('refuses a disabled task list (409) and a closed case (409) without writing', async () => {
    const { client } = caseStore({});
    await expect(applyTaskListToCase(client, 'case-1', taskList({ enabled: false }), 'carol', NOW)).rejects.toMatchObject({ statusCode: 409 });
    const closed = caseStore({ status: 'closed' });
    await expect(applyTaskListToCase(closed.client, 'case-1', taskList(), 'carol', NOW)).rejects.toMatchObject({ statusCode: 409 });
    expect(client.update).not.toHaveBeenCalled();
    expect(closed.client.update).not.toHaveBeenCalled();
  });

  test('automation options: deterministic activity id with op_type create, source automation and the operation id', async () => {
    const { client } = caseStore({});
    await applyTaskListToCase(client, 'case-1', taskList(), 'correlation-rule', NOW, { source: 'automation', operationId: 'rule-1|key', ruleRevision: 4, activityId: 'task-list-apply:abc' });
    expect(client.index.mock.calls[0][0]).toMatchObject({ id: 'task-list-apply:abc', op_type: 'create' });
    expect(client.index.mock.calls[0][0].body).toMatchObject({ source: 'automation', operation_id: 'rule-1|key', rule_revision: 4, user: 'correlation-rule' });
  });

  test('retries once from a realtime GET after a stale search token, then surfaces 409', async () => {
    const { client, state } = caseStore({});
    let first = true;
    const update = client.update;
    client.update = jest.fn(async (req: any) => {
      if (first) {
        first = false;
        state.seqNo += 1; // a refresh: false writer moved the document
        throw Object.assign(new Error('version conflict'), { meta: { statusCode: 409 } });
      }
      return update(req);
    });
    const out = await applyTaskListToCase(client, 'case-1', taskList(), 'carol', NOW);
    expect(out.applied).toBe(true);
    expect(client.get).toHaveBeenCalledTimes(1);
    expect(client.update.mock.calls[1][0].if_seq_no).toBe(4);

    const always = caseStore({});
    always.client.update = jest.fn(async () => { throw Object.assign(new Error('version conflict'), { meta: { statusCode: 409 } }); });
    await expect(applyTaskListToCase(always.client, 'case-1', taskList(), 'carol', NOW)).rejects.toMatchObject({ statusCode: 409 });
  });
});
