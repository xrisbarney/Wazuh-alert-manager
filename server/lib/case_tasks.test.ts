import { CASE_TASKS_MAX, CASE_TASK_TITLE_MAX_LENGTH, CaseTask } from '../../common';
import {
  addTask,
  newTaskId,
  normaliseStoredTasks,
  removeTask,
  reorderTasks,
  taskCounts,
  updateTask,
  validateTaskInput,
} from './case_tasks';

const NOW = '2026-11-21T10:00:00.000Z';

function task(id: string, order: number, extra: Partial<CaseTask> = {}): CaseTask {
  return {
    id,
    title: `Task ${id}`,
    owner: null,
    due_at: null,
    done: false,
    done_by: null,
    done_at: null,
    created_by: 'analyst',
    created_at: NOW,
    order,
    ...extra,
  };
}

describe('validateTaskInput', () => {
  test('requires a single-line title within the cap on create', () => {
    expect(validateTaskInput({ title: '  Block\nthe  host ' })).toEqual({ title: 'Block the host', owner: null, due_at: null });
    expect(() => validateTaskInput({ title: '' })).toThrow('needs a title');
    expect(() => validateTaskInput({})).toThrow('needs a title');
    expect(() => validateTaskInput({ title: 'x'.repeat(CASE_TASK_TITLE_MAX_LENGTH + 1) })).toThrow('at most 200');
    expect(validateTaskInput({ title: 'x'.repeat(CASE_TASK_TITLE_MAX_LENGTH) }).title).toHaveLength(CASE_TASK_TITLE_MAX_LENGTH);
  });

  test('normalises owner and due date, refuses garbage', () => {
    expect(validateTaskInput({ title: 't', owner: '  bob ', dueAt: '2026-11-22T00:00:00Z' })).toEqual({
      title: 't',
      owner: 'bob',
      due_at: '2026-11-22T00:00:00.000Z',
    });
    expect(validateTaskInput({ title: 't', owner: '', dueAt: '' })).toEqual({ title: 't', owner: null, due_at: null });
    expect(() => validateTaskInput({ title: 't', dueAt: 'tomorrow-ish' })).toThrow('ISO 8601');
    expect(() => validateTaskInput({ title: 't', owner: 42 })).toThrow('owner must be');
  });

  test('partial mode only touches the keys that are present', () => {
    expect(validateTaskInput({}, { partial: true })).toEqual({});
    expect(validateTaskInput({ owner: null }, { partial: true })).toEqual({ owner: null });
    expect(validateTaskInput({ title: 'new' }, { partial: true })).toEqual({ title: 'new' });
    expect(() => validateTaskInput({ title: '' }, { partial: true })).toThrow('needs a title');
  });

  test('every validation error carries statusCode 400', () => {
    try {
      validateTaskInput({ title: '' });
      throw new Error('expected a throw');
    } catch (e: any) {
      expect(e.statusCode).toBe(400);
    }
  });
});

describe('ids, ordering and counts', () => {
  test('newTaskId is 12 lower-case base36 characters and unique', () => {
    const ids = new Set(Array.from({ length: 200 }, () => newTaskId()));
    expect(ids.size).toBe(200);
    for (const id of ids) expect(id).toMatch(/^[0-9a-z]{12}$/);
  });

  test('reorderTasks sorts by order then created_at and renumbers densely without mutating', () => {
    const input = [task('b', 5), task('a', 2, { created_at: '2026-01-01T00:00:00.000Z' }), task('c', 2)];
    const frozen = JSON.stringify(input);
    const out = reorderTasks(input);
    expect(out.map((t) => [t.id, t.order])).toEqual([['a', 0], ['c', 1], ['b', 2]]);
    expect(JSON.stringify(input)).toBe(frozen);
    expect(out[0]).not.toBe(input[1]);
  });

  test('taskCounts splits open and done', () => {
    expect(taskCounts([])).toEqual({ open: 0, done: 0 });
    expect(taskCounts([task('a', 0), task('b', 1, { done: true }), task('c', 2, { done: true })])).toEqual({ open: 1, done: 2 });
  });

  test('normaliseStoredTasks drops malformed rows and tolerates non-arrays', () => {
    expect(normaliseStoredTasks(undefined)).toEqual([]);
    expect(normaliseStoredTasks('nope')).toEqual([]);
    const out = normaliseStoredTasks([
      { id: 'ok', title: 'fine', done: 'yes', order: '3' },
      { id: '', title: 'no id' },
      null,
      { id: 'x', title: 'also fine', done: true, order: 1, owner: 7 },
    ]);
    expect(out.map((t) => [t.id, t.order, t.done, t.owner])).toEqual([['x', 0, true, null], ['ok', 1, false, null]]);
  });
});

describe('addTask', () => {
  test('appends at the end with actor and timestamp, returns counts, never mutates', () => {
    const existing = [task('a', 0, { done: true })];
    const result = addTask(existing, { title: 'Collect logs', owner: 'bob', dueAt: '2026-11-22T00:00:00Z' }, 'alice', NOW, 'newid0000001');
    expect(result.task).toEqual({
      id: 'newid0000001',
      title: 'Collect logs',
      owner: 'bob',
      due_at: '2026-11-22T00:00:00.000Z',
      done: false,
      done_by: null,
      done_at: null,
      created_by: 'alice',
      created_at: NOW,
      order: 1,
    });
    expect(result.tasks).toHaveLength(2);
    expect(result.counts).toEqual({ open: 1, done: 1 });
    expect(existing).toHaveLength(1);
  });

  test('refuses the 101st task with a 409 before validating the input', () => {
    const full = Array.from({ length: CASE_TASKS_MAX }, (_, i) => task(`t${i}`, i));
    try {
      addTask(full, { title: 'one more' }, 'alice', NOW);
      throw new Error('expected a throw');
    } catch (e: any) {
      expect(e.statusCode).toBe(409);
      expect(e.message).toContain(`${CASE_TASKS_MAX} tasks`);
    }
    expect(addTask(full.slice(0, CASE_TASKS_MAX - 1), { title: 'fits' }, 'alice', NOW).tasks).toHaveLength(CASE_TASKS_MAX);
  });

  test('renumbers a sparse stored list before appending', () => {
    const result = addTask([task('a', 7), task('b', 3)], { title: 'c' }, 'alice', NOW, 'cid000000000');
    expect(result.tasks.map((t) => [t.id, t.order])).toEqual([['b', 0], ['a', 1], ['cid000000000', 2]]);
  });
});

describe('updateTask', () => {
  const list = [task('a', 0), task('b', 1), task('c', 2)];

  test('done: true stamps done_by/done_at from the actor and reports completed', () => {
    const result = updateTask(list, 'b', { done: true }, 'alice', NOW);
    expect(result.transition).toBe('completed');
    expect(result.task).toMatchObject({ id: 'b', done: true, done_by: 'alice', done_at: NOW, order: 1 });
    expect(result.previous.done).toBe(false);
    expect(result.counts).toEqual({ open: 2, done: 1 });
    expect(list[1].done).toBe(false);
  });

  test('done: false clears the stamps and reports reopened', () => {
    const doneList = [task('a', 0, { done: true, done_by: 'bob', done_at: NOW })];
    const result = updateTask(doneList, 'a', { done: false }, 'alice', NOW);
    expect(result.transition).toBe('reopened');
    expect(result.task).toMatchObject({ done: false, done_by: null, done_at: null });
  });

  test('field edits report updated; an identical patch is unchanged; done wins over fields for the action', () => {
    expect(updateTask(list, 'a', { title: 'renamed' }, 'alice', NOW).transition).toBe('updated');
    expect(updateTask(list, 'a', { owner: 'bob', dueAt: null }, 'alice', NOW).transition).toBe('updated');
    expect(updateTask(list, 'a', { title: 'Task a' }, 'alice', NOW).transition).toBe('unchanged');
    expect(updateTask(list, 'a', { done: false }, 'alice', NOW).transition).toBe('unchanged');
    expect(updateTask(list, 'a', { title: 'renamed', done: true }, 'alice', NOW).transition).toBe('completed');
  });

  test('order moves the task and renumbers the rest, clamped to the end', () => {
    expect(updateTask(list, 'a', { order: 2 }, 'alice', NOW).tasks.map((t) => [t.id, t.order])).toEqual([['b', 0], ['c', 1], ['a', 2]]);
    expect(updateTask(list, 'c', { order: 0 }, 'alice', NOW).tasks.map((t) => [t.id, t.order])).toEqual([['c', 0], ['a', 1], ['b', 2]]);
    expect(updateTask(list, 'a', { order: 99 }, 'alice', NOW).tasks.map((t) => t.id)).toEqual(['b', 'c', 'a']);
    expect(updateTask(list, 'a', { order: 2 }, 'alice', NOW).transition).toBe('updated');
    expect(updateTask(list, 'a', { order: 0 }, 'alice', NOW).transition).toBe('unchanged');
  });

  test('unknown task is 404, bad flags are 400', () => {
    expect(() => updateTask(list, 'zzz', { done: true }, 'alice', NOW)).toThrow(expect.objectContaining({ statusCode: 404 }));
    expect(() => updateTask(list, 'a', { done: 'yes' }, 'alice', NOW)).toThrow(expect.objectContaining({ statusCode: 400 }));
    expect(() => updateTask(list, 'a', { order: -1 }, 'alice', NOW)).toThrow(expect.objectContaining({ statusCode: 400 }));
    expect(() => updateTask(list, 'a', { order: 1.5 }, 'alice', NOW)).toThrow(expect.objectContaining({ statusCode: 400 }));
    expect(() => updateTask(list, 'a', { title: '' }, 'alice', NOW)).toThrow(expect.objectContaining({ statusCode: 400 }));
  });
});

describe('removeTask', () => {
  test('drops the task, renumbers and recounts; unknown is 404', () => {
    const list = [task('a', 0, { done: true }), task('b', 1), task('c', 2)];
    const result = removeTask(list, 'b');
    expect(result.task.id).toBe('b');
    expect(result.tasks.map((t) => [t.id, t.order])).toEqual([['a', 0], ['c', 1]]);
    expect(result.counts).toEqual({ open: 1, done: 1 });
    expect(list).toHaveLength(3);
    expect(() => removeTask(list, 'nope')).toThrow(expect.objectContaining({ statusCode: 404 }));
  });
});
