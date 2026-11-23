/**
 * @jest-environment jsdom
 */
import React from 'react';
import { configure, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { TASK_LIST_TASKS_MAX, TaskList } from '../../common';
import { TaskListsView, draftToInput, emptyDraft, formatOffset, toDraft } from './task_lists_view';

jest.mock('./assignee_picker', () => ({
  AssigneePicker: ({ value, onChange, testSubj, isDisabled }: any) => (
    <input data-test-subj={testSubj} value={value || ''} disabled={isDisabled} onChange={(e: any) => onChange(e.target.value || null)} />
  ),
}));

configure({ testIdAttribute: 'data-test-subj' });

const NOW = '2026-11-21T10:00:00.000Z';
const TRIAGE: TaskList = {
  id: 'pb-1', name: 'Phishing triage', description: 'Mail incidents', enabled: true,
  tasks: [{ title: 'Pull headers', owner: 'bob', dueOffsetMinutes: 60, order: 0 }, { title: 'Block sender', owner: null, dueOffsetMinutes: null, order: 1 }],
  created_by: 'admin', created_at: NOW, updated_by: 'admin', updated_at: NOW,
};
const OFF: TaskList = { ...TRIAGE, id: 'pb-2', name: 'Retired', enabled: false, tasks: [TRIAGE.tasks[0]] };

function service(isPluginAdmin: boolean, taskLists: TaskList[] = [TRIAGE, OFF], failFirstLoad = false) {
  let stored = [...taskLists];
  let fail = failFirstLoad;
  return {
    fetchSystemCapabilities: jest.fn(async () => ({ isPluginAdmin })),
    fetchTaskLists: jest.fn(async () => {
      if (fail) {
        fail = false;
        throw new Error('task lists index unavailable');
      }
      return { taskLists: stored, limit: 200 };
    }),
    createTaskList: jest.fn(async (input: any) => {
      const taskList = { ...TRIAGE, id: 'pb-new', ...input, tasks: input.tasks.map((t: any, order: number) => ({ ...t, order })) };
      stored = [...stored, taskList];
      return { taskList };
    }),
    updateTaskList: jest.fn(async (id: string, input: any) => {
      const taskList = { ...stored.find((p) => p.id === id)!, ...input, tasks: input.tasks.map((t: any, order: number) => ({ ...t, order })) };
      stored = stored.map((p) => (p.id === id ? taskList : p));
      return { taskList };
    }),
    deleteTaskList: jest.fn(async (id: string) => {
      stored = stored.filter((p) => p.id !== id);
      return { deleted: true };
    }),
  } as any;
}

describe('draft helpers', () => {
  test('toDraft / draftToInput round-trip and validation', () => {
    const draft = toDraft(TRIAGE);
    expect(draft.tasks.map((t) => [t.title, t.owner, t.dueOffsetMinutes])).toEqual([['Pull headers', 'bob', '60'], ['Block sender', '', '']]);
    const { input, errors } = draftToInput(draft);
    expect(errors).toEqual([]);
    expect(input).toEqual({
      name: 'Phishing triage', description: 'Mail incidents', enabled: true,
      tasks: [{ title: 'Pull headers', owner: 'bob', dueOffsetMinutes: 60 }, { title: 'Block sender', owner: null, dueOffsetMinutes: null }],
    });
    const empty = draftToInput(emptyDraft());
    expect(empty.input).toBeNull();
    expect(empty.errors).toEqual(['A task list needs a name.', 'A task list needs at least one task.']);
    const bad = draftToInput({ ...draft, tasks: [{ ...draft.tasks[0], title: '', dueOffsetMinutes: '0' }, { ...draft.tasks[1], dueOffsetMinutes: '1.5' }] });
    expect(bad.errors).toEqual([
      'Task 1 needs a title.',
      'Task 1: the due offset must be 1-525600 whole minutes.',
      'Task 2: the due offset must be 1-525600 whole minutes.',
    ]);
    expect(formatOffset(null)).toBe('-');
    expect(formatOffset(45)).toBe('45 min');
    expect(formatOffset(120)).not.toBe('-');
  });
});

describe('TaskListsView', () => {
  test('locks the tab for non-administrators but still lists the task lists', async () => {
    render(<TaskListsView apiService={service(false)} onToast={jest.fn()} />);
    await waitFor(() => expect(screen.getByText(/administered by Wazuh administrators/)).toBeTruthy());
    expect(screen.queryByTestId('wamTaskListNew')).toBeNull();
    expect(screen.queryByTestId('wamTaskListEdit-pb-1')).toBeNull();
    expect(screen.getByTestId('wamTaskListName-pb-1').textContent).toBe('Phishing triage');
    expect(screen.getByTestId('wamTaskListTasks-pb-1').textContent).toBe('2');
    expect(screen.getByTestId('wamTaskListEnabled-pb-2').textContent).toBe('Disabled');
  });

  test('shows the load error with Retry and recovers', async () => {
    const api = service(true, [TRIAGE], true);
    render(<TaskListsView apiService={api} onToast={jest.fn()} />);
    await waitFor(() => expect(screen.getByTestId('wamTaskListsError')).toBeTruthy());
    expect(screen.getByText(/task lists index unavailable/)).toBeTruthy();
    fireEvent.click(screen.getByTestId('wamTaskListsRetry'));
    await waitFor(() => expect(screen.getByTestId('wamTaskListName-pb-1')).toBeTruthy());
    expect(screen.queryByTestId('wamTaskListsError')).toBeNull();
    expect(api.fetchTaskLists).toHaveBeenCalledTimes(2);
  });

  test('an administrator creates a task list through the editor (validation first, then the API)', async () => {
    const api = service(true, []);
    const onToast = jest.fn();
    render(<TaskListsView apiService={api} onToast={onToast} />);
    await waitFor(() => expect(screen.getByTestId('wamTaskListsEmpty')).toBeTruthy());
    fireEvent.click(screen.getByTestId('wamTaskListNew'));
    expect(screen.getByTestId('wamTaskListEditor')).toBeTruthy();
    fireEvent.click(screen.getByTestId('wamTaskListSave'));
    await waitFor(() => expect(screen.getByTestId('wamTaskListFormErrors')).toBeTruthy());
    expect(api.createTaskList).not.toHaveBeenCalled();

    fireEvent.change(screen.getByTestId('wamTaskListName'), { target: { value: ' Ransomware ' } });
    fireEvent.change(screen.getByTestId('wamTaskListTaskTitle-0'), { target: { value: 'Isolate host' } });
    fireEvent.change(screen.getByTestId('wamTaskListTaskOwner-0'), { target: { value: 'ir-team' } });
    fireEvent.change(screen.getByTestId('wamTaskListTaskDue-0'), { target: { value: '30' } });
    fireEvent.click(screen.getByTestId('wamTaskListTaskAdd'));
    fireEvent.change(screen.getByTestId('wamTaskListTaskTitle-1'), { target: { value: 'Collect memory' } });
    expect(screen.getByTestId('wamTaskListTaskAdd').textContent).toContain(`2/${TASK_LIST_TASKS_MAX}`);
    fireEvent.click(screen.getByTestId('wamTaskListSave'));
    await waitFor(() => expect(api.createTaskList).toHaveBeenCalledTimes(1));
    expect(api.createTaskList).toHaveBeenCalledWith({
      name: 'Ransomware', description: undefined, enabled: true,
      tasks: [{ title: 'Isolate host', owner: 'ir-team', dueOffsetMinutes: 30 }, { title: 'Collect memory', owner: null, dueOffsetMinutes: null }],
    });
    await waitFor(() => expect(screen.getByTestId('wamTaskListName-pb-new')).toBeTruthy());
    expect(screen.queryByTestId('wamTaskListEditor')).toBeNull();
    expect(onToast).toHaveBeenCalledWith('Task list created', 'success', 'Ransomware');
  });

  test('edit loads the draft, the enable toggle saves the whole document, delete asks for confirmation', async () => {
    const api = service(true);
    const onToast = jest.fn();
    render(<TaskListsView apiService={api} onToast={onToast} />);
    await waitFor(() => expect(screen.getByTestId('wamTaskListEdit-pb-1')).toBeTruthy());
    fireEvent.click(screen.getByTestId('wamTaskListEdit-pb-1'));
    expect((screen.getByTestId('wamTaskListName') as HTMLInputElement).value).toBe('Phishing triage');
    expect((screen.getByTestId('wamTaskListTaskDue-0') as HTMLInputElement).value).toBe('60');
    fireEvent.click(screen.getByTestId('wamTaskListTaskRemove-1'));
    fireEvent.click(screen.getByTestId('wamTaskListSave'));
    await waitFor(() => expect(api.updateTaskList).toHaveBeenCalledTimes(1));
    expect(api.updateTaskList.mock.calls[0][0]).toBe('pb-1');
    expect(api.updateTaskList.mock.calls[0][1].tasks).toEqual([{ title: 'Pull headers', owner: 'bob', dueOffsetMinutes: 60 }]);

    fireEvent.click(screen.getByTestId('wamTaskListEnabled-pb-2'));
    await waitFor(() => expect(api.updateTaskList).toHaveBeenCalledTimes(2));
    expect(api.updateTaskList.mock.calls[1]).toEqual(['pb-2', { name: 'Retired', description: 'Mail incidents', enabled: true, tasks: [{ title: 'Pull headers', owner: 'bob', dueOffsetMinutes: 60 }] }]);

    fireEvent.click(screen.getByTestId('wamTaskListDelete-pb-1'));
    await waitFor(() => expect(screen.getByTestId('wamTaskListDeleteConfirm')).toBeTruthy());
    expect(api.deleteTaskList).not.toHaveBeenCalled();
    fireEvent.click(screen.getByText('Delete task list'));
    await waitFor(() => expect(api.deleteTaskList).toHaveBeenCalledWith('pb-1'));
    await waitFor(() => expect(screen.queryByTestId('wamTaskListName-pb-1')).toBeNull());
    expect(onToast).toHaveBeenCalledWith('Task list deleted', 'success', 'Phishing triage');
  });

  test('a save failure keeps the editor open and toasts the server message', async () => {
    const api = service(true, [TRIAGE]);
    api.createTaskList.mockRejectedValueOnce({ body: { message: 'A task list named "Phishing triage" already exists.' } });
    const onToast = jest.fn();
    render(<TaskListsView apiService={api} onToast={onToast} />);
    await waitFor(() => expect(screen.getByTestId('wamTaskListNew')).toBeTruthy());
    fireEvent.click(screen.getByTestId('wamTaskListNew'));
    fireEvent.change(screen.getByTestId('wamTaskListName'), { target: { value: 'phishing triage' } });
    fireEvent.change(screen.getByTestId('wamTaskListTaskTitle-0'), { target: { value: 'x' } });
    fireEvent.click(screen.getByTestId('wamTaskListSave'));
    await waitFor(() => expect(onToast).toHaveBeenCalledWith('Task list could not be saved', 'danger', 'A task list named "Phishing triage" already exists.'));
    expect(screen.getByTestId('wamTaskListEditor')).toBeTruthy();
  });
});
