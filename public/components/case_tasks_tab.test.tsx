/**
 * @jest-environment jsdom
 */
import React from 'react';
import { configure, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { CASE_TASKS_MAX, CaseTask } from '../../common';
import { CaseTasksChip, CaseTasksTab, tasksChipLabel } from './case_tasks_tab';

jest.mock('./assignee_picker', () => ({
  AssigneePicker: ({ value, onChange, testSubj, isDisabled }: any) => (
    <input data-test-subj={testSubj} value={value || ''} disabled={isDisabled} onChange={(e: any) => onChange(e.target.value || null)} />
  ),
}));

configure({ testIdAttribute: 'data-test-subj' });

const OPEN: CaseTask = { id: 'aaaaaaaaaaa1', title: 'Collect logs', owner: 'bob', due_at: '2020-01-01T00:00:00.000Z', done: false, done_by: null, done_at: null, created_by: 'alice', created_at: '2026-11-20T10:00:00.000Z', order: 0 };
const DONE: CaseTask = { id: 'aaaaaaaaaaa2', title: 'Isolate host', owner: null, due_at: null, done: true, done_by: 'carol', done_at: '2026-11-20T12:00:00.000Z', created_by: 'alice', created_at: '2026-11-20T11:00:00.000Z', order: 1 };

function service(fetchImpl: () => Promise<any>) {
  return {
    fetchCaseTasks: jest.fn(fetchImpl),
    addCaseTask: jest.fn(async () => ({ task: { ...OPEN, id: 'aaaaaaaaaaa3', title: 'New' }, counts: { open: 2, done: 1 } })),
    updateCaseTask: jest.fn(async () => ({ task: { ...OPEN, done: true, done_by: 'me' }, counts: { open: 0, done: 2 } })),
    deleteCaseTask: jest.fn(async () => ({ deleted: true, counts: { open: 0, done: 1 } })),
    fetchTaskLists: jest.fn(async () => ({ taskLists: [] })),
    applyTaskListToCase: jest.fn(async () => ({ applied: true, task_list_id: 'pb-1', tasks_added: 2, counts: { open: 3, done: 0 } })),
  } as any;
}

const TASK_LIST = { id: 'pb-1', name: 'Phishing triage', description: '', enabled: true, tasks: [], created_by: 'alice', created_at: '2026-11-20T10:00:00.000Z', updated_by: 'alice', updated_at: '2026-11-20T10:00:00.000Z' };
const DISABLED_TASK_LIST = { ...TASK_LIST, id: 'pb-2', name: 'Retired', enabled: false };

describe('tasksChipLabel / CaseTasksChip', () => {
  test('is hidden without tasks and reads done/total otherwise', () => {
    expect(tasksChipLabel(undefined)).toBeNull();
    expect(tasksChipLabel({ open: 0, done: 0 })).toBeNull();
    expect(tasksChipLabel({ open: 4, done: 3 })).toBe('3/7 tasks');
    const { container, rerender } = render(<CaseTasksChip counts={{ open: 0, done: 0 }} />);
    expect(container.querySelector('.wamCaseTasksChip')).toBeNull();
    rerender(<CaseTasksChip counts={{ open: 4, done: 3 }} testSubj="chip" />);
    expect(screen.getByTestId('chip').textContent).toBe('3/7 tasks');
    expect(screen.getByTestId('chip').className).toContain('wamCaseTasksChip');
    rerender(<CaseTasksChip counts={{ open: 0, done: 2 }} testSubj="chip" />);
    expect(screen.getByTestId('chip').className).toContain('wamCaseTasksChip--done');
  });
});

describe('CaseTasksTab', () => {
  test('renders the checklist with counts, overdue and done metadata, and toggling calls the API', async () => {
    const apiService = service(async () => ({ tasks: [OPEN, DONE], counts: { open: 1, done: 1 }, limit: CASE_TASKS_MAX }));
    const onError = jest.fn();
    const onCountsChanged = jest.fn();
    render(<CaseTasksTab caseId="case-1" apiService={apiService} onError={onError} onCountsChanged={onCountsChanged} />);
    await waitFor(() => expect(screen.getByTestId('wamCaseTasks')).toBeTruthy());
    expect(apiService.fetchCaseTasks).toHaveBeenCalledWith('case-1');
    expect(screen.getByTestId('wamCaseTasksCounts').textContent).toBe('1/2 done');
    expect(screen.getByTestId(`wamCaseTaskTitle-${OPEN.id}`).textContent).toBe('Collect logs');
    expect(screen.getByTestId(`wamCaseTaskOwner-${OPEN.id}`).textContent).toBe('bob');
    expect(screen.getByTestId(`wamCaseTaskDue-${OPEN.id}`).textContent).toContain('Overdue');
    expect(screen.getByTestId(`wamCaseTaskRow-${OPEN.id}`).className).toContain('wamCaseTask--overdue');
    expect(screen.getByTestId(`wamCaseTaskRow-${DONE.id}`).className).toContain('wamCaseTask--done');
    expect(screen.getByTestId(`wamCaseTaskDoneBy-${DONE.id}`).textContent).toContain('Done by carol');
    expect((screen.getByTestId(`wamCaseTaskDone-${DONE.id}`) as HTMLInputElement).checked).toBe(true);
    expect((screen.getByTestId(`wamCaseTaskDone-${OPEN.id}`) as HTMLInputElement).checked).toBe(false);
    expect(screen.getAllByTestId(/^wamCaseTaskRemove-/)).toHaveLength(2);
    expect((screen.getByTestId('wamCaseTaskAdd') as HTMLButtonElement).disabled).toBe(false);
    expect(screen.queryByTestId('wamCaseTasksError')).toBeNull();

    fireEvent.click(screen.getByTestId(`wamCaseTaskDone-${OPEN.id}`));
    await waitFor(() => expect(apiService.updateCaseTask).toHaveBeenCalledWith('case-1', OPEN.id, { done: true }));
    await waitFor(() => expect(onCountsChanged).toHaveBeenCalledWith({ open: 0, done: 2 }));
    expect(apiService.fetchCaseTasks).toHaveBeenCalledTimes(2);
    expect(onError).not.toHaveBeenCalled();
  });

  test('adds a task from the inline form and removes one from the row action', async () => {
    const apiService = service(async () => ({ tasks: [OPEN], counts: { open: 1, done: 0 }, limit: CASE_TASKS_MAX }));
    render(<CaseTasksTab caseId="case-1" apiService={apiService} onError={jest.fn()} />);
    await waitFor(() => expect(screen.getByTestId('wamCaseTaskAdd')).toBeTruthy());

    fireEvent.click(screen.getByTestId('wamCaseTaskAdd'));
    expect(screen.getByTestId('wamCaseTaskForm')).toBeTruthy();
    expect((screen.getByTestId('wamCaseTaskSave') as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByTestId('wamCaseTaskNewTitle'), { target: { value: '  Block the IP ' } });
    fireEvent.change(screen.getByTestId('wamCaseTaskNewOwner'), { target: { value: 'dave' } });
    expect((screen.getByTestId('wamCaseTaskSave') as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(screen.getByTestId('wamCaseTaskSave'));
    await waitFor(() => expect(apiService.addCaseTask).toHaveBeenCalledWith('case-1', { title: 'Block the IP', owner: 'dave', dueAt: null }));
    await waitFor(() => expect(screen.queryByTestId('wamCaseTaskForm')).toBeNull());

    fireEvent.click(screen.getByTestId(`wamCaseTaskRemove-${OPEN.id}`));
    await waitFor(() => expect(apiService.deleteCaseTask).toHaveBeenCalledWith('case-1', OPEN.id));
  });

  test('applies an enabled task list from the tab header and toasts an already-applied one (step 2.2)', async () => {
    const apiService = service(async () => ({ tasks: [OPEN], counts: { open: 1, done: 0 }, limit: CASE_TASKS_MAX }));
    apiService.fetchTaskLists.mockResolvedValue({ taskLists: [TASK_LIST, DISABLED_TASK_LIST] });
    const onToast = jest.fn();
    const onCountsChanged = jest.fn();
    render(<CaseTasksTab caseId="case-1" apiService={apiService} onError={jest.fn()} onToast={onToast} onCountsChanged={onCountsChanged} />);
    await waitFor(() => expect(screen.getByTestId('wamCaseTasksTaskList')).toBeTruthy());
    expect(apiService.fetchTaskLists).toHaveBeenCalledWith(true);
    const select = screen.getByTestId('wamCaseTasksTaskList') as HTMLSelectElement;
    expect(Array.from(select.options).map((option) => option.value)).toEqual(['', 'pb-1']);
    expect((screen.getByTestId('wamCaseTasksTaskListApply') as HTMLButtonElement).disabled).toBe(true);

    fireEvent.change(select, { target: { value: 'pb-1' } });
    expect((screen.getByTestId('wamCaseTasksTaskListApply') as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(screen.getByTestId('wamCaseTasksTaskListApply'));
    await waitFor(() => expect(apiService.applyTaskListToCase).toHaveBeenCalledWith('case-1', 'pb-1'));
    await waitFor(() => expect(onCountsChanged).toHaveBeenCalledWith({ open: 3, done: 0 }));
    expect(onToast).toHaveBeenCalledWith('Task list applied', 'success', 'Phishing triage: 2 task(s) added');
    expect(apiService.fetchCaseTasks).toHaveBeenCalledTimes(2);
    await waitFor(() => expect((screen.getByTestId('wamCaseTasksTaskList') as HTMLSelectElement).value).toBe(''));

    apiService.applyTaskListToCase.mockResolvedValueOnce({ applied: false, reason: 'already_applied', task_list_id: 'pb-1', tasks_added: 0, counts: { open: 3, done: 0 } });
    fireEvent.change(screen.getByTestId('wamCaseTasksTaskList'), { target: { value: 'pb-1' } });
    fireEvent.click(screen.getByTestId('wamCaseTasksTaskListApply'));
    await waitFor(() => expect(onToast).toHaveBeenCalledWith('Task list already applied', 'primary', expect.stringContaining('Phishing triage')));
    expect(apiService.fetchCaseTasks).toHaveBeenCalledTimes(2);
  });

  test('hides the task list control without enabled task lists, on a closed case, and when the list fails', async () => {
    const empty = service(async () => ({ tasks: [], counts: { open: 0, done: 0 }, limit: CASE_TASKS_MAX }));
    const { unmount } = render(<CaseTasksTab caseId="case-1" apiService={empty} onError={jest.fn()} />);
    await waitFor(() => expect(screen.getByTestId('wamCaseTasks')).toBeTruthy());
    await waitFor(() => expect(empty.fetchTaskLists).toHaveBeenCalled());
    expect(screen.queryByTestId('wamCaseTasksTaskList')).toBeNull();
    unmount();

    const closed = service(async () => ({ tasks: [], counts: { open: 0, done: 0 }, limit: CASE_TASKS_MAX }));
    closed.fetchTaskLists.mockResolvedValue({ taskLists: [TASK_LIST] });
    const closedRender = render(<CaseTasksTab caseId="case-1" apiService={closed} readOnly onError={jest.fn()} />);
    await waitFor(() => expect(screen.getByTestId('wamCaseTasks')).toBeTruthy());
    expect(closed.fetchTaskLists).not.toHaveBeenCalled();
    expect(screen.queryByTestId('wamCaseTasksTaskList')).toBeNull();
    closedRender.unmount();

    const failing = service(async () => ({ tasks: [], counts: { open: 0, done: 0 }, limit: CASE_TASKS_MAX }));
    const onError = jest.fn();
    failing.fetchTaskLists.mockRejectedValue(new Error('403'));
    render(<CaseTasksTab caseId="case-1" apiService={failing} onError={onError} />);
    await waitFor(() => expect(screen.getByTestId('wamCaseTasks')).toBeTruthy());
    await waitFor(() => expect(failing.fetchTaskLists).toHaveBeenCalled());
    expect(screen.queryByTestId('wamCaseTasksTaskList')).toBeNull();
    expect(screen.queryByTestId('wamCaseTasksError')).toBeNull();
    expect(onError).not.toHaveBeenCalled();
  });

  test('a closed case is read-only: no add button, disabled checkboxes, no row actions', async () => {
    const apiService = service(async () => ({ tasks: [OPEN, DONE], counts: { open: 1, done: 1 }, limit: CASE_TASKS_MAX }));
    render(<CaseTasksTab caseId="case-1" apiService={apiService} readOnly onError={jest.fn()} />);
    await waitFor(() => expect(screen.getByTestId('wamCaseTasks')).toBeTruthy());
    expect(screen.queryByTestId('wamCaseTaskAdd')).toBeNull();
    expect(screen.queryByTestId(`wamCaseTaskRemove-${OPEN.id}`)).toBeNull();
    expect(screen.queryByTestId(`wamCaseTaskEdit-${OPEN.id}`)).toBeNull();
    expect((screen.getByTestId(`wamCaseTaskDone-${OPEN.id}`) as HTMLInputElement).disabled).toBe(true);
    expect(screen.getByTestId('wamCaseTasksCounts').textContent).toContain('read-only');
    fireEvent.click(screen.getByTestId(`wamCaseTaskDone-${OPEN.id}`));
    expect(apiService.updateCaseTask).not.toHaveBeenCalled();
  });

  test('a failed load shows an in-tab error with retry; empty state afterwards', async () => {
    let calls = 0;
    const apiService = service(async () => {
      calls += 1;
      if (calls === 1) throw Object.assign(new Error('Forbidden'), { response: { status: 403 } });
      return { tasks: [], counts: { open: 0, done: 0 }, limit: CASE_TASKS_MAX };
    });
    const onError = jest.fn();
    render(<CaseTasksTab caseId="case-1" apiService={apiService} onError={onError} />);
    await waitFor(() => expect(screen.getByTestId('wamCaseTasksError')).toBeTruthy());
    expect(screen.getByTestId('wamCaseTasksError').textContent).toContain("You do not have access to this case's tasks.");
    expect(screen.queryByTestId('wamCaseTasksEmpty')).toBeNull();
    expect((screen.getByTestId('wamCaseTaskAdd') as HTMLButtonElement).disabled).toBe(true);
    expect(onError).toHaveBeenCalledWith('Failed to load tasks');

    fireEvent.click(screen.getByTestId('wamCaseTasksRetry'));
    await waitFor(() => expect(screen.queryByTestId('wamCaseTasksError')).toBeNull());
    expect(screen.getByTestId('wamCaseTasksEmpty')).toBeTruthy();
    expect(screen.getByTestId('wamCaseTasksCounts').textContent).toBe('No tasks');
    expect((screen.getByTestId('wamCaseTaskAdd') as HTMLButtonElement).disabled).toBe(false);
  });

  test('a mutation failure is reported through onError and the list stays', async () => {
    const apiService = service(async () => ({ tasks: [OPEN], counts: { open: 1, done: 0 }, limit: CASE_TASKS_MAX }));
    apiService.updateCaseTask.mockRejectedValue(Object.assign(new Error('nope'), { body: { message: 'Case is closed' } }));
    const onError = jest.fn();
    render(<CaseTasksTab caseId="case-1" apiService={apiService} onError={onError} />);
    await waitFor(() => expect(screen.getByTestId(`wamCaseTaskDone-${OPEN.id}`)).toBeTruthy());
    fireEvent.click(screen.getByTestId(`wamCaseTaskDone-${OPEN.id}`));
    await waitFor(() => expect(onError).toHaveBeenCalledWith('Case is closed'));
    await waitFor(() => expect((screen.getByTestId(`wamCaseTaskDone-${OPEN.id}`) as HTMLInputElement).disabled).toBe(false));
    expect(screen.getByTestId(`wamCaseTaskTitle-${OPEN.id}`)).toBeTruthy();
  });

  test('a load that outlives the tab neither touches state nor raises a toast', async () => {
    let reject: (e: any) => void = () => undefined;
    const apiService = service(() => new Promise((_resolve, r) => { reject = r; }));
    const onError = jest.fn();
    const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => undefined);
    const { unmount } = render(<CaseTasksTab caseId="case-1" apiService={apiService} onError={onError} />);
    await waitFor(() => expect(apiService.fetchCaseTasks).toHaveBeenCalledTimes(1));
    unmount();
    reject(Object.assign(new Error('late'), { response: { status: 500 } }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(onError).not.toHaveBeenCalled();
    expect(errorSpy).not.toHaveBeenCalled();
    errorSpy.mockRestore();
  });
});
