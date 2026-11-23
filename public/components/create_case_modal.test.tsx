/**
 * @jest-environment jsdom
 */
import React from 'react';
import { configure, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { CreateCaseModal, taskListHelpText } from './create_case_modal';

configure({ testIdAttribute: 'data-test-subj' });

jest.mock('./assignee_picker', () => ({ AssigneePicker: () => <div data-test-subj="assigneePicker" /> }));

const TASK_LISTS = [
  { id: 'pb-1', name: 'Phishing triage', enabled: true, tasks: [{ title: 'a', order: 0 }, { title: 'b', order: 1 }] },
  { id: 'pb-2', name: 'Single', enabled: true, tasks: [{ title: 'a', order: 0 }] },
];

function service(taskLists: any[] | Error) {
  return {
    fetchTaskLists: jest.fn(async () => {
      if (taskLists instanceof Error) throw taskLists;
      return { taskLists, limit: 200 };
    }),
    fetchUsers: jest.fn(async () => []),
  } as any;
}

describe('taskListHelpText', () => {
  test('describes each load state and the chosen task list', () => {
    expect(taskListHelpText({ state: 'loading' }, null)).toBe('Loading task lists');
    expect(taskListHelpText({ state: 'error', message: 'boom' }, null)).toContain('boom');
    expect(taskListHelpText({ state: 'ready', taskLists: [] }, null)).toBe('No task lists defined');
    expect(taskListHelpText({ state: 'ready', taskLists: TASK_LISTS as any }, null)).toBe('Its tasks are added to the new case.');
    expect(taskListHelpText({ state: 'ready', taskLists: TASK_LISTS as any }, 'pb-1')).toBe('Adds 2 tasks to the new case.');
    expect(taskListHelpText({ state: 'ready', taskLists: TASK_LISTS as any }, 'pb-2')).toBe('Adds 1 task to the new case.');
  });
});

describe('CreateCaseModal', () => {
  test('loads enabled task lists on open and passes the chosen id through onCreate', async () => {
    const api = service(TASK_LISTS);
    const onCreate = jest.fn();
    render(<CreateCaseModal apiService={api} alertCount={2} busy={false} onClose={jest.fn()} onCreate={onCreate} />);
    await waitFor(() => expect((screen.getByTestId('wamCreateCaseTaskList') as HTMLSelectElement).disabled).toBe(false));
    expect(api.fetchTaskLists).toHaveBeenCalledWith(true);
    const select = screen.getByTestId('wamCreateCaseTaskList') as HTMLSelectElement;
    expect(Array.from(select.options).map((o) => o.textContent)).toEqual(['No task list', 'Phishing triage (2 tasks)', 'Single (1 task)']);
    fireEvent.change(screen.getByTestId('wamCreateCaseTitle'), { target: { value: ' Mail incident ' } });
    fireEvent.change(select, { target: { value: 'pb-1' } });
    fireEvent.click(screen.getByTestId('wamCreateCaseSubmit'));
    expect(onCreate).toHaveBeenCalledWith({ title: 'Mail incident', description: '', severity: 'medium', assignedTo: null, taskListId: 'pb-1' });
  });

  test('shows the empty state when no task list is defined and sends taskListId null', async () => {
    const onCreate = jest.fn();
    render(<CreateCaseModal apiService={service([])} alertCount={1} busy={false} onClose={jest.fn()} onCreate={onCreate} />);
    await waitFor(() => expect(screen.getAllByText('No task lists defined').length).toBeGreaterThanOrEqual(1));
    const select = screen.getByTestId('wamCreateCaseTaskList') as HTMLSelectElement;
    expect(select.disabled).toBe(true);
    fireEvent.change(screen.getByTestId('wamCreateCaseTitle'), { target: { value: 'T' } });
    fireEvent.click(screen.getByTestId('wamCreateCaseSubmit'));
    expect(onCreate).toHaveBeenCalledWith(expect.objectContaining({ taskListId: null }));
  });

  test('a task list load failure only disables the picker; the case can still be created', async () => {
    const onCreate = jest.fn();
    render(<CreateCaseModal apiService={service(new Error('nope'))} alertCount={1} busy={false} onClose={jest.fn()} onCreate={onCreate} />);
    await waitFor(() => expect(screen.getByText(/could not be loaded \(nope\)/)).toBeTruthy());
    expect((screen.getByTestId('wamCreateCaseTaskList') as HTMLSelectElement).disabled).toBe(true);
    fireEvent.change(screen.getByTestId('wamCreateCaseTitle'), { target: { value: 'T' } });
    fireEvent.click(screen.getByTestId('wamCreateCaseSubmit'));
    expect(onCreate).toHaveBeenCalledWith(expect.objectContaining({ title: 'T', taskListId: null }));
  });
});
