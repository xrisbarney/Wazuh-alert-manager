import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  EuiBadge,
  EuiButton,
  EuiButtonEmpty,
  EuiButtonIcon,
  EuiCallOut,
  EuiCheckbox,
  EuiDatePicker,
  EuiFieldText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFormRow,
  EuiLoadingSpinner,
  EuiPanel,
  EuiSelect,
  EuiSpacer,
  EuiText,
  EuiToolTip,
} from '@elastic/eui';
import moment from 'moment';
import { CASE_TASKS_MAX, CASE_TASK_TITLE_MAX_LENGTH, CaseTask, CaseTaskCounts, TaskList } from '../../common';
import { AlertsApiService } from '../services/api';
import { formatAbsolute } from '../design';
import { AssigneePicker } from './assignee_picker';

/**
 * Case tasks (step 2.1): the checklist tab of the case flyout and the
 * "3/7 tasks" chip the case queue and the flyout header share. The chip is
 * hidden when a case has no tasks; the tab is read-only on a closed case.
 */

export function tasksChipLabel(counts?: CaseTaskCounts | null): string | null {
  const open = Number(counts?.open ?? 0);
  const done = Number(counts?.done ?? 0);
  const total = open + done;
  if (!Number.isFinite(total) || total <= 0) return null;
  return `${done}/${total} tasks`;
}

export const CaseTasksChip: React.FC<{ counts?: CaseTaskCounts | null; testSubj?: string }> = ({ counts, testSubj }) => {
  const label = tasksChipLabel(counts);
  if (!label) return null;
  const allDone = Number(counts?.open ?? 0) === 0;
  return (
    <EuiToolTip content={allDone ? 'Every task on this case is done' : `${counts?.open} task(s) still open`}>
      <EuiBadge
        color={allDone ? 'success' : 'hollow'}
        className={`wamCaseTasksChip${allDone ? ' wamCaseTasksChip--done' : ''}`}
        data-test-subj={testSubj || 'wamCaseTasksChip'}
      >
        {label}
      </EuiBadge>
    </EuiToolTip>
  );
};

interface Props {
  caseId: string;
  apiService: AlertsApiService;
  /** True when the case is closed: no add form, no toggles, no row actions. */
  readOnly?: boolean;
  onError: (message: string) => void;
  onToast?: (title: string, color: 'success' | 'danger' | 'primary', text?: string) => void;
  /** Called after every successful mutation with the fresh counts (for the header chip and queue). */
  onCountsChanged?: (counts: CaseTaskCounts) => void;
}

interface TaskForm {
  title: string;
  owner: string;
  dueAt: moment.Moment | null;
}

const EMPTY_FORM: TaskForm = { title: '', owner: '', dueAt: null };

function errorMessage(e: any, fallback: string): string {
  return e?.body?.message || e?.message || fallback;
}

function isOverdue(task: CaseTask, now: number): boolean {
  if (task.done || !task.due_at) return false;
  const due = Date.parse(task.due_at);
  return Number.isFinite(due) && due < now;
}

const TaskFormFields: React.FC<{
  form: TaskForm;
  onChange: (form: TaskForm) => void;
  busy: boolean;
  idPrefix: string;
  apiService: AlertsApiService;
}> = ({ form, onChange, busy, idPrefix, apiService }) => (
  <EuiFlexGroup gutterSize="s" responsive={false} wrap>
    <EuiFlexItem grow={3}>
      <EuiFormRow label="Task" display="rowCompressed">
        <EuiFieldText
          compressed
          value={form.title}
          maxLength={CASE_TASK_TITLE_MAX_LENGTH}
          placeholder="What needs doing?"
          onChange={(e) => onChange({ ...form, title: e.target.value })}
          disabled={busy}
          data-test-subj={`${idPrefix}Title`}
        />
      </EuiFormRow>
    </EuiFlexItem>
    <EuiFlexItem grow={2}>
      <EuiFormRow label="Owner" display="rowCompressed">
        <AssigneePicker
          apiService={apiService}
          value={form.owner || null}
          extraOptions={form.owner ? [form.owner] : []}
          placeholder="Optional"
          onChange={(owner) => onChange({ ...form, owner: owner ?? '' })}
          isDisabled={busy}
          ariaLabel="Owner"
          testSubj={`${idPrefix}Owner`}
        />
      </EuiFormRow>
    </EuiFlexItem>
    <EuiFlexItem grow={2}>
      <EuiFormRow label="Due" display="rowCompressed">
        <EuiDatePicker
          compressed
          selected={form.dueAt}
          onChange={(date: moment.Moment | null) => onChange({ ...form, dueAt: date })}
          onClear={() => onChange({ ...form, dueAt: null })}
          placeholder="Optional"
          showTimeSelect
          disabled={busy}
          data-test-subj={`${idPrefix}Due`}
        />
      </EuiFormRow>
    </EuiFlexItem>
  </EuiFlexGroup>
);

export const CaseTasksTab: React.FC<Props> = ({ caseId, apiService, readOnly = false, onError, onToast, onCountsChanged }) => {
  const [tasks, setTasks] = useState<CaseTask[]>([]);
  const [counts, setCounts] = useState<CaseTaskCounts>({ open: 0, done: 0 });
  const [limit, setLimit] = useState(CASE_TASKS_MAX);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [addForm, setAddForm] = useState<TaskForm>(EMPTY_FORM);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editForm, setEditForm] = useState<TaskForm>(EMPTY_FORM);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // Task lists (step 2.2): enabled templates the analyst may apply to an open
  // case from this tab. The list is loaded once; a failure or an empty list
  // simply hides the control, it never blocks the checklist.
  const [taskLists, setTaskLists] = useState<TaskList[]>([]);
  const [taskListId, setTaskListId] = useState('');
  const [applying, setApplying] = useState(false);

  // The flyout mounts this tab only while it is selected, so a fetch may
  // outlive the component: every result is checked against the generation
  // that started it (bumped on unmount and on each new load) before it
  // touches state or raises a toast.
  const loadGeneration = useRef(0);
  const onErrorRef = useRef(onError);
  onErrorRef.current = onError;

  const load = useCallback(async () => {
    const generation = ++loadGeneration.current;
    try {
      setLoading(true);
      const res = await apiService.fetchCaseTasks(caseId);
      if (generation !== loadGeneration.current) return;
      setTasks(res?.tasks || []);
      setCounts(res?.counts || { open: 0, done: 0 });
      setLimit(res?.limit || CASE_TASKS_MAX);
      setLoadError(null);
    } catch (e: any) {
      if (generation !== loadGeneration.current) return;
      const status = e?.response?.status ?? e?.body?.statusCode;
      const message = status === 403
        ? "You do not have access to this case's tasks."
        : status === 404
        ? 'Case not found.'
        : errorMessage(e, 'Failed to load tasks');
      setLoadError(message);
      setTasks([]);
      onErrorRef.current('Failed to load tasks');
    } finally {
      if (generation === loadGeneration.current) setLoading(false);
    }
  }, [caseId, apiService]);

  useEffect(() => {
    load();
    return () => {
      loadGeneration.current += 1;
    };
  }, [load]);

  useEffect(() => {
    if (readOnly || typeof apiService.fetchTaskLists !== 'function') return;
    let active = true;
    apiService
      .fetchTaskLists(true)
      .then((response) => {
        if (active) setTaskLists((response?.taskLists || []).filter((item) => item.enabled));
      })
      .catch(() => {
        if (active) setTaskLists([]);
      });
    return () => {
      active = false;
    };
  }, [apiService, readOnly]);

  const applyTaskList = async () => {
    const taskList = taskLists.find((item) => item.id === taskListId);
    if (!taskList) return;
    try {
      setApplying(true);
      const res = await apiService.applyTaskListToCase(caseId, taskList.id);
      if (res?.applied) {
        await load();
        applyCounts(res.counts);
        onToast?.('Task list applied', 'success', `${taskList.name}: ${res.tasks_added} task(s) added`);
      } else {
        onToast?.('Task list already applied', 'primary', `${taskList.name} was applied to this case before; nothing was added.`);
      }
      setTaskListId('');
    } catch (e: any) {
      onError(errorMessage(e, 'Failed to apply the task list'));
    } finally {
      setApplying(false);
    }
  };

  const applyCounts = (next: CaseTaskCounts | undefined) => {
    if (!next) return;
    setCounts(next);
    onCountsChanged?.(next);
  };

  const total = counts.open + counts.done;
  const full = total >= limit;

  const add = async () => {
    const title = addForm.title.trim();
    if (!title) return;
    try {
      setBusy(true);
      const res = await apiService.addCaseTask(caseId, {
        title,
        owner: addForm.owner.trim() || null,
        dueAt: addForm.dueAt ? addForm.dueAt.toISOString() : null,
      });
      setAddForm(EMPTY_FORM);
      setAdding(false);
      await load();
      applyCounts(res?.counts);
      onToast?.('Task added', 'success', title);
    } catch (e: any) {
      onError(errorMessage(e, 'Failed to add the task'));
    } finally {
      setBusy(false);
    }
  };

  const toggleDone = async (task: CaseTask) => {
    if (readOnly) return;
    try {
      setBusyId(task.id);
      const res = await apiService.updateCaseTask(caseId, task.id, { done: !task.done });
      await load();
      applyCounts(res?.counts);
    } catch (e: any) {
      onError(errorMessage(e, 'Failed to update the task'));
    } finally {
      setBusyId(null);
    }
  };

  const startEdit = (task: CaseTask) => {
    setEditingId(task.id);
    setEditForm({ title: task.title, owner: task.owner || '', dueAt: task.due_at ? moment(task.due_at) : null });
  };

  const saveEdit = async (task: CaseTask) => {
    const title = editForm.title.trim();
    if (!title) return;
    try {
      setBusyId(task.id);
      const res = await apiService.updateCaseTask(caseId, task.id, {
        title,
        owner: editForm.owner.trim() || null,
        dueAt: editForm.dueAt ? editForm.dueAt.toISOString() : null,
      });
      setEditingId(null);
      await load();
      applyCounts(res?.counts);
    } catch (e: any) {
      onError(errorMessage(e, 'Failed to update the task'));
    } finally {
      setBusyId(null);
    }
  };

  const remove = async (task: CaseTask) => {
    try {
      setBusyId(task.id);
      const res = await apiService.deleteCaseTask(caseId, task.id);
      await load();
      applyCounts(res?.counts);
      onToast?.('Task removed', 'success', task.title);
    } catch (e: any) {
      onError(errorMessage(e, 'Failed to remove the task'));
    } finally {
      setBusyId(null);
    }
  };

  if (loading && tasks.length === 0 && !loadError) return <EuiLoadingSpinner size="m" />;

  const now = Date.now();

  return (
    <div className="wamCaseTasks" data-test-subj="wamCaseTasks">
      <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" responsive={false}>
        <EuiFlexItem grow={false}>
          <EuiText size="s" color="subdued" data-test-subj="wamCaseTasksCounts">
            {total === 0 ? 'No tasks' : `${counts.done}/${total} done`}
            {readOnly ? ' · case is closed, tasks are read-only' : ''}
          </EuiText>
        </EuiFlexItem>
        {!readOnly && (
          <EuiFlexItem grow={false}>
            <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false} className="wamCaseTasksActions">
              {taskLists.length > 0 && (
                <>
                  <EuiFlexItem grow={false}>
                    <EuiSelect
                      compressed
                      aria-label="Task list to apply"
                      options={[{ value: '', text: 'Apply task list…' }, ...taskLists.map((item) => ({ value: item.id, text: item.name }))]}
                      value={taskListId}
                      onChange={(e) => setTaskListId(e.target.value)}
                      disabled={applying || busy || loadError !== null}
                      data-test-subj="wamCaseTasksTaskList"
                    />
                  </EuiFlexItem>
                  <EuiFlexItem grow={false}>
                    <EuiButton
                      size="s"
                      onClick={applyTaskList}
                      isLoading={applying}
                      isDisabled={!taskListId || full || busy || loadError !== null}
                      data-test-subj="wamCaseTasksTaskListApply"
                    >
                      Apply
                    </EuiButton>
                  </EuiFlexItem>
                </>
              )}
              <EuiFlexItem grow={false}>
                <EuiButtonEmpty
                  size="s"
                  iconType="plusInCircle"
                  onClick={() => setAdding((v) => !v)}
                  isDisabled={full || busy || loadError !== null}
                  data-test-subj="wamCaseTaskAdd"
                >
                  Add task
                </EuiButtonEmpty>
              </EuiFlexItem>
            </EuiFlexGroup>
          </EuiFlexItem>
        )}
      </EuiFlexGroup>

      {loadError && (
        <>
          <EuiSpacer size="s" />
          <EuiCallOut color="danger" size="s" title="Tasks could not be loaded" data-test-subj="wamCaseTasksError">
            <p>{loadError}</p>
            <EuiButton size="s" color="danger" onClick={load} data-test-subj="wamCaseTasksRetry">
              Retry
            </EuiButton>
          </EuiCallOut>
        </>
      )}

      {!readOnly && adding && !loadError && (
        <>
          <EuiSpacer size="s" />
          <EuiPanel paddingSize="s" className="wamCaseTaskForm" data-test-subj="wamCaseTaskForm">
            <TaskFormFields form={addForm} onChange={setAddForm} busy={busy} idPrefix="wamCaseTaskNew" apiService={apiService} />
            <EuiSpacer size="s" />
            <EuiFlexGroup gutterSize="s" responsive={false} justifyContent="flexEnd">
              <EuiFlexItem grow={false}>
                <EuiButtonEmpty size="s" onClick={() => { setAdding(false); setAddForm(EMPTY_FORM); }} isDisabled={busy}>
                  Cancel
                </EuiButtonEmpty>
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiButton size="s" fill onClick={add} isLoading={busy} isDisabled={!addForm.title.trim() || full} data-test-subj="wamCaseTaskSave">
                  Add
                </EuiButton>
              </EuiFlexItem>
            </EuiFlexGroup>
            {full && (
              <EuiText size="xs" color="subdued">
                This case already has {limit} tasks; remove one first.
              </EuiText>
            )}
          </EuiPanel>
        </>
      )}

      <EuiSpacer size="s" />

      {!loadError && tasks.length === 0 && (
        <EuiText size="s" color="subdued" data-test-subj="wamCaseTasksEmpty">
          No tasks yet. {readOnly ? '' : 'Add the steps this case needs so the team can see what is left.'}
        </EuiText>
      )}

      {tasks.map((task) => {
        const rowBusy = busyId === task.id;
        const overdue = isOverdue(task, now);
        const editing = editingId === task.id;
        return (
          <div
            key={task.id}
            className={`wamCaseTaskRow${task.done ? ' wamCaseTask--done' : ''}${overdue ? ' wamCaseTask--overdue' : ''}`}
            data-test-subj={`wamCaseTaskRow-${task.id}`}
          >
            {editing ? (
              <EuiPanel paddingSize="s" className="wamCaseTaskForm" data-test-subj={`wamCaseTaskEditForm-${task.id}`}>
                <TaskFormFields form={editForm} onChange={setEditForm} busy={rowBusy} idPrefix={`wamCaseTaskEdit-${task.id}`} apiService={apiService} />
                <EuiSpacer size="s" />
                <EuiFlexGroup gutterSize="s" responsive={false} justifyContent="flexEnd">
                  <EuiFlexItem grow={false}>
                    <EuiButtonEmpty size="s" onClick={() => setEditingId(null)} isDisabled={rowBusy}>
                      Cancel
                    </EuiButtonEmpty>
                  </EuiFlexItem>
                  <EuiFlexItem grow={false}>
                    <EuiButton size="s" fill onClick={() => saveEdit(task)} isLoading={rowBusy} isDisabled={!editForm.title.trim()} data-test-subj={`wamCaseTaskEditSave-${task.id}`}>
                      Save
                    </EuiButton>
                  </EuiFlexItem>
                </EuiFlexGroup>
              </EuiPanel>
            ) : (
              <EuiFlexGroup gutterSize="s" alignItems="flexStart" responsive={false}>
                <EuiFlexItem grow={false}>
                  <EuiCheckbox
                    id={`wamCaseTask-${task.id}`}
                    checked={task.done}
                    disabled={readOnly || rowBusy}
                    onChange={() => toggleDone(task)}
                    aria-label={task.done ? `Reopen ${task.title}` : `Mark ${task.title} done`}
                    data-test-subj={`wamCaseTaskDone-${task.id}`}
                  />
                </EuiFlexItem>
                <EuiFlexItem>
                  <EuiText size="s" className="wamCaseTask__title" data-test-subj={`wamCaseTaskTitle-${task.id}`}>
                    {task.title}
                  </EuiText>
                  <div className="wamCaseTask__meta">
                    {task.owner && (
                      <EuiBadge color="hollow" data-test-subj={`wamCaseTaskOwner-${task.id}`}>{task.owner}</EuiBadge>
                    )}
                    {task.due_at && (
                      <span className="wamCaseTask__due" data-test-subj={`wamCaseTaskDue-${task.id}`}>
                        {overdue ? 'Overdue ' : 'Due '}
                        {formatAbsolute(task.due_at)}
                      </span>
                    )}
                    {task.done && (
                      <span className="wamCaseTask__doneBy" data-test-subj={`wamCaseTaskDoneBy-${task.id}`}>
                        Done by {task.done_by || 'unknown'} {task.done_at ? formatAbsolute(task.done_at) : ''}
                      </span>
                    )}
                    <span className="wamCaseTask__created">
                      Added by {task.created_by || 'unknown'} {task.created_at ? formatAbsolute(task.created_at) : ''}
                    </span>
                  </div>
                </EuiFlexItem>
                {!readOnly && (
                  <EuiFlexItem grow={false}>
                    <EuiFlexGroup gutterSize="none" responsive={false}>
                      <EuiFlexItem grow={false}>
                        <EuiToolTip content="Edit task">
                          <EuiButtonIcon
                            iconType="pencil"
                            aria-label={`Edit ${task.title}`}
                            onClick={() => startEdit(task)}
                            isDisabled={rowBusy}
                            data-test-subj={`wamCaseTaskEdit-${task.id}`}
                          />
                        </EuiToolTip>
                      </EuiFlexItem>
                      <EuiFlexItem grow={false}>
                        <EuiToolTip content="Remove task">
                          <EuiButtonIcon
                            iconType="trash"
                            color="danger"
                            aria-label={`Remove ${task.title}`}
                            onClick={() => remove(task)}
                            isDisabled={rowBusy}
                            data-test-subj={`wamCaseTaskRemove-${task.id}`}
                          />
                        </EuiToolTip>
                      </EuiFlexItem>
                    </EuiFlexGroup>
                  </EuiFlexItem>
                )}
              </EuiFlexGroup>
            )}
          </div>
        );
      })}
    </div>
  );
};
