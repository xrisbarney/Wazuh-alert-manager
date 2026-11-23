import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  EuiBadge,
  EuiBasicTable,
  EuiButton,
  EuiButtonEmpty,
  EuiButtonIcon,
  EuiCallOut,
  EuiConfirmModal,
  EuiFieldNumber,
  EuiFieldText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiForm,
  EuiFormRow,
  EuiLoadingSpinner,
  EuiPanel,
  EuiSpacer,
  EuiSwitch,
  EuiText,
  EuiTextArea,
  EuiTitle,
} from '@elastic/eui';
import {
  CASE_TASKS_MAX,
  CASE_TASK_OWNER_MAX_LENGTH,
  CASE_TASK_TITLE_MAX_LENGTH,
  TASK_LISTS_MAX,
  TASK_LIST_DESCRIPTION_MAX_LENGTH,
  TASK_LIST_DUE_OFFSET_MAX_MINUTES,
  TASK_LIST_DUE_OFFSET_MIN_MINUTES,
  TASK_LIST_NAME_MAX_LENGTH,
  TASK_LIST_TASKS_MAX,
  TaskList,
  TaskListInput,
} from '../../common';
import { AlertsApiService } from '../services/api';
import { formatDuration, formatRelative } from '../design';
import { SettingsPageHeader } from './settings_page';
import { AssigneePicker } from './assignee_picker';

/**
 * Settings > TaskLists (step 2.2): the reusable task templates a case can
 * apply (Create case modal, the case Tasks tab, automation "Apply task list").
 * Reads are open to every user; create / edit / delete need the plugin
 * administrator role, exactly like the other settings tabs.
 */

interface Props {
  apiService: AlertsApiService;
  onToast: (title: string, color: 'success' | 'danger' | 'primary', text?: string) => void;
}

const ADMIN_HELP =
  'Your effective Wazuh authorization does not include all_access. OpenSearch Security roles, not SSO/LDAP group names, control task list administration.';

export interface TaskDraft {
  key: string;
  title: string;
  owner: string;
  /** What the user typed; empty = no due date. */
  dueOffsetMinutes: string;
}

export interface TaskListDraft {
  /** null while creating. */
  id: string | null;
  name: string;
  description: string;
  enabled: boolean;
  tasks: TaskDraft[];
}

let nextKey = 0;
const taskKey = () => `task-${Date.now()}-${++nextKey}`;

export const emptyTaskDraft = (): TaskDraft => ({ key: taskKey(), title: '', owner: '', dueOffsetMinutes: '' });

export const emptyDraft = (): TaskListDraft => ({ id: null, name: '', description: '', enabled: true, tasks: [emptyTaskDraft()] });

export function toDraft(taskList: TaskList): TaskListDraft {
  return {
    id: taskList.id,
    name: taskList.name,
    description: taskList.description || '',
    enabled: taskList.enabled,
    tasks: [...taskList.tasks]
      .sort((a, b) => a.order - b.order)
      .map((task) => ({
        key: taskKey(),
        title: task.title,
        owner: task.owner || '',
        dueOffsetMinutes: task.dueOffsetMinutes ? String(task.dueOffsetMinutes) : '',
      })),
  };
}

/** Human form of a due offset ("45 min", "4h", "3d") or "-" when unset. */
export function formatOffset(minutes: number | null | undefined): string {
  if (!minutes) return '-';
  return minutes < 60 ? `${minutes} min` : formatDuration(minutes);
}

/** Client-side mirror of the server validation: the payload, or the reasons it cannot be saved. */
export function draftToInput(draft: TaskListDraft): { input: TaskListInput | null; errors: string[] } {
  const errors: string[] = [];
  const name = draft.name.trim();
  if (!name) errors.push('A task list needs a name.');
  if (name.length > TASK_LIST_NAME_MAX_LENGTH) errors.push(`The name must be at most ${TASK_LIST_NAME_MAX_LENGTH} characters.`);
  const description = draft.description.trim();
  if (description.length > TASK_LIST_DESCRIPTION_MAX_LENGTH) {
    errors.push(`The description must be at most ${TASK_LIST_DESCRIPTION_MAX_LENGTH} characters.`);
  }
  const tasks = draft.tasks.filter((task) => task.title.trim() || task.owner.trim() || task.dueOffsetMinutes.trim());
  if (!tasks.length) errors.push('A task list needs at least one task.');
  if (tasks.length > TASK_LIST_TASKS_MAX) errors.push(`A task list can hold at most ${TASK_LIST_TASKS_MAX} tasks.`);
  const input: TaskListInput = { name, description: description || undefined, enabled: draft.enabled, tasks: [] };
  tasks.forEach((task, index) => {
    const position = index + 1;
    const title = task.title.trim();
    if (!title) errors.push(`Task ${position} needs a title.`);
    if (title.length > CASE_TASK_TITLE_MAX_LENGTH) errors.push(`Task ${position}: the title must be at most ${CASE_TASK_TITLE_MAX_LENGTH} characters.`);
    const owner = task.owner.trim();
    if (owner.length > CASE_TASK_OWNER_MAX_LENGTH) errors.push(`Task ${position}: the owner must be at most ${CASE_TASK_OWNER_MAX_LENGTH} characters.`);
    const offsetText = task.dueOffsetMinutes.trim();
    let dueOffsetMinutes: number | null = null;
    if (offsetText) {
      const value = Number(offsetText);
      if (!/^\d+$/.test(offsetText) || value < TASK_LIST_DUE_OFFSET_MIN_MINUTES || value > TASK_LIST_DUE_OFFSET_MAX_MINUTES) {
        errors.push(`Task ${position}: the due offset must be ${TASK_LIST_DUE_OFFSET_MIN_MINUTES}-${TASK_LIST_DUE_OFFSET_MAX_MINUTES} whole minutes.`);
      } else {
        dueOffsetMinutes = value;
      }
    }
    input.tasks.push({ title, owner: owner || null, dueOffsetMinutes });
  });
  return { input: errors.length ? null : input, errors };
}

function errorMessage(error: any): string {
  return error?.body?.message || error?.message || 'Request failed';
}

export const TaskListsView: React.FC<Props> = ({ apiService, onToast }) => {
  const [capabilitiesLoaded, setCapabilitiesLoaded] = useState(false);
  const [canAdminister, setCanAdminister] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [taskLists, setTaskLists] = useState<TaskList[]>([]);
  const [editing, setEditing] = useState<TaskListDraft | null>(null);
  const [formErrors, setFormErrors] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const [pendingDelete, setPendingDelete] = useState<TaskList | null>(null);
  const [deleting, setDeleting] = useState(false);
  // Generation guard: a load that outlives the tab never touches state.
  const generation = useRef(0);

  const load = useCallback(async () => {
    const mine = ++generation.current;
    setLoading(true);
    setError(null);
    try {
      const response = await apiService.fetchTaskLists();
      if (mine !== generation.current) return;
      setTaskLists(response.taskLists);
    } catch (e: any) {
      if (mine !== generation.current) return;
      setError(errorMessage(e));
    } finally {
      if (mine === generation.current) setLoading(false);
    }
  }, [apiService]);

  useEffect(() => {
    load();
    let active = true;
    apiService
      .fetchSystemCapabilities()
      .then((capabilities: any) => {
        if (!active) return;
        setCanAdminister(Boolean(capabilities?.isPluginAdmin));
      })
      .catch(() => {
        if (active) setCanAdminister(false);
      })
      .finally(() => {
        if (active) setCapabilitiesLoaded(true);
      });
    return () => {
      active = false;
      generation.current += 1;
    };
  }, [apiService, load]);

  const startCreate = () => {
    setFormErrors([]);
    setEditing(emptyDraft());
  };
  const startEdit = (taskList: TaskList) => {
    setFormErrors([]);
    setEditing(toDraft(taskList));
  };
  const cancelEdit = () => {
    setEditing(null);
    setFormErrors([]);
  };

  const updateDraft = (patch: Partial<TaskListDraft>) => setEditing((current) => (current ? { ...current, ...patch } : current));
  const updateTask = (key: string, patch: Partial<TaskDraft>) =>
    setEditing((current) =>
      current ? { ...current, tasks: current.tasks.map((task) => (task.key === key ? { ...task, ...patch } : task)) } : current
    );
  const removeTask = (key: string) =>
    setEditing((current) => (current ? { ...current, tasks: current.tasks.filter((task) => task.key !== key) } : current));
  const moveTask = (key: string, delta: -1 | 1) =>
    setEditing((current) => {
      if (!current) return current;
      const index = current.tasks.findIndex((task) => task.key === key);
      const target = index + delta;
      if (index < 0 || target < 0 || target >= current.tasks.length) return current;
      const tasks = [...current.tasks];
      const [moved] = tasks.splice(index, 1);
      tasks.splice(target, 0, moved);
      return { ...current, tasks };
    });
  const addTask = () =>
    setEditing((current) =>
      current && current.tasks.length < TASK_LIST_TASKS_MAX ? { ...current, tasks: [...current.tasks, emptyTaskDraft()] } : current
    );

  const save = async () => {
    if (!editing) return;
    const { input, errors } = draftToInput(editing);
    setFormErrors(errors);
    if (!input) return;
    setSaving(true);
    try {
      const response = editing.id
        ? await apiService.updateTaskList(editing.id, input)
        : await apiService.createTaskList(input);
      onToast(editing.id ? 'Task list saved' : 'Task list created', 'success', response.taskList.name);
      setEditing(null);
      setFormErrors([]);
      await load();
    } catch (e: any) {
      onToast('Task list could not be saved', 'danger', errorMessage(e));
    } finally {
      setSaving(false);
    }
  };

  const confirmDelete = async () => {
    if (!pendingDelete) return;
    setDeleting(true);
    try {
      await apiService.deleteTaskList(pendingDelete.id);
      onToast('Task list deleted', 'success', pendingDelete.name);
      if (editing?.id === pendingDelete.id) cancelEdit();
      setPendingDelete(null);
      await load();
    } catch (e: any) {
      onToast('Task list could not be deleted', 'danger', errorMessage(e));
    } finally {
      setDeleting(false);
    }
  };

  const toggleEnabled = async (taskList: TaskList, enabled: boolean) => {
    try {
      await apiService.updateTaskList(taskList.id, {
        name: taskList.name,
        description: taskList.description || undefined,
        enabled,
        tasks: taskList.tasks.map((task) => ({ title: task.title, owner: task.owner ?? null, dueOffsetMinutes: task.dueOffsetMinutes ?? null })),
      });
      onToast(enabled ? 'Task list enabled' : 'Task list disabled', 'success', taskList.name);
      await load();
    } catch (e: any) {
      onToast('Task list could not be updated', 'danger', errorMessage(e));
    }
  };

  const columns: any[] = [
    {
      field: 'name',
      name: 'Name',
      render: (name: string, taskList: TaskList) => (
        <div>
          <strong data-test-subj={`wamTaskListName-${taskList.id}`}>{name}</strong>
          {taskList.description ? (
            <EuiText size="xs" color="subdued" className="wamTaskListDescription">
              {taskList.description}
            </EuiText>
          ) : null}
        </div>
      ),
    },
    {
      field: 'tasks',
      name: 'Tasks',
      width: '90px',
      render: (tasks: TaskList['tasks'], taskList: TaskList) => (
        <span data-test-subj={`wamTaskListTasks-${taskList.id}`}>{tasks.length}</span>
      ),
    },
    {
      field: 'enabled',
      name: 'Enabled',
      width: '120px',
      render: (enabled: boolean, taskList: TaskList) =>
        canAdminister ? (
          <EuiSwitch
            compressed
            showLabel={false}
            label={enabled ? 'Enabled' : 'Disabled'}
            checked={enabled}
            data-test-subj={`wamTaskListEnabled-${taskList.id}`}
            onChange={(event) => toggleEnabled(taskList, event.target.checked)}
          />
        ) : (
          <EuiBadge color={enabled ? 'success' : 'hollow'} data-test-subj={`wamTaskListEnabled-${taskList.id}`}>
            {enabled ? 'Enabled' : 'Disabled'}
          </EuiBadge>
        ),
    },
    {
      field: 'updated_at',
      name: 'Updated',
      width: '200px',
      render: (value: string, taskList: TaskList) => (
        <EuiText size="xs" color="subdued">
          {value ? formatRelative(value) : '-'}
          {taskList.updated_by ? ` by ${taskList.updated_by}` : ''}
        </EuiText>
      ),
    },
    ...(canAdminister
      ? [
          {
            name: '',
            width: '90px',
            render: (taskList: TaskList) => (
              <EuiFlexGroup gutterSize="xs" responsive={false} justifyContent="flexEnd">
                <EuiFlexItem grow={false}>
                  <EuiButtonIcon
                    iconType="pencil"
                    aria-label={`Edit ${taskList.name}`}
                    data-test-subj={`wamTaskListEdit-${taskList.id}`}
                    onClick={() => startEdit(taskList)}
                  />
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiButtonIcon
                    iconType="trash"
                    color="danger"
                    aria-label={`Delete ${taskList.name}`}
                    data-test-subj={`wamTaskListDelete-${taskList.id}`}
                    onClick={() => setPendingDelete(taskList)}
                  />
                </EuiFlexItem>
              </EuiFlexGroup>
            ),
          },
        ]
      : []),
  ];

  const editor = editing && (
    <EuiPanel paddingSize="m" hasBorder hasShadow={false} className="wamTaskListEditor" data-test-subj="wamTaskListEditor">
      <EuiTitle size="xs">
        <h3>{editing.id ? 'Edit task list' : 'New task list'}</h3>
      </EuiTitle>
      <EuiSpacer size="s" />
      {formErrors.length ? (
        <>
          <EuiCallOut color="danger" size="s" title="The task list cannot be saved yet" data-test-subj="wamTaskListFormErrors">
            <ul>
              {formErrors.map((message) => (
                <li key={message}>{message}</li>
              ))}
            </ul>
          </EuiCallOut>
          <EuiSpacer size="s" />
        </>
      ) : null}
      <EuiForm component="form" onSubmit={(event) => { event.preventDefault(); save(); }}>
        <EuiFlexGroup gutterSize="m">
          <EuiFlexItem>
            <EuiFormRow label="Name" fullWidth helpText={`Unique, up to ${TASK_LIST_NAME_MAX_LENGTH} characters.`}>
              <EuiFieldText
                fullWidth
                value={editing.name}
                maxLength={TASK_LIST_NAME_MAX_LENGTH}
                data-test-subj="wamTaskListName"
                onChange={(event) => updateDraft({ name: event.target.value })}
                autoFocus
              />
            </EuiFormRow>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiFormRow fullWidth label="Status" hasChildLabel={false}>
              <EuiSwitch
                label={editing.enabled ? 'Enabled' : 'Disabled'}
                checked={editing.enabled}
                data-test-subj="wamTaskListEnabled"
                onChange={(event) => updateDraft({ enabled: event.target.checked })}
              />
            </EuiFormRow>
          </EuiFlexItem>
        </EuiFlexGroup>
        <EuiFormRow label="Description" fullWidth>
          <EuiTextArea
            fullWidth
            rows={2}
            value={editing.description}
            maxLength={TASK_LIST_DESCRIPTION_MAX_LENGTH}
            data-test-subj="wamTaskListDescription"
            onChange={(event) => updateDraft({ description: event.target.value })}
          />
        </EuiFormRow>
        <EuiSpacer size="m" />
        <EuiTitle size="xxs">
          <h4>Tasks</h4>
        </EuiTitle>
        <EuiText size="xs" color="subdued">
          <p>
            Added to the case in this order. A due offset is counted from the moment the task list is applied; a case can
            hold at most {CASE_TASKS_MAX} tasks.
          </p>
        </EuiText>
        <div className="wamTaskListTasks" data-test-subj="wamTaskListTaskList">
          {editing.tasks.map((task, index) => (
            <EuiFlexGroup key={task.key} gutterSize="s" alignItems="center" responsive={false} className="wamTaskListTaskRow" data-test-subj={`wamTaskListTaskRow-${index}`}>
              <EuiFlexItem grow={false}>
                <span className="wamTaskListTaskRow__position">{index + 1}.</span>
              </EuiFlexItem>
              <EuiFlexItem grow={3}>
                <EuiFieldText
                  compressed
                  fullWidth
                  placeholder="Task title"
                  value={task.title}
                  maxLength={CASE_TASK_TITLE_MAX_LENGTH}
                  aria-label={`Task ${index + 1} title`}
                  data-test-subj={`wamTaskListTaskTitle-${index}`}
                  onChange={(event) => updateTask(task.key, { title: event.target.value })}
                />
              </EuiFlexItem>
              <EuiFlexItem grow={2}>
                <AssigneePicker
                  apiService={apiService}
                  fullWidth
                  placeholder="Owner (optional)"
                  value={task.owner || null}
                  extraOptions={task.owner ? [task.owner] : []}
                  ariaLabel={`Task ${index + 1} owner`}
                  testSubj={`wamTaskListTaskOwner-${index}`}
                  onChange={(owner) => updateTask(task.key, { owner: owner ?? '' })}
                />
              </EuiFlexItem>
              <EuiFlexItem grow={false} className="wamTaskListTaskRow__due">
                <EuiFieldNumber fullWidth
                  compressed
                  placeholder="Due in (min)"
                  min={TASK_LIST_DUE_OFFSET_MIN_MINUTES}
                  max={TASK_LIST_DUE_OFFSET_MAX_MINUTES}
                  value={task.dueOffsetMinutes}
                  aria-label={`Task ${index + 1} due offset in minutes`}
                  data-test-subj={`wamTaskListTaskDue-${index}`}
                  onChange={(event) => updateTask(task.key, { dueOffsetMinutes: event.target.value })}
                />
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiButtonIcon iconType="sortUp" aria-label="Move up" isDisabled={index === 0} onClick={() => moveTask(task.key, -1)} />
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiButtonIcon iconType="sortDown" aria-label="Move down" isDisabled={index === editing.tasks.length - 1} onClick={() => moveTask(task.key, 1)} />
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiButtonIcon
                  iconType="cross"
                  color="danger"
                  aria-label="Remove task"
                  data-test-subj={`wamTaskListTaskRemove-${index}`}
                  isDisabled={editing.tasks.length === 1}
                  onClick={() => removeTask(task.key)}
                />
              </EuiFlexItem>
            </EuiFlexGroup>
          ))}
        </div>
        <EuiSpacer size="s" />
        <EuiButtonEmpty
          size="s"
          iconType="plusInCircle"
          data-test-subj="wamTaskListTaskAdd"
          isDisabled={editing.tasks.length >= TASK_LIST_TASKS_MAX}
          onClick={addTask}
        >
          Add task ({editing.tasks.length}/{TASK_LIST_TASKS_MAX})
        </EuiButtonEmpty>
        <EuiSpacer size="m" />
        <EuiFlexGroup gutterSize="s" justifyContent="flexEnd" responsive={false}>
          <EuiFlexItem grow={false}>
            <EuiButtonEmpty size="s" onClick={cancelEdit} data-test-subj="wamTaskListCancel" isDisabled={saving}>
              Cancel
            </EuiButtonEmpty>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiButton size="s" fill type="submit" isLoading={saving} data-test-subj="wamTaskListSave">
              {editing.id ? 'Save task list' : 'Create task list'}
            </EuiButton>
          </EuiFlexItem>
        </EuiFlexGroup>
      </EuiForm>
    </EuiPanel>
  );

  return (
    <div className="wamSettingsPage wamTaskLists" data-test-subj="wamTaskLists">
      <SettingsPageHeader
        title="Task lists"
        description="Reusable task checklists. Apply one from the Create case dialog, the case Tasks tab or an automation rule; each task list is applied at most once per case."
        actions={
          canAdminister ? (
            <EuiButton
              size="s"
              iconType="plusInCircle"
              fill
              data-test-subj="wamTaskListNew"
              isDisabled={!!editing || taskLists.length >= TASK_LISTS_MAX}
              onClick={startCreate}
            >
              New task list
            </EuiButton>
          ) : null
        }
      />
      {capabilitiesLoaded && !canAdminister ? (
        <>
          <EuiCallOut size="s" color="warning" iconType="lock" title="Task lists are administered by Wazuh administrators">
            <p>{ADMIN_HELP} Analysts can still apply the task lists listed below to a case.</p>
          </EuiCallOut>
          <EuiSpacer size="m" />
        </>
      ) : null}
      {error ? (
        <>
          <EuiCallOut color="danger" size="s" iconType="alert" title="Task lists could not be loaded" className="wamTaskListError" data-test-subj="wamTaskListsError">
            <p>{error}</p>
            <EuiButton size="s" color="danger" iconType="refresh" data-test-subj="wamTaskListsRetry" onClick={() => load()}>
              Retry
            </EuiButton>
          </EuiCallOut>
          <EuiSpacer size="m" />
        </>
      ) : null}
      {editor}
      {editor ? <EuiSpacer size="m" /> : null}
      <EuiPanel hasBorder hasShadow={false} paddingSize="m">
        <EuiTitle size="xs"><h4>Defined task lists</h4></EuiTitle>
        <EuiSpacer size="s" />
        {loading && !taskLists.length && !error ? (
          <EuiLoadingSpinner size="l" />
        ) : !taskLists.length && !error ? (
          <EuiText size="s" color="subdued" data-test-subj="wamTaskListsEmpty">
            <p>No task lists defined{canAdminister ? '. Create the first one with "New task list".' : '.'}</p>
          </EuiText>
        ) : taskLists.length ? (
          <EuiBasicTable items={taskLists} columns={columns} rowProps={(taskList: TaskList) => ({ 'data-test-subj': `wamTaskListRow-${taskList.id}` })} data-test-subj="wamTaskListsTable" />
        ) : null}
      </EuiPanel>
      {pendingDelete ? (
        <EuiConfirmModal
          title={`Delete "${pendingDelete.name}"?`}
          onCancel={() => setPendingDelete(null)}
          onConfirm={confirmDelete}
          cancelButtonText="Keep"
          confirmButtonText="Delete task list"
          buttonColor="danger"
          isLoading={deleting}
          data-test-subj="wamTaskListDeleteConfirm"
        >
          <p>
            Cases that already applied it keep their tasks. Automation rules that reference it stop applying a task list
            when they create a case.
          </p>
        </EuiConfirmModal>
      ) : null}
    </div>
  );
};
