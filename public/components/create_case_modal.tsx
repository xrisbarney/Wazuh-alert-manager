import React, { useEffect, useState } from 'react';
import {
  EuiModal,
  EuiModalHeader,
  EuiModalHeaderTitle,
  EuiModalBody,
  EuiModalFooter,
  EuiButton,
  EuiButtonEmpty,
  EuiFieldText,
  EuiTextArea,
  EuiSelect,
  EuiFormRow,
  EuiText,
} from '@elastic/eui';
import { CaseSeverity, TaskList } from '../../common';
import { CASE_SEVERITY_OPTIONS } from './status_badge';
import { AssigneePicker } from './assignee_picker';
import { AlertsApiService } from '../services/api';

export interface CreateCasePayload {
  title: string;
  description: string;
  severity: CaseSeverity;
  assignedTo: string | null;
  /** Enabled task list applied right after creation (step 2.2); null = none. */
  taskListId: string | null;
}

interface Props {
  apiService: AlertsApiService;
  alertCount: number;
  onClose: () => void;
  onCreate: (payload: CreateCasePayload) => void;
  busy: boolean;
}

type TaskListLoad = { state: 'loading' } | { state: 'ready'; taskLists: TaskList[] } | { state: 'error'; message: string };

/** Help text under the task list picker for the current load state and choice. */
export function taskListHelpText(load: TaskListLoad, taskListId: string | null): string {
  if (load.state === 'loading') return 'Loading task lists';
  if (load.state === 'error') return `Task lists could not be loaded (${load.message}); the case is created without one.`;
  if (!load.taskLists.length) return 'No task lists defined';
  const chosen = taskListId ? load.taskLists.find((item) => item.id === taskListId) : undefined;
  if (!chosen) return 'Its tasks are added to the new case.';
  const n = chosen.tasks.length;
  return `Adds ${n} task${n === 1 ? '' : 's'} to the new case.`;
}

export const CreateCaseModal: React.FC<Props> = ({ apiService, alertCount, onClose, onCreate, busy }) => {
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState<CaseSeverity>('medium');
  const [assignedTo, setAssignedTo] = useState<string | null>(null);
  const [taskListId, setTaskListId] = useState<string | null>(null);
  const [taskLists, setTaskLists] = useState<TaskListLoad>({ state: 'loading' });

  // Enabled task lists are loaded once per open; a failure only disables the picker.
  useEffect(() => {
    let active = true;
    apiService
      .fetchTaskLists(true)
      .then((response) => {
        if (active) setTaskLists({ state: 'ready', taskLists: response.taskLists.filter((item) => item.enabled) });
      })
      .catch((error: any) => {
        if (active) setTaskLists({ state: 'error', message: error?.body?.message || error?.message || 'request failed' });
      });
    return () => {
      active = false;
    };
  }, [apiService]);

  const options = [
    { value: '', text: taskLists.state === 'ready' && !taskLists.taskLists.length ? 'No task lists defined' : 'No task list' },
    ...(taskLists.state === 'ready'
      ? taskLists.taskLists.map((item) => ({ value: item.id, text: `${item.name} (${item.tasks.length} task${item.tasks.length === 1 ? '' : 's'})` }))
      : []),
  ];

  return (
    <EuiModal onClose={onClose} className="wamCreateCaseModal">
      <EuiModalHeader>
        <EuiModalHeaderTitle>Create case</EuiModalHeaderTitle>
      </EuiModalHeader>
      <EuiModalBody>
        <EuiText size="s" color="subdued">
          This case will link {alertCount} selected alert{alertCount === 1 ? '' : 's'}.
        </EuiText>
        <EuiFormRow label="Title" fullWidth>
          <EuiFieldText fullWidth value={title} onChange={(e) => setTitle(e.target.value)} autoFocus data-test-subj="wamCreateCaseTitle" />
        </EuiFormRow>
        <EuiFormRow label="Description" fullWidth>
          <EuiTextArea fullWidth value={description} onChange={(e) => setDescription(e.target.value)} rows={4} />
        </EuiFormRow>
        <EuiFormRow label="Severity" fullWidth>
          <EuiSelect
            fullWidth
            options={CASE_SEVERITY_OPTIONS}
            value={severity}
            onChange={(e) => setSeverity(e.target.value as CaseSeverity)}
          />
        </EuiFormRow>
        <EuiFormRow label="Assign to" fullWidth>
          <AssigneePicker apiService={apiService} value={assignedTo} onChange={setAssignedTo} fullWidth compressed={false} />
        </EuiFormRow>
        <EuiFormRow label="Task list" fullWidth helpText={taskListHelpText(taskLists, taskListId)}>
          <EuiSelect
            fullWidth
            data-test-subj="wamCreateCaseTaskList"
            options={options}
            value={taskListId || ''}
            disabled={taskLists.state !== 'ready' || !taskLists.taskLists.length}
            isLoading={taskLists.state === 'loading'}
            onChange={(e) => setTaskListId(e.target.value || null)}
          />
        </EuiFormRow>
      </EuiModalBody>
      <EuiModalFooter>
        <EuiButtonEmpty onClick={onClose}>Cancel</EuiButtonEmpty>
        <EuiButton
          fill
          isDisabled={!title.trim()}
          isLoading={busy}
          data-test-subj="wamCreateCaseSubmit"
          onClick={() => onCreate({ title: title.trim(), description, severity, assignedTo, taskListId })}
        >
          Create case
        </EuiButton>
      </EuiModalFooter>
    </EuiModal>
  );
};
