import React, { useState } from 'react';
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
import { CaseSeverity } from '../../common';
import { CASE_SEVERITY_OPTIONS } from './status_badge';
import { AssigneePicker } from './assignee_picker';
import { AlertsApiService } from '../services/api';

interface Props {
  apiService: AlertsApiService;
  alertCount: number;
  onClose: () => void;
  onCreate: (payload: { title: string; description: string; severity: CaseSeverity; assignedTo: string | null }) => void;
  busy: boolean;
}

export const CreateCaseModal: React.FC<Props> = ({ apiService, alertCount, onClose, onCreate, busy }) => {
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState<CaseSeverity>('medium');
  const [assignedTo, setAssignedTo] = useState<string | null>(null);

  return (
    <EuiModal onClose={onClose}>
      <EuiModalHeader>
        <EuiModalHeaderTitle>Create case</EuiModalHeaderTitle>
      </EuiModalHeader>
      <EuiModalBody>
        <EuiText size="s" color="subdued">
          This case will link {alertCount} selected alert{alertCount === 1 ? '' : 's'}.
        </EuiText>
        <EuiFormRow label="Title" fullWidth>
          <EuiFieldText fullWidth value={title} onChange={(e) => setTitle(e.target.value)} autoFocus />
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
      </EuiModalBody>
      <EuiModalFooter>
        <EuiButtonEmpty onClick={onClose}>Cancel</EuiButtonEmpty>
        <EuiButton
          fill
          isDisabled={!title.trim()}
          isLoading={busy}
          onClick={() => onCreate({ title: title.trim(), description, severity, assignedTo })}
        >
          Create case
        </EuiButton>
      </EuiModalFooter>
    </EuiModal>
  );
};
