import React, { useState } from 'react';
import {
  EuiButton,
  EuiButtonEmpty,
  EuiFormRow,
  EuiModal,
  EuiModalBody,
  EuiModalFooter,
  EuiModalHeader,
  EuiModalHeaderTitle,
  EuiSpacer,
  EuiSuperSelect,
  EuiText,
  EuiTextArea,
} from '@elastic/eui';
import {
  CLOSURE_REASON_MAX_LENGTH,
  DEFAULT_DISPOSITION,
  DISPOSITIONS,
  DISPOSITION_DESCRIPTIONS,
  DISPOSITION_LABELS,
} from '../../common';
import type { Disposition } from '../../common';

/** What the analyst chose in the close dialog (step 2.4). */
export interface CloseOutcome {
  disposition: Disposition;
  /** Trimmed; null when left empty. */
  closureReason: string | null;
}

interface Props {
  /** "Close this case?", "Close 3 alerts?" ... */
  title: string;
  confirmLabel: string;
  onConfirm: (outcome: CloseOutcome) => void;
  onCancel: () => void;
  busy?: boolean;
  initialDisposition?: Disposition;
  /** Extra body content rendered under the outcome controls (the case dialog lists the linked alerts here). */
  children?: React.ReactNode;
  /** Prefix of the data-test-subj hooks (`<prefix>`, `<prefix>Disposition`, `<prefix>Reason`, `<prefix>Confirm`, `<prefix>Cancel`). */
  testSubj?: string;
}

/** Select options: label plus the one-line description of each disposition. */
export const DISPOSITION_SELECT_OPTIONS = DISPOSITIONS.map((value) => ({
  value,
  inputDisplay: DISPOSITION_LABELS[value],
  dropdownDisplay: (
    <span className="wamDispositionOption" data-test-subj={`wamDispositionOption-${value}`}>
      <strong>{DISPOSITION_LABELS[value]}</strong>
      <EuiText size="xs" color="subdued">
        <p>{DISPOSITION_DESCRIPTIONS[value]}</p>
      </EuiText>
    </span>
  ),
}));

/**
 * The one close dialog of the workbench (step 2.4): a disposition select and a
 * closure reason, used by the case flyout (with the linked-alert checklist as
 * children), the alert flyout and the bulk close of the queue.
 */
export const CloseCaseDialog: React.FC<Props> = ({
  title,
  confirmLabel,
  onConfirm,
  onCancel,
  busy = false,
  initialDisposition = DEFAULT_DISPOSITION,
  children,
  testSubj = 'wamCloseDialog',
}) => {
  const [disposition, setDisposition] = useState<Disposition>(initialDisposition);
  const [reason, setReason] = useState('');
  const confirm = () => {
    const trimmed = reason.trim();
    onConfirm({ disposition, closureReason: trimmed ? trimmed : null });
  };

  return (
    <EuiModal onClose={onCancel} className="wamCloseDialog" data-test-subj={testSubj}>
      <EuiModalHeader>
        <EuiModalHeaderTitle>{title}</EuiModalHeaderTitle>
      </EuiModalHeader>
      <EuiModalBody>
        <EuiFormRow label="Disposition" helpText="Recorded on the closed record and reported as the outcome of the detection." fullWidth>
          <EuiSuperSelect
            fullWidth
            options={DISPOSITION_SELECT_OPTIONS}
            valueOfSelected={disposition}
            onChange={(value) => setDisposition(value as Disposition)}
            hasDividers
            data-test-subj={`${testSubj}Disposition`}
          />
        </EuiFormRow>
        <EuiFormRow label="Closure reason (optional)" fullWidth>
          <EuiTextArea
            fullWidth
            rows={3}
            maxLength={CLOSURE_REASON_MAX_LENGTH}
            value={reason}
            placeholder="Why this outcome? Kept with the record and shown in the case report."
            onChange={(event) => setReason(event.target.value)}
            data-test-subj={`${testSubj}Reason`}
          />
        </EuiFormRow>
        {children ? (
          <>
            <EuiSpacer size="m" />
            {children}
          </>
        ) : null}
      </EuiModalBody>
      <EuiModalFooter>
        <EuiButtonEmpty onClick={onCancel} data-test-subj={`${testSubj}Cancel`}>Cancel</EuiButtonEmpty>
        <EuiButton color="danger" fill onClick={confirm} isLoading={busy} data-test-subj={`${testSubj}Confirm`}>
          {confirmLabel}
        </EuiButton>
      </EuiModalFooter>
    </EuiModal>
  );
};
