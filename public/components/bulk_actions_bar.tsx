import React, { useState } from 'react';
import { EuiFlexGroup, EuiFlexItem, EuiText, EuiButton, EuiPopover, EuiContextMenuPanel, EuiContextMenuItem, EuiSpacer, EuiPanel } from '@elastic/eui';
import { AlertStatus, CaseStatus } from '../../common';
import { STATUS_OPTIONS } from './status_badge';
import { AssigneePicker } from './assignee_picker';
import { CasePicker } from './case_picker';
import { AlertsApiService } from '../services/api';

interface StatusOption<TStatus> {
  value: TStatus;
  text: string;
}

interface Props<TStatus extends AlertStatus | CaseStatus> {
  apiService: AlertsApiService;
  selectedCount: number;
  onSetStatus: (status: TStatus) => void;
  onAssign: (assignee: string | null) => void;
  onAddToCase?: (caseId: string | null) => void;
  onCreateCase?: () => void;
  onClear: () => void;
  busy: boolean;
  statusOptions?: Array<StatusOption<TStatus>>;
  statusHelpText?: string;
}

export function BulkActionsBar<TStatus extends AlertStatus | CaseStatus>({
  apiService,
  selectedCount,
  onSetStatus,
  onAssign,
  onAddToCase,
  onCreateCase,
  onClear,
  busy,
  statusOptions,
  statusHelpText,
}: Props<TStatus>) {
  const [isStatusMenuOpen, setIsStatusMenuOpen] = useState(false);
  const [isAssignPopoverOpen, setIsAssignPopoverOpen] = useState(false);
  const [pendingAssignee, setPendingAssignee] = useState<string | null>(null);
  const [isCasePopoverOpen, setIsCasePopoverOpen] = useState(false);
  const [pendingCaseId, setPendingCaseId] = useState<string | null>(null);
  const availableStatuses = statusOptions || (STATUS_OPTIONS as unknown as Array<StatusOption<TStatus>>);

  if (selectedCount === 0) return null;

  return (
    <EuiPanel color="subdued" paddingSize="s" hasShadow={false} hasBorder style={{ marginBottom: 8 }} className="wamBulkActions">
    <EuiFlexGroup alignItems="center" gutterSize="m" wrap>
      <EuiFlexItem grow={false}>
        <EuiText size="s">
          <strong>{selectedCount}</strong> selected
        </EuiText>
      </EuiFlexItem>
      <EuiFlexItem grow={false}>
        <EuiPopover
          button={
            <EuiButton size="s" iconType="arrowDown" iconSide="right" onClick={() => setIsStatusMenuOpen((v) => !v)} isLoading={busy}>
              Set status
            </EuiButton>
          }
          isOpen={isStatusMenuOpen}
          closePopover={() => setIsStatusMenuOpen(false)}
          panelPaddingSize="none"
        >
          <EuiContextMenuPanel
            items={availableStatuses.map((opt) => (
              <EuiContextMenuItem
                key={opt.value}
                onClick={() => {
                  setIsStatusMenuOpen(false);
                  onSetStatus(opt.value);
                }}
              >
                {opt.text}
              </EuiContextMenuItem>
            ))}
          />
          {statusHelpText && <EuiText size="xs" color="subdued"><p>{statusHelpText}</p></EuiText>}
        </EuiPopover>
      </EuiFlexItem>
      <EuiFlexItem grow={false}>
        <EuiPopover
          button={
            <EuiButton size="s" iconType="user" iconSide="right" onClick={() => setIsAssignPopoverOpen((v) => !v)} isLoading={busy}>
              Assign
            </EuiButton>
          }
          isOpen={isAssignPopoverOpen}
          closePopover={() => setIsAssignPopoverOpen(false)}
          panelPaddingSize="m"
        >
          <div style={{ width: 260 }}>
            <AssigneePicker apiService={apiService} value={pendingAssignee} onChange={setPendingAssignee} fullWidth />
            <EuiSpacer size="s" />
            <EuiFlexGroup gutterSize="s">
              <EuiFlexItem>
                <EuiButton
                  size="s"
                  fullWidth
                  onClick={() => {
                    onAssign(pendingAssignee);
                    setIsAssignPopoverOpen(false);
                  }}
                >
                  Assign
                </EuiButton>
              </EuiFlexItem>
              <EuiFlexItem>
                <EuiButton
                  size="s"
                  fullWidth
                  color="text"
                  onClick={() => {
                    onAssign(null);
                    setIsAssignPopoverOpen(false);
                  }}
                >
                  Unassign
                </EuiButton>
              </EuiFlexItem>
            </EuiFlexGroup>
          </div>
        </EuiPopover>
      </EuiFlexItem>
      {onAddToCase && <EuiFlexItem grow={false}>
        <EuiPopover
          button={
            <EuiButton size="s" iconType="link" iconSide="right" onClick={() => setIsCasePopoverOpen((v) => !v)} isLoading={busy}>
              Add to case
            </EuiButton>
          }
          isOpen={isCasePopoverOpen}
          closePopover={() => setIsCasePopoverOpen(false)}
          panelPaddingSize="m"
        >
          <div style={{ width: 300 }}>
            <CasePicker apiService={apiService} value={pendingCaseId} onChange={setPendingCaseId} fullWidth />
            <EuiSpacer size="s" />
            <EuiButton
              size="s"
              fullWidth
              isDisabled={!pendingCaseId}
              onClick={() => {
                onAddToCase(pendingCaseId);
                setPendingCaseId(null);
                setIsCasePopoverOpen(false);
              }}
            >
              Add selected alerts to this case
            </EuiButton>
          </div>
        </EuiPopover>
      </EuiFlexItem>}
      {onCreateCase && <EuiFlexItem grow={false}>
        <EuiButton size="s" iconType="folderClosed" onClick={onCreateCase} isLoading={busy}>
          Create case from selected
        </EuiButton>
      </EuiFlexItem>}
      <EuiFlexItem grow={false}>
        <EuiButton size="s" color="text" onClick={onClear}>
          Clear selection
        </EuiButton>
      </EuiFlexItem>
    </EuiFlexGroup>
    </EuiPanel>
  );
}
