import React, { useState } from 'react';
import { EuiFlexGroup, EuiFlexItem, EuiText, EuiButton, EuiPopover, EuiContextMenuPanel, EuiContextMenuItem, EuiSpacer } from '@elastic/eui';
import { AlertStatus } from '../../common';
import { STATUS_OPTIONS } from './status_badge';
import { AssigneePicker } from './assignee_picker';
import { AlertsApiService } from '../services/api';

interface Props {
  apiService: AlertsApiService;
  selectedCount: number;
  onSetStatus: (status: AlertStatus) => void;
  onAssign: (assignee: string | null) => void;
  onCreateCase: () => void;
  onClear: () => void;
  busy: boolean;
}

export const BulkActionsBar: React.FC<Props> = ({ apiService, selectedCount, onSetStatus, onAssign, onCreateCase, onClear, busy }) => {
  const [isStatusMenuOpen, setIsStatusMenuOpen] = useState(false);
  const [isAssignPopoverOpen, setIsAssignPopoverOpen] = useState(false);
  const [pendingAssignee, setPendingAssignee] = useState<string | null>(null);

  if (selectedCount === 0) return null;

  return (
    <EuiFlexGroup
      alignItems="center"
      gutterSize="m"
      style={{ background: '#f5f7fa', padding: '8px 12px', borderRadius: 4, marginBottom: 8 }}
    >
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
            items={STATUS_OPTIONS.map((opt) => (
              <EuiContextMenuItem
                key={opt.value}
                onClick={() => {
                  setIsStatusMenuOpen(false);
                  onSetStatus(opt.value as AlertStatus);
                }}
              >
                {opt.text}
              </EuiContextMenuItem>
            ))}
          />
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
      <EuiFlexItem grow={false}>
        <EuiButton size="s" iconType="folderClosed" onClick={onCreateCase} isLoading={busy}>
          Create case from selected
        </EuiButton>
      </EuiFlexItem>
      <EuiFlexItem grow={false}>
        <EuiButton size="s" color="text" onClick={onClear}>
          Clear selection
        </EuiButton>
      </EuiFlexItem>
    </EuiFlexGroup>
  );
};
