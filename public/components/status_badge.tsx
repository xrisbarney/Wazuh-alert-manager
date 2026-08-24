import React from 'react';
import { EuiHealth } from '@elastic/eui';
import { AlertStatus, CaseStatus } from '../../common';

const STATUS_LABELS: Record<string, string> = {
  open: 'Open',
  in_progress: 'In Progress',
  closed: 'Closed',
};

const STATUS_COLORS: Record<string, string> = {
  open: 'danger',
  in_progress: 'warning',
  closed: 'success',
};

export const statusLabel = (status: string) => STATUS_LABELS[status] || status;
export const statusColor = (status: string) => STATUS_COLORS[status] || 'subdued';

export const StatusBadge: React.FC<{ status: AlertStatus | CaseStatus }> = ({ status }) => (
  <EuiHealth color={statusColor(status)}>{statusLabel(status)}</EuiHealth>
);

export const STATUS_OPTIONS = [
  { value: 'open', text: 'Open' },
  { value: 'in_progress', text: 'In Progress' },
  { value: 'closed', text: 'Closed' },
];

export const CASE_SEVERITY_OPTIONS = [
  { value: 'low', text: 'Low' },
  { value: 'medium', text: 'Medium' },
  { value: 'high', text: 'High' },
  { value: 'critical', text: 'Critical' },
];
