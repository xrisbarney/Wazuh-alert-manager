import React from 'react';
import { EuiHealth, EuiBadge } from '@elastic/eui';
import { AlertStatus, CaseStatus } from '../../common';
import {
  statusLabel,
  statusColor,
  severityBand,
  SEVERITY_LABEL,
  SEVERITY_BADGE_COLOR,
  CASE_SEVERITY_BADGE_COLOR,
} from '../design';

export { statusLabel, statusColor } from '../design';

export const StatusBadge: React.FC<{ status: AlertStatus | CaseStatus }> = ({ status }) => (
  <EuiHealth color={statusColor(status)}>{statusLabel(status)}</EuiHealth>
);

// Alert severity derived from the rule level, badged with a label + the number
// so colour is never the sole carrier of meaning (accessibility) and the exact
// level is still visible.
export const SeverityBadge: React.FC<{ level: number | null | undefined }> = ({ level }) => {
  const band = severityBand(level);
  return (
    <EuiBadge color={SEVERITY_BADGE_COLOR[band]}>
      {SEVERITY_LABEL[band]}
      {typeof level === 'number' ? ` ${level}` : ''}
    </EuiBadge>
  );
};

// Case severity is a named value (low/medium/high/critical), not a rule level.
export const CaseSeverityBadge: React.FC<{ severity: string }> = ({ severity }) => (
  <EuiBadge color={CASE_SEVERITY_BADGE_COLOR[severity] || 'default'}>
    {severity ? severity.charAt(0).toUpperCase() + severity.slice(1) : 'Unknown'}
  </EuiBadge>
);

export const STATUS_OPTIONS = [
  { value: 'open', text: 'Open' },
  { value: 'in_progress', text: 'In progress' },
  { value: 'closed', text: 'Closed' },
];

export const CASE_SEVERITY_OPTIONS = [
  { value: 'low', text: 'Low' },
  { value: 'medium', text: 'Medium' },
  { value: 'high', text: 'High' },
  { value: 'critical', text: 'Critical' },
];
