import React from 'react';
import { EuiHealth, EuiBadge } from '@elastic/eui';
import { AlertStatus, CaseStatus, DISPOSITIONS, DISPOSITION_LABELS } from '../../common';
import type { Disposition } from '../../common';
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
// A Wazuh 5.0 finding carries a severity label instead of a number; the badge
// shows the band from the label and no numeric suffix.
export const SeverityBadge: React.FC<{ level: number | null | undefined; label?: string | null }> = ({ level, label }) => {
  const band = severityBand(level, label);
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

// Close outcome (step 2.4): one colour per taxonomy value, label always
// shown. Rendered only on closed records: a reopened alert keeps its stored
// disposition for audit but the queue must not read as "closed".
export const DISPOSITION_BADGE_COLOR: Record<Disposition, string> = {
  true_positive: 'danger',
  false_positive: 'default',
  benign: 'success',
  duplicate: 'hollow',
  undetermined: 'warning',
};

export const DispositionBadge: React.FC<{
  disposition?: string | null;
  /** When given, the badge renders only for `closed`. */
  status?: string | null;
  className?: string;
  testSubj?: string;
}> = ({ disposition, status, className, testSubj = 'wamDispositionBadge' }) => {
  if (!disposition || !(DISPOSITIONS as readonly string[]).includes(disposition)) return null;
  if (status != null && status !== 'closed') return null;
  const value = disposition as Disposition;
  return (
    <EuiBadge
      color={DISPOSITION_BADGE_COLOR[value]}
      className={`wamDispositionBadge wamDispositionBadge--${value}${className ? ` ${className}` : ''}`}
      title={`Disposition: ${DISPOSITION_LABELS[value]}`}
      data-test-subj={testSubj}
    >
      {DISPOSITION_LABELS[value]}
    </EuiBadge>
  );
};

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
