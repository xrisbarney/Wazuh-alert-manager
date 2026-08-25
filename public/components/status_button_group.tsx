import React from 'react';
import { EuiButtonGroup } from '@elastic/eui';
import { AlertStatus } from '../../common';
import { STATUS_LABEL } from '../design';

const ORDER: AlertStatus[] = ['open', 'in_progress', 'closed'];

/**
 * The single status control used both inline in each alert row and in the
 * detail flyout, so the two read identically. A segmented EuiButtonGroup gives
 * the control real form (three connected pills showing the current state) in
 * place of the old shapeless dropdown.
 */
export const StatusButtonGroup: React.FC<{
  status: AlertStatus;
  onChange: (s: AlertStatus) => void;
  disabled?: boolean;
  compressed?: boolean;
  idPrefix?: string;
}> = ({ status, onChange, disabled, compressed, idPrefix = 'st' }) => {
  const options = ORDER.map((s) => ({ id: `${idPrefix}-${s}`, label: STATUS_LABEL[s] }));
  return (
    <EuiButtonGroup
      legend="Status"
      options={options}
      idSelected={`${idPrefix}-${status}`}
      onChange={(id) => {
        const next = id.replace(`${idPrefix}-`, '') as AlertStatus;
        if (next !== status) onChange(next);
      }}
      buttonSize={compressed ? 'compressed' : 's'}
      isDisabled={disabled}
      color="primary"
    />
  );
};
