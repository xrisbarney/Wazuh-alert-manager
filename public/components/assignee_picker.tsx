import React, { useState, useEffect } from 'react';
import { EuiComboBox, EuiComboBoxOptionOption } from '@elastic/eui';
import { AlertsApiService } from '../services/api';

interface Props {
  apiService: AlertsApiService;
  value: string | null | undefined;
  onChange: (value: string | null) => void;
  extraOptions?: string[];
  compressed?: boolean;
  fullWidth?: boolean;
  placeholder?: string;
}

/**
 * Assignee picker: prefers real dashboard users (from the Security
 * plugin's internal users API) but always allows free text, since not
 * every cluster has that API available or every assignee needs to be a
 * dashboard login (e.g. an external ticket owner).
 */
export const AssigneePicker: React.FC<Props> = ({
  apiService,
  value,
  onChange,
  extraOptions = [],
  compressed = true,
  fullWidth = false,
  placeholder = 'Unassigned',
}) => {
  const [users, setUsers] = useState<string[]>([]);

  useEffect(() => {
    apiService
      .fetchUsers()
      .then(setUsers)
      .catch(() => setUsers([]));
  }, []);

  const optionValues = Array.from(new Set([...users, ...extraOptions])).sort();
  const options: EuiComboBoxOptionOption[] = optionValues.map((u) => ({ label: u }));
  const selectedOptions: EuiComboBoxOptionOption[] = value ? [{ label: value }] : [];

  return (
    <EuiComboBox
      placeholder={placeholder}
      singleSelection={{ asPlainText: true }}
      options={options}
      selectedOptions={selectedOptions}
      onChange={(selected) => onChange(selected.length ? selected[0].label : null)}
      onCreateOption={(searchValue) => onChange(searchValue.trim())}
      compressed={compressed}
      fullWidth={fullWidth}
      isClearable
    />
  );
};
