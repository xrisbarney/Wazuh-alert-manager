import React, { useState, useEffect } from 'react';
import { EuiComboBox, EuiComboBoxOptionOption } from '@elastic/eui';
import { AlertsApiService } from '../services/api';

interface Props {
  /** Set by a wrapping EuiFormRow so its label targets the combo box input. */
  id?: string;
  apiService: AlertsApiService;
  value?: string | null;
  valueLabel?: string;
  onChange: (caseId: string | null, label?: string) => void;
  compressed?: boolean;
  fullWidth?: boolean;
  placeholder?: string;
}

/**
 * Case picker: searches by title as-you-type, and also accepts a pasted
 * case ID directly (tried as an exact lookup when nothing matches by
 * title) - covers both "I remember the case name" and "I have the ID
 * from a link/ticket" without needing two separate controls.
 */
export const CasePicker: React.FC<Props> = ({
  id,
  apiService,
  value,
  valueLabel,
  onChange,
  compressed = true,
  fullWidth = false,
  placeholder = 'Search by title, or paste a case ID',
}) => {
  const [options, setOptions] = useState<EuiComboBoxOptionOption[]>([]);
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState<EuiComboBoxOptionOption[]>(
    value ? [{ label: valueLabel || value, value }] : []
  );

  // Keep the displayed selection in sync with `value` (the tied case_id) as it
  // changes — e.g. when a different alert's flyout re-uses this control — and,
  // when only an id is supplied, resolve the case's title so the picker shows a
  // human-readable name instead of the raw id. Runs once per value change.
  useEffect(() => {
    let live = true;
    if (!value) {
      setSelected([]);
      return;
    }
    // show something immediately, then upgrade the label to the case title
    setSelected([{ label: valueLabel || value, value }]);
    if (!valueLabel) {
      apiService
        .fetchCase(value)
        .then((res: any) => {
          if (live && res?.case) setSelected([{ label: `${res.case.title} (${res.case.status})`, value }]);
        })
        .catch(() => {
          /* leave the id as the label if the case can't be fetched */
        });
    }
    return () => {
      live = false;
    };
  }, [value, valueLabel]);

  const search = async (query: string) => {
    if (!query.trim()) {
      setOptions([]);
      return;
    }
    setLoading(true);
    try {
      const res: any = await apiService.fetchCases({ q: query });
      let cases = res?.cases || [];
      if (cases.length === 0) {
        // Might be a pasted case ID rather than a title search term.
        try {
          const exact: any = await apiService.fetchCase(query.trim());
          if (exact?.case) cases = [{ id: query.trim(), ...exact.case }];
        } catch (e) {
          // not a valid id either - leave options empty
        }
      }
      setOptions(cases.map((c: any) => ({ label: `${c.title} (${c.status})`, value: c.id })));
    } catch (e) {
      setOptions([]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <EuiComboBox
      id={id}
      placeholder={placeholder}
      async
      isLoading={loading}
      options={options}
      selectedOptions={selected}
      onSearchChange={search}
      onChange={(sel) => {
        setSelected(sel);
        onChange(sel.length ? (sel[0].value as string) : null, sel.length ? sel[0].label : undefined);
      }}
      singleSelection={{ asPlainText: true }}
      compressed={compressed}
      fullWidth={fullWidth}
      isClearable
    />
  );
};
