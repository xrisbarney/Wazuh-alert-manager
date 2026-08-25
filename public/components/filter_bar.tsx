import React, { useState } from 'react';
import {
  EuiFlexGroup,
  EuiFlexItem,
  EuiComboBox,
  EuiComboBoxOptionOption,
  EuiFieldNumber,
  EuiFormRow,
  EuiButton,
  EuiButtonEmpty,
  EuiPopover,
  EuiText,
  EuiSpacer,
  EuiTextArea,
  EuiSwitch,
  EuiDatePickerRange,
  EuiDatePicker,
  EuiFilterGroup,
  EuiFilterButton,
} from '@elastic/eui';
import moment from 'moment';
import { FilterOptions, AlertStatus } from '../../common';
import { STATUS_OPTIONS } from './status_badge';

export interface AlertFilterState {
  statuses: AlertStatus[];
  levelMin?: number;
  levelMax?: number;
  ruleIds: string[];
  agentNames: string[];
  alertTypes: string[];
  assignedTo: string[];
  q: string;
}

interface TimeRange {
  from: string;
  to: string;
  mode?: 'absolute' | 'relative';
}

const QUICK_TIME_RANGES = [
  { start: 'now-15m', end: 'now', label: 'Last 15 minutes' },
  { start: 'now-30m', end: 'now', label: 'Last 30 minutes' },
  { start: 'now-1h', end: 'now', label: 'Last 1 hour' },
  { start: 'now-24h', end: 'now', label: 'Last 24 hours' },
  { start: 'now-7d', end: 'now', label: 'Last 7 days' },
  { start: 'now-30d', end: 'now', label: 'Last 30 days' },
];

interface Props {
  filters: AlertFilterState;
  onChange: (filters: AlertFilterState) => void;
  timeRange: TimeRange;
  onTimeRangeChange: (range: TimeRange) => void;
  filterOptions: FilterOptions | null;
  onApply: () => void;
  loading: boolean;
  autoRefreshEnabled: boolean;
  onToggleAutoRefresh: () => void;
}

const toOptions = (values: string[]): EuiComboBoxOptionOption[] => values.map((v) => ({ label: v }));

export const FilterBar: React.FC<Props> = ({
  filters,
  onChange,
  timeRange,
  onTimeRangeChange,
  filterOptions,
  onApply,
  loading,
  autoRefreshEnabled,
  onToggleAutoRefresh,
}) => {
  const [isTimePopoverOpen, setIsTimePopoverOpen] = useState(false);
  const [customStart, setCustomStart] = useState<moment.Moment | null>(null);
  const [customEnd, setCustomEnd] = useState<moment.Moment | null>(null);
  const [advancedOpen, setAdvancedOpen] = useState(false);

  const statusOptions = STATUS_OPTIONS.map((s) => ({ label: s.text, value: s.value }));
  const ruleIdOptions = toOptions((filterOptions?.ruleIds || []).map((r) => r.value));
  const agentOptions = toOptions((filterOptions?.agents || []).map((a) => a.value));
  const alertTypeOptions = toOptions((filterOptions?.alertTypes || []).map((a) => a.value));
  const assigneeOptions = toOptions((filterOptions?.assignees || []).map((a) => a.value));

  const formatTimeRangeDisplay = () => {
    if (timeRange.mode === 'absolute') {
      return `${new Date(timeRange.from).toLocaleString()} - ${new Date(timeRange.to).toLocaleString()}`;
    }
    const range = QUICK_TIME_RANGES.find((r) => r.start === timeRange.from && r.end === timeRange.to);
    return range ? range.label : `${timeRange.from} to ${timeRange.to}`;
  };

  return (
    <>
      <EuiFlexGroup gutterSize="s" wrap alignItems="flexEnd">
        <EuiFlexItem grow={false}>
          <EuiFormRow label="Status" display="rowCompressed">
            <EuiFilterGroup compressed>
              {statusOptions.map((o) => {
                const active = filters.statuses.includes(o.value as AlertStatus);
                return (
                  <EuiFilterButton
                    key={o.value}
                    hasActiveFilters={active}
                    onClick={() =>
                      onChange({
                        ...filters,
                        statuses: active
                          ? filters.statuses.filter((s) => s !== o.value)
                          : [...filters.statuses, o.value as AlertStatus],
                      })
                    }
                  >
                    {o.label}
                  </EuiFilterButton>
                );
              })}
            </EuiFilterGroup>
          </EuiFormRow>
        </EuiFlexItem>

        <EuiFlexItem style={{ minWidth: 90 }}>
          <EuiFormRow label="Level min" display="rowCompressed">
            <EuiFieldNumber
              compressed
              min={filterOptions?.levelRange.min ?? 0}
              max={filterOptions?.levelRange.max ?? 15}
              value={filters.levelMin ?? ''}
              onChange={(e) => onChange({ ...filters, levelMin: e.target.value === '' ? undefined : Number(e.target.value) })}
            />
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem style={{ minWidth: 90 }}>
          <EuiFormRow label="Level max" display="rowCompressed">
            <EuiFieldNumber
              compressed
              min={filterOptions?.levelRange.min ?? 0}
              max={filterOptions?.levelRange.max ?? 15}
              value={filters.levelMax ?? ''}
              onChange={(e) => onChange({ ...filters, levelMax: e.target.value === '' ? undefined : Number(e.target.value) })}
            />
          </EuiFormRow>
        </EuiFlexItem>

        <EuiFlexItem style={{ minWidth: 150 }}>
          <EuiFormRow label="Rule ID" display="rowCompressed">
            <EuiComboBox
              placeholder="Any rule"
              options={ruleIdOptions}
              selectedOptions={toOptions(filters.ruleIds)}
              onChange={(selected) => onChange({ ...filters, ruleIds: selected.map((s) => s.label) })}
              onCreateOption={(value) => onChange({ ...filters, ruleIds: [...filters.ruleIds, value] })}
              compressed
            />
          </EuiFormRow>
        </EuiFlexItem>

        <EuiFlexItem style={{ minWidth: 150 }}>
          <EuiFormRow label="Agent" display="rowCompressed">
            <EuiComboBox
              placeholder="Any agent"
              options={agentOptions}
              selectedOptions={toOptions(filters.agentNames)}
              onChange={(selected) => onChange({ ...filters, agentNames: selected.map((s) => s.label) })}
              onCreateOption={(value) => onChange({ ...filters, agentNames: [...filters.agentNames, value] })}
              compressed
            />
          </EuiFormRow>
        </EuiFlexItem>

        <EuiFlexItem style={{ minWidth: 150 }}>
          <EuiFormRow label="Alert Type" display="rowCompressed">
            <EuiComboBox
              placeholder="Any type"
              options={alertTypeOptions}
              selectedOptions={toOptions(filters.alertTypes)}
              onChange={(selected) => onChange({ ...filters, alertTypes: selected.map((s) => s.label) })}
              compressed
            />
          </EuiFormRow>
        </EuiFlexItem>

        <EuiFlexItem style={{ minWidth: 150 }}>
          <EuiFormRow label="Assigned to" display="rowCompressed">
            <EuiComboBox
              placeholder="Anyone"
              options={assigneeOptions}
              selectedOptions={toOptions(filters.assignedTo)}
              onChange={(selected) => onChange({ ...filters, assignedTo: selected.map((s) => s.label) })}
              onCreateOption={(value) => onChange({ ...filters, assignedTo: [...filters.assignedTo, value] })}
              compressed
            />
          </EuiFormRow>
        </EuiFlexItem>
      </EuiFlexGroup>

      <EuiSpacer size="s" />

      <EuiFlexGroup gutterSize="s" alignItems="center" justifyContent="flexEnd" responsive={false} wrap>
        <EuiFlexItem grow={false}>
            <EuiPopover
              button={
                <EuiButton size="s" iconType="arrowDown" iconSide="right" onClick={() => setIsTimePopoverOpen((v) => !v)}>
                  {formatTimeRangeDisplay()}
                </EuiButton>
              }
              isOpen={isTimePopoverOpen}
              closePopover={() => setIsTimePopoverOpen(false)}
              panelPaddingSize="m"
            >
              <div style={{ width: 300 }}>
                <EuiText size="s">
                  <h4>Quick ranges</h4>
                </EuiText>
                <EuiSpacer size="s" />
                {QUICK_TIME_RANGES.map((range) => (
                  <EuiButton
                    key={range.label}
                    size="s"
                    fullWidth
                    onClick={() => {
                      onTimeRangeChange({ from: range.start, to: range.end, mode: 'relative' });
                      setIsTimePopoverOpen(false);
                    }}
                    style={{ marginBottom: 4, justifyContent: 'flex-start' }}
                  >
                    {range.label}
                  </EuiButton>
                ))}
                <EuiSpacer size="m" />
                <EuiText size="s">
                  <h4>Custom range</h4>
                </EuiText>
                <EuiSpacer size="s" />
                <EuiDatePickerRange
                  startDateControl={
                    <EuiDatePicker selected={customStart} onChange={setCustomStart} placeholder="Start" showTimeSelect />
                  }
                  endDateControl={<EuiDatePicker selected={customEnd} onChange={setCustomEnd} placeholder="End" showTimeSelect />}
                />
                <EuiSpacer size="s" />
                <EuiButton
                  size="s"
                  fullWidth
                  disabled={!customStart || !customEnd}
                  onClick={() => {
                    if (customStart && customEnd) {
                      onTimeRangeChange({ from: customStart.toISOString(), to: customEnd.toISOString(), mode: 'absolute' });
                      setIsTimePopoverOpen(false);
                    }
                  }}
                >
                  Apply custom range
                </EuiButton>
              </div>
            </EuiPopover>
        </EuiFlexItem>

        <EuiFlexItem grow={false}>
            <EuiButton size="s" fill onClick={onApply} isLoading={loading} iconType="search">
              Apply
            </EuiButton>
        </EuiFlexItem>

        <EuiFlexItem grow={false}>
            <EuiSwitch label="Auto refresh (5 min)" checked={autoRefreshEnabled} onChange={onToggleAutoRefresh} compressed />
        </EuiFlexItem>
      </EuiFlexGroup>

      <EuiSpacer size="xs" />
      <EuiButtonEmpty size="xs" onClick={() => setAdvancedOpen((v) => !v)} iconType={advancedOpen ? 'arrowUp' : 'arrowDown'}>
        Advanced query (Lucene)
      </EuiButtonEmpty>
      {advancedOpen && (
        <EuiFormRow
          fullWidth
          display="rowCompressed"
          helpText="Optional Lucene query, combined with the filters above using AND. Press Apply to run it."
        >
          <EuiTextArea
            fullWidth
            rows={3}
            placeholder="e.g. rule.description:*ssh* AND NOT agent.name:server1"
            value={filters.q}
            onChange={(e) => onChange({ ...filters, q: e.target.value })}
            resize="vertical"
          />
        </EuiFormRow>
      )}
    </>
  );
};
