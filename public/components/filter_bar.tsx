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
  EuiFieldSearch,
  EuiSwitch,
  EuiDatePickerRange,
  EuiDatePicker,
  EuiFilterGroup,
  EuiFilterButton,
  EuiPanel,
  EuiSelect,
} from '@elastic/eui';
import moment from 'moment';
import { FilterOptions, AlertStatus, EnrichmentVerdictFilter, AssetCriticality, ASSET_CRITICALITIES, SlaState, DISPOSITIONS, DISPOSITION_LABELS } from '../../common';
import type { Disposition } from '../../common';
import { STATUS_OPTIONS } from './status_badge';

export interface AlertFilterState {
  statuses: AlertStatus[];
  levelMin?: number;
  levelMax?: number;
  ruleIds: string[];
  agentNames: string[];
  alertTypes: string[];
  assignedTo: string[];
  /** Stored enrichment worst verdict (step 6.3); undefined = any. */
  enrichmentVerdict?: EnrichmentVerdictFilter;
  /** Stamped asset criticality (step 6.4a); empty = any. */
  assetCriticality?: AssetCriticality[];
  /** Due-date quick filter (step 3.2): breached | due_soon; undefined = any. */
  slaState?: SlaState;
  /** Close outcome (step 2.4); empty = any. Meaningful with the Closed status. */
  disposition?: Disposition[];
  q: string;
}

/** Quick filters of the queue: chips that set `slaState` (exclusive; a second click clears). */
export const SLA_QUICK_FILTERS: Array<{ value: SlaState; label: string; title: string }> = [
  { value: 'breached', label: 'Breached', title: 'Open or in-progress alerts whose resolve due date has passed' },
  { value: 'due_soon', label: 'Due within 1h', title: 'Open or in-progress alerts due in the next hour' },
];

const ASSET_CRITICALITY_OPTIONS: Array<EuiComboBoxOptionOption<AssetCriticality>> = ASSET_CRITICALITIES.map((value) => ({
  label: value.charAt(0).toUpperCase() + value.slice(1),
  value,
}));

const DISPOSITION_OPTIONS: Array<EuiComboBoxOptionOption<Disposition>> = DISPOSITIONS.map((value) => ({
  label: DISPOSITION_LABELS[value],
  value,
}));

const ENRICHMENT_VERDICT_OPTIONS: Array<{ value: string; text: string }> = [
  { value: '', text: 'Any' },
  { value: 'malicious', text: 'Malicious' },
  { value: 'suspicious', text: 'Suspicious' },
  { value: 'clean', text: 'Clean' },
];

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
  const draftSignature = JSON.stringify({ filters, timeRange });
  const [appliedSignature, setAppliedSignature] = useState(draftSignature);

  const statusOptions = STATUS_OPTIONS.map((s) => ({ label: s.text, value: s.value }));
  const ruleIdOptions = toOptions((filterOptions?.ruleIds || []).map((r) => r.value));
  const agentOptions = toOptions((filterOptions?.agents || []).map((a) => a.value));
  const alertTypeOptions = toOptions((filterOptions?.alertTypes || []).map((a) => a.value));
  const assigneeOptions = toOptions((filterOptions?.assignees || []).map((a) => a.value));
  const customRangeInvalid = Boolean(customStart && customEnd && !customStart.isBefore(customEnd));
  const levelRangeInvalid = filters.levelMin != null && filters.levelMax != null && filters.levelMin > filters.levelMax;
  const hasPendingChanges = draftSignature !== appliedSignature;
  const apply = () => {
    if (!levelRangeInvalid) {
      setAppliedSignature(draftSignature);
      onApply();
    }
  };

  const formatTimeRangeDisplay = () => {
    if (timeRange.mode === 'absolute') {
      return `${new Date(timeRange.from).toLocaleString()} - ${new Date(timeRange.to).toLocaleString()}`;
    }
    const range = QUICK_TIME_RANGES.find((r) => r.start === timeRange.from && r.end === timeRange.to);
    return range ? range.label : `${timeRange.from} to ${timeRange.to}`;
  };

  return (
    <EuiPanel paddingSize="s" hasShadow={false} hasBorder className="wamFilterBar">
      <EuiFlexGroup gutterSize="s" alignItems="flexStart" wrap className="wamQueryRow">
        <EuiFlexItem className="wamQueryRow__query">
          <EuiFormRow
            label="Query"
            helpText="Lucene syntax. Combined with the structured filters below using AND."
            fullWidth
          >
            <EuiFieldSearch
              fullWidth
              placeholder='Search all fields, or use Lucene: rule.description:*ssh* AND NOT agent.name:"server1"'
              value={filters.q}
              onChange={(e) => onChange({ ...filters, q: e.target.value })}
              onSearch={apply}
              aria-label="Lucene alert query"
            />
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem grow={false} className="wamQueryRow__time">
          <EuiFormRow label="Time range">
            <EuiPopover
              button={
                <EuiButton className="wamTimeRangeButton" iconType="calendar" onClick={() => setIsTimePopoverOpen((v) => !v)}>
                  {formatTimeRangeDisplay()}
                </EuiButton>
              }
              isOpen={isTimePopoverOpen}
              closePopover={() => setIsTimePopoverOpen(false)}
              panelPaddingSize="m"
            >
              <div className="wamTimePopover">
                <EuiText size="s"><h4>Quick ranges</h4></EuiText>
                <EuiSpacer size="s" />
                {QUICK_TIME_RANGES.map((range) => (
                  <EuiButtonEmpty
                    key={range.label}
                    size="s"
                    onClick={() => {
                      onTimeRangeChange({ from: range.start, to: range.end, mode: 'relative' });
                      setIsTimePopoverOpen(false);
                    }}
                  >
                    {range.label}
                  </EuiButtonEmpty>
                ))}
                <EuiSpacer size="m" />
                <EuiText size="s"><h4>Custom range</h4></EuiText>
                <EuiSpacer size="s" />
                <EuiFormRow
                  fullWidth
                  isInvalid={customRangeInvalid}
                  error={customRangeInvalid ? 'Start must be before end.' : undefined}
                >
                  <EuiDatePickerRange
                    startDateControl={<EuiDatePicker selected={customStart} onChange={setCustomStart} placeholder="Start" showTimeSelect />}
                    endDateControl={<EuiDatePicker selected={customEnd} onChange={setCustomEnd} placeholder="End" showTimeSelect />}
                  />
                </EuiFormRow>
                <EuiSpacer size="s" />
                <EuiButton
                  size="s"
                  fullWidth
                  disabled={!customStart || !customEnd || customRangeInvalid}
                  onClick={() => {
                    if (customStart && customEnd) {
                      onTimeRangeChange({ from: customStart.toISOString(), to: customEnd.toISOString(), mode: 'absolute' });
                      setIsTimePopoverOpen(false);
                    }
                  }}
                >
                  Use custom range
                </EuiButton>
              </div>
            </EuiPopover>
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem grow={false} className="wamQueryRow__apply">
          <EuiFormRow label="Apply filters">
            <EuiButton fill onClick={apply} isLoading={loading} disabled={levelRangeInvalid} iconType="search">
              Apply
            </EuiButton>
          </EuiFormRow>
        </EuiFlexItem>
      </EuiFlexGroup>

      {hasPendingChanges && (
        <EuiText size="xs" color="warning" className="wamFilterPending" aria-live="polite">
          Filters or time range changed. Apply to update the results.
        </EuiText>
      )}

      <EuiSpacer size="m" />

      <EuiFlexGroup gutterSize="s" wrap alignItems="flexEnd" className="wamStructuredFilters">
        <EuiFlexItem grow={false} className="wamStructuredFilters__chips">
          <EuiFormRow label="Status" display="rowCompressed">
            <EuiFilterGroup>
              {statusOptions.map((o) => {
                const active = filters.statuses.includes(o.value as AlertStatus);
                return (
                  <EuiFilterButton
                    key={o.value}
                    hasActiveFilters={active}
                    isSelected={active}
                    className={`wamStatusFilter wamStatusFilter--${o.value}${active ? ' wamStatusFilter--active' : ''}`}
                    data-test-subj={`wamStatusFilter-${o.value}`}
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

        <EuiFlexItem grow={false} className="wamStructuredFilters__chips">
          <EuiFormRow label="SLA" display="rowCompressed">
            <EuiFilterGroup>
              {SLA_QUICK_FILTERS.map((o) => {
                const active = filters.slaState === o.value;
                return (
                  <EuiFilterButton
                    key={o.value}
                    hasActiveFilters={active}
                    isSelected={active}
                    title={o.title}
                    className={`wamSlaFilter wamSlaFilter--${o.value}${active ? ' wamSlaFilter--active' : ''}`}
                    data-test-subj={`wamSlaFilter-${o.value}`}
                    onClick={() => onChange({ ...filters, slaState: active ? undefined : o.value })}
                  >
                    {o.label}
                  </EuiFilterButton>
                );
              })}
            </EuiFilterGroup>
          </EuiFormRow>
        </EuiFlexItem>

        <EuiFlexItem className="wamStructuredFilters__item wamStructuredFilters__item--narrow">
          <EuiFormRow label="Level min" display="rowCompressed" isInvalid={levelRangeInvalid} error={levelRangeInvalid ? 'Minimum must not exceed maximum.' : undefined}>
            <EuiFieldNumber
              compressed
              min={filterOptions?.levelRange.min ?? 0}
              max={filterOptions?.levelRange.max ?? 15}
              value={filters.levelMin ?? ''}
              isInvalid={levelRangeInvalid}
              onChange={(e) => onChange({ ...filters, levelMin: e.target.value === '' ? undefined : Number(e.target.value) })}
            />
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem className="wamStructuredFilters__item wamStructuredFilters__item--narrow">
          <EuiFormRow label="Level max" display="rowCompressed" isInvalid={levelRangeInvalid}>
            <EuiFieldNumber
              compressed
              min={filterOptions?.levelRange.min ?? 0}
              max={filterOptions?.levelRange.max ?? 15}
              value={filters.levelMax ?? ''}
              isInvalid={levelRangeInvalid}
              onChange={(e) => onChange({ ...filters, levelMax: e.target.value === '' ? undefined : Number(e.target.value) })}
            />
          </EuiFormRow>
        </EuiFlexItem>

        <EuiFlexItem className="wamStructuredFilters__item">
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

        <EuiFlexItem className="wamStructuredFilters__item">
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

        <EuiFlexItem className="wamStructuredFilters__item">
          <EuiFormRow label="Alert type" display="rowCompressed">
            <EuiComboBox
              placeholder="Any type"
              options={alertTypeOptions}
              selectedOptions={toOptions(filters.alertTypes)}
              onChange={(selected) => onChange({ ...filters, alertTypes: selected.map((s) => s.label) })}
              compressed
            />
          </EuiFormRow>
        </EuiFlexItem>

        <EuiFlexItem className="wamStructuredFilters__item">
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

        <EuiFlexItem className="wamStructuredFilters__item">
          <EuiFormRow label="Enrichment verdict" display="rowCompressed">
            <EuiSelect
              compressed
              options={ENRICHMENT_VERDICT_OPTIONS}
              value={filters.enrichmentVerdict || ''}
              onChange={(e) => onChange({ ...filters, enrichmentVerdict: (e.target.value || undefined) as EnrichmentVerdictFilter | undefined })}
              aria-label="Filter by stored enrichment verdict"
              data-test-subj="wamEnrichmentVerdictFilter"
            />
          </EuiFormRow>
        </EuiFlexItem>

        <EuiFlexItem className="wamStructuredFilters__item">
          <EuiFormRow label="Disposition" display="rowCompressed">
            <EuiComboBox
              placeholder="Any"
              options={DISPOSITION_OPTIONS}
              selectedOptions={DISPOSITION_OPTIONS.filter((option) => (filters.disposition || []).includes(option.value!))}
              onChange={(selected) => onChange({ ...filters, disposition: selected.map((option) => option.value!) })}
              isClearable
              compressed
              data-test-subj="wamDispositionFilter"
            />
          </EuiFormRow>
        </EuiFlexItem>

        <EuiFlexItem className="wamStructuredFilters__item">
          <EuiFormRow label="Asset criticality" display="rowCompressed">
            <EuiComboBox
              placeholder="Any"
              options={ASSET_CRITICALITY_OPTIONS}
              selectedOptions={ASSET_CRITICALITY_OPTIONS.filter((option) => (filters.assetCriticality || []).includes(option.value!))}
              onChange={(selected) => onChange({ ...filters, assetCriticality: selected.map((option) => option.value!) })}
              isClearable
              compressed
              data-test-subj="wamAssetCriticalityFilter"
            />
          </EuiFormRow>
        </EuiFlexItem>

        <EuiFlexItem grow={false} className="wamStructuredFilters__refresh">
          <EuiFormRow hasEmptyLabelSpace display="rowCompressed">
            <EuiSwitch label="Auto refresh every 5 minutes" checked={autoRefreshEnabled} onChange={onToggleAutoRefresh} compressed />
          </EuiFormRow>
        </EuiFlexItem>
      </EuiFlexGroup>
    </EuiPanel>
  );
};
