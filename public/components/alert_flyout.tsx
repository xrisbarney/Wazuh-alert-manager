import { useTerminology } from '../terminology';
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  EuiFlyout,
  EuiFlyoutHeader,
  EuiFlyoutBody,
  EuiTitle,
  EuiSpacer,
  EuiFormRow,
  EuiCodeBlock,
  EuiText,
  EuiButtonEmpty,
  EuiFlexGroup,
  EuiFlexItem,
  EuiButtonIcon,
  EuiToolTip,
  EuiCallOut,
  EuiBasicTable,
  EuiFieldSearch,
  EuiBadge,
  EuiPanel,
} from '@elastic/eui';
import { Alert, AiAnalysis, AlertEnrichment, ThreatMatch, extractIndicators } from '../../common';
import { IndicatorGroups, CopyValueButton, indicatorsAsText } from './indicator_list';
import { EnrichmentPanel } from './enrichment_panel';
import { AssetBadge } from './asset_badge';
import { AssetContextChips } from './asset_context_chips';
import { NativeCaseChip, nativeCaseVisible } from './native_case_chip';
import { AlertsApiService } from '../services/api';
import { StatusBadge, SeverityBadge, DispositionBadge } from './status_badge';
import { StatusButtonGroup } from './status_button_group';
import { formatAbsolute } from '../design';
import { SlaDue } from './sla_due';
import { SlaEscalated } from './sla_escalated';
import { PrecedentCallout } from './precedent_callout';
import { CommentsThread } from './comments_thread';
import { HistoryList } from './history_list';
import { RelatedAlertsPanel } from './related_alerts_panel';
import { AiAnalysisTab } from './ai_analysis_tab';
import { AssigneePicker } from './assignee_picker';
import { CasePicker } from './case_picker';
import { FlyoutNav, FlyoutNavGroup, useFlyoutNavCollapsed } from './flyout_nav';
import { MetaGrid, MetaGroup, MetaRow } from './meta_grid';

/**
 * Alert flyout sections (step 11.1): the former `EuiTabbedContent` tabs as
 * the same left rail the case flyout uses (`flyout_nav.tsx`). Ids are the
 * old tab ids so anything keyed on them keeps working; the former `details`
 * tab is `fields` (its visible label was already "Fields"). Every item
 * carries `data-test-subj="wamAlertNav-<id>"` in both the expanded list and
 * the collapsed rail.
 */
export const ALERT_SECTION_IDS = ['overview', 'related', 'enrichment', 'ai', 'comments', 'history', 'fields', 'raw'] as const;

export type AlertSectionId = typeof ALERT_SECTION_IDS[number];

export function isAlertSectionId(value: string | null | undefined): value is AlertSectionId {
  return (ALERT_SECTION_IDS as readonly string[]).includes(String(value));
}

/** Overview | Investigation | Work | Detail; membership covers every section exactly once (asserted by the unit test). */
export const ALERT_NAV_GROUPS: readonly FlyoutNavGroup<AlertSectionId>[] = [
  { id: 'overview', items: ['overview'] },
  { id: 'investigation', items: ['related', 'enrichment', 'ai'] },
  { id: 'work', items: ['comments'] },
  { id: 'detail', items: ['history', 'fields', 'raw'] },
];

/** Icons from the case set where the meaning matches (`CASE_SECTION_ICONS`). */
export const ALERT_SECTION_ICONS: Record<AlertSectionId, string> = {
  overview: 'inspect',
  related: 'link',
  enrichment: 'crosshairs',
  ai: 'compute',
  comments: 'editorComment',
  history: 'history',
  fields: 'list',
  raw: 'editorCodeBlock',
};

/** `localStorage` key holding the analyst's collapsed-rail preference for the alert flyout. */
export const ALERT_NAV_COLLAPSED_KEY = 'wam.alertNav.collapsed';

/** Section label; `unitsLabel` is the terminology plural ("alerts" / "findings"). */
export function alertSectionLabel(id: AlertSectionId, unitsLabel: string = 'alerts'): string {
  switch (id) {
    case 'overview':
      return 'Overview';
    case 'related':
      return `Related ${unitsLabel}`;
    case 'enrichment':
      return 'Enrichment';
    case 'ai':
      return 'AI analysis';
    case 'comments':
      return 'Comments';
    case 'history':
      return 'History';
    case 'fields':
      return 'Fields';
    case 'raw':
      return 'Raw JSON';
  }
}

export interface AlertSectionCounts {
  /** Known once the Comments section has fetched its thread; null before that. */
  comments?: number | null;
  /** Known once the Related section has fetched its linked list; null before that. */
  related?: number | null;
  /** Stored enrichment verdicts on the record (`enrichment.items`), known up front. */
  enrichment?: number | null;
}

/** Badge text for a section: comments / related / enrichment once known and non-zero, nothing otherwise. */
export function alertSectionCount(id: AlertSectionId, counts: AlertSectionCounts): string | null {
  switch (id) {
    case 'comments':
    case 'related':
    case 'enrichment': {
      const value = counts[id];
      return typeof value === 'number' && Number.isFinite(value) && value > 0 ? String(value) : null;
    }
    default:
      return null;
  }
}

interface Props {
  alert: Alert;
  apiService: AlertsApiService;
  updating: boolean;
  onClose: () => void;
  onStatusChange: (status: string) => void;
  onAssigneeChange: (assignee: string | null) => void;
  onCaseChange: (caseId: string | null) => void;
  onError: (message: string) => void;
  onToast?: (title: string, color: 'success' | 'danger' | 'primary', text?: string) => void;
  onOpenCase?: (caseId: string) => void;
  onOpenAlert?: (alert: Alert) => void;
  onAnalysisGenerated?: (alertId: string, analysis: AiAnalysis) => void;
  /** A per-alert lookup stored new verdicts on the record (step 6.3). */
  onEnrichmentUpdated?: (alertId: string, enrichment: AlertEnrichment | null) => void;
  onAddFilter?: (field: string, value: unknown, negate: boolean) => void;
}

interface FieldRow { field: string; value: unknown; display: string; operational: boolean; }

/** Badge colour for a stored enrichment verdict (same mapping as the queue badge). */
const ENRICHMENT_VERDICT_COLOR: Record<string, string> = {
  malicious: 'danger',
  suspicious: 'warning',
  clean: 'success',
  unknown: 'hollow',
};

/**
 * Flatten a document into one row per leaf. Scalar lists keep one row per
 * element under the same path (so each `rule.groups` value stays filterable);
 * objects inside a list get an index (`wazuh.threat.enrichments[1].indicator.name`)
 * so every element keeps its own rows instead of collapsing onto the last one.
 */
export function flattenFields(value: any, operational: boolean, prefix = '', rows: FieldRow[] = []): FieldRow[] {
  if (Array.isArray(value)) {
    if (value.length === 0) rows.push({ field: prefix, value, display: '[]', operational });
    value.forEach((child, index) => {
      const childPrefix = child != null && typeof child === 'object' ? `${prefix}[${index}]` : prefix;
      flattenFields(child, operational, childPrefix, rows);
    });
  } else if (value != null && typeof value === 'object') {
    if (Object.keys(value).length === 0) rows.push({ field: prefix, value, display: '{}', operational });
    for (const [key, child] of Object.entries(value)) flattenFields(child, operational, prefix ? `${prefix}.${key}` : key, rows);
  } else {
    rows.push({
      field: prefix,
      value,
      display: value == null ? '—' : String(value),
      operational,
    });
  }
  return rows;
}

export const AlertFlyout: React.FC<Props> = (props) => {
  const terms = useTerminology();
  return <AlertFlyoutInner {...props} terms={terms} />;
};

const AlertFlyoutInner: React.FC<Props & { terms: ReturnType<typeof useTerminology> }> = ({
  terms,
  alert,
  apiService,
  updating,
  onClose,
  onStatusChange,
  onAssigneeChange,
  onCaseChange,
  onError,
  onToast,
  onOpenCase,
  onOpenAlert,
  onAnalysisGenerated,
  onEnrichmentUpdated,
  onAddFilter,
}) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const [fieldSearch, setFieldSearch] = useState('');
  // Section rail (11.1): the active section survives opening another alert
  // from the Related list, as the uncontrolled tabs did; the fetched counts
  // belong to one alert and reset with it.
  const [activeSection, setActiveSection] = useState<AlertSectionId>('overview');
  const [navCollapsed, toggleNavCollapsed] = useFlyoutNavCollapsed(ALERT_NAV_COLLAPSED_KEY);
  const [commentCount, setCommentCount] = useState<number | null>(null);
  const [relatedCount, setRelatedCount] = useState<number | null>(null);
  useEffect(() => {
    setCommentCount(null);
    setRelatedCount(null);
  }, [alert._id]);
  const selectSection = useCallback((id: AlertSectionId) => setActiveSection(id), []);
  const fieldRows = useMemo(() => {
    // Rows are grouped per path and the indexed operational projection is
    // authoritative: when both the raw document and the projection carry a
    // path, the projection's rows (all of them, for a list) replace the raw
    // rows for that path. Nothing else is deduplicated, so a list with N
    // elements shows N rows.
    const byField = new Map<string, FieldRow[]>();
    const absorb = (list: FieldRow[]) => {
      const grouped = new Map<string, FieldRow[]>();
      for (const row of list) {
        const bucket = grouped.get(row.field) || [];
        bucket.push(row);
        grouped.set(row.field, bucket);
      }
      for (const [field, rows] of grouped) byField.set(field, rows);
    };
    absorb(flattenFields(alert._raw_source || {}, false));
    absorb(flattenFields(alert._source, true));
    absorb(flattenFields({ _id: alert._id, _index: alert._index }, false));
    const query = fieldSearch.trim().toLowerCase();
    const uniqueRows = Array.from(byField.entries())
      .sort((a, b) => a[0].localeCompare(b[0], undefined, { numeric: true }))
      .flatMap(([, rows]) => rows);
    return query
      ? uniqueRows.filter((row) => row.field.toLowerCase().includes(query) || row.display.toLowerCase().includes(query))
      : uniqueRows;
  }, [alert, fieldSearch]);
  // Indicators come from the projected record plus, when a 4.x VirusTotal /
  // Maltiverse sibling alert enriched this one, the verdicts those siblings
  // carry (looked up by `threat.sibling_of`). The lookup is best-effort: a
  // failure only leaves the sibling hints out.
  const [siblingMatches, setSiblingMatches] = useState<ThreatMatch[]>([]);
  useEffect(() => {
    let cancelled = false;
    setSiblingMatches([]);
    Promise.resolve()
      .then(() => apiService.fetchAlertSiblingVerdicts(alert._id))
      .then((res) => { if (!cancelled && Array.isArray(res?.matches)) setSiblingMatches(res.matches); })
      .catch(() => { /* best-effort enrichment */ });
    return () => { cancelled = true; };
  }, [alert._id]);
  const indicators = useMemo(
    () => extractIndicators(alert._source, { siblingMatches }),
    [alert._source, siblingMatches]
  );
  const agentName = alert._source.agent?.name;
  const agentIp = alert._source.agent?.ip;
  const agentLabel = agentName && agentIp ? `${agentName} (${agentIp})` : agentName || agentIp || '—';
  const ruleLevel = typeof alert._source.rule?.level === 'number' ? alert._source.rule.level : null;
  const severityLabel = alert._source.severity_label || null;
  const hasSeverity = ruleLevel !== null || Boolean(severityLabel);
  const title = alert._source.rule?.description || `${terms.Unit} details`;
  const enrichmentVerdict = alert._source.enrichment?.worst_verdict;
  const enrichmentCount = alert._source.enrichment?.items?.length ?? 0;
  const showDue = Boolean(alert._source.reporting?.sla_due_at) && alert._source.status !== 'closed';

  return (
    <EuiFlyout
      onClose={onClose}
      hideCloseButton
      size={isExpanded ? '95vw' : 'l'}
      aria-labelledby="alert-details-flyout"
      className={`wamAlertFlyout${isExpanded ? ' wamAlertFlyout--expanded' : ''}`}
    >
      <EuiFlyoutHeader hasBorder>
        {/* 11.6: the actions sit on the title row (right-aligned, as the case
            flyout's Report / Collapse / Close) so a wide asset chip row never
            pushes them onto a third header line. */}
        <EuiFlexGroup alignItems="center" gutterSize="s" responsive={false} wrap className="wamAlertFlyoutTitleRow">
          <EuiFlexItem className="wamAlertFlyoutTitleRow__title">
            <EuiTitle size="m">
              <h2 id="alert-details-flyout" className="wamAlertFlyoutTitle" data-test-subj="wamAlertFlyoutTitle">{title}</h2>
            </EuiTitle>
          </EuiFlexItem>
          <EuiFlexItem grow={false} className="wamAlertFlyoutActions" data-test-subj="wamAlertFlyoutActions">
            <EuiFlexGroup alignItems="center" gutterSize="xs" responsive={false}>
              {alert._source.case_id ? (
                <EuiFlexItem grow={false}>
                  <EuiButtonEmpty
                    size="s"
                    iconType="folderOpen"
                    iconSide="left"
                    data-test-subj="wamAlertFlyoutOpenCase"
                    onClick={() => onOpenCase?.(alert._source.case_id!)}
                  >
                    Open case
                  </EuiButtonEmpty>
                </EuiFlexItem>
              ) : null}
              <EuiFlexItem grow={false}>
                <EuiButtonEmpty
                  size="s"
                  iconType={isExpanded ? 'minimize' : 'expand'}
                  iconSide="left"
                  aria-label={isExpanded ? 'Collapse' : 'Expand to full screen'}
                  data-test-subj="wamAlertFlyoutExpand"
                  onClick={() => setIsExpanded((v) => !v)}
                >
                  {isExpanded ? 'Collapse' : 'Expand'}
                </EuiButtonEmpty>
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiButtonEmpty size="s" iconType="cross" iconSide="left" aria-label="Close details" data-test-subj="wamAlertFlyoutClose" onClick={onClose}>
                  Close
                </EuiButtonEmpty>
              </EuiFlexItem>
            </EuiFlexGroup>
          </EuiFlexItem>
        </EuiFlexGroup>
        <EuiSpacer size="s" />
        <EuiFlexGroup alignItems="center" gutterSize="m" responsive={false} wrap className="wamAlertFlyoutMeta" data-test-subj="wamAlertFlyoutMeta">
          <EuiFlexItem grow={false}>
            <span className="wamStatusCell">
              <StatusBadge status={alert._source.status} />
              <DispositionBadge disposition={alert._source.disposition} status={alert._source.status} className="wamDispositionQueueBadge" testSubj="wamAlertFlyoutDisposition" />
            </span>
          </EuiFlexItem>
          {hasSeverity ? (
            <EuiFlexItem grow={false} data-test-subj="wamAlertFlyoutSeverity">
              <SeverityBadge level={ruleLevel} label={severityLabel} />
            </EuiFlexItem>
          ) : null}
          <EuiFlexItem grow={false}>
            <EuiText size="xs" color="subdued" className="wamAlertFlyoutMeta__text" data-test-subj="wamAlertFlyoutAgent">
              {agentLabel}
            </EuiText>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiText size="xs" color="subdued" className="wamAlertFlyoutMeta__text" data-test-subj="wamAlertFlyoutTimestamp">
              {formatAbsolute(alert._source['@timestamp'])}
            </EuiText>
          </EuiFlexItem>
          {showDue ? (
            <EuiFlexItem grow={false}>
              <SlaDue dueAt={alert._source.reporting!.sla_due_at!} status={alert._source.status} label="Resolve" testSubj="wamAlertFlyoutDue" />
            </EuiFlexItem>
          ) : null}
          <EuiFlexItem grow={false}>
            <AssetContextChips
              apiService={apiService}
              agentId={alert._source.agent?.id}
              agentName={agentName}
              testSubj="wamAlertAssetContext"
            />
          </EuiFlexItem>
        </EuiFlexGroup>
      </EuiFlyoutHeader>
      <EuiFlyoutBody>
        {(() => {
          // Only the active section mounts (as the tabs did), so the
          // Comments / Related lists fetch when first opened and report
          // their totals to the rail.
          const sections: Record<AlertSectionId, React.ReactNode> = {
            overview: (
                <div className="wamAlertFlyoutTab" data-test-subj="wamAlertOverview">
                  <PrecedentCallout alertId={alert._id} apiService={apiService} />
                  {/* 11.6: the editable row comes first (the first thing the analyst touches);
                      the read-only facts follow as a grouped meta grid. The two pickers carry
                      the Overview subjects their former read-only rows had. */}
                  <EuiFlexGroup gutterSize="m" alignItems="flexStart" wrap className="wamAlertFormGrid" data-test-subj="wamAlertFormGrid">
                    <EuiFlexItem grow={false}>
                      <EuiFormRow label="Status" display="rowCompressed">
                        <StatusButtonGroup
                          status={alert._source.status}
                          disabled={updating}
                          idPrefix={`fly-${alert._id}`}
                          onChange={(s) => onStatusChange(s)}
                          compressed
                        />
                      </EuiFormRow>
                    </EuiFlexItem>
                    <EuiFlexItem className="wamAlertFormGrid__picker">
                      <EuiFormRow label="Assigned to" display="rowCompressed" fullWidth data-test-subj="wamAlertOverviewAssignee">
                        <AssigneePicker
                          apiService={apiService}
                          value={alert._source.assigned_to}
                          onChange={onAssigneeChange}
                          fullWidth
                          compressed
                        />
                      </EuiFormRow>
                    </EuiFlexItem>
                    <EuiFlexItem className="wamAlertFormGrid__picker">
                      <EuiFormRow label="Case" display="rowCompressed" fullWidth data-test-subj="wamAlertOverviewCase">
                        <CasePicker
                          apiService={apiService}
                          value={alert._source.case_id}
                          onChange={(caseId) => onCaseChange(caseId)}
                          fullWidth
                          compressed
                        />
                      </EuiFormRow>
                    </EuiFlexItem>
                  </EuiFlexGroup>

                  <EuiSpacer size="m" />

                  <MetaGrid className="wamMetaList" data-test-subj="wamAlertMeta">
                    <MetaGroup title="Detection" data-test-subj="wamAlertMetaDetection">
                      <MetaRow label="Rule">
                        {alert._source.rule?.description || '—'}
                        {alert._source.rule?.id ? <span className="wamMetaList__muted"> (rule {alert._source.rule.id})</span> : null}
                      </MetaRow>
                      <MetaRow label={ruleLevel !== null ? 'Level' : 'Severity'}>
                        {hasSeverity ? (
                          <span className="wamMetaList__inline">
                            <SeverityBadge level={ruleLevel} label={severityLabel} />
                            {ruleLevel !== null ? <span className="wamMetaList__muted">Level {ruleLevel}</span> : null}
                          </span>
                        ) : (
                          '—'
                        )}
                      </MetaRow>
                      <MetaRow label="Agent">
                        <span className="wamMetaList__inline">
                          {agentLabel}
                          <AssetBadge asset={alert._source.asset} className="wamAssetFlyoutBadge" testSubj="wamAssetFlyoutBadge" />
                        </span>
                      </MetaRow>
                      {(alert._source.asset?.groups?.length || alert._source.asset?.tags?.length) ? (
                        <MetaRow label="Asset">
                          <span className="wamAssetChips" data-test-subj="wamAssetChips">
                            {(alert._source.asset?.groups || []).map((group) => (
                              <EuiBadge key={`g-${group}`} color="hollow" iconType="users" title={`Agent group ${group}`}>{group}</EuiBadge>
                            ))}
                            {(alert._source.asset?.tags || []).map((tag) => (
                              <EuiBadge key={`t-${tag}`} color="default" iconType="tag" title={`Asset tag ${tag}`}>{tag}</EuiBadge>
                            ))}
                          </span>
                        </MetaRow>
                      ) : null}
                      <MetaRow label="Timestamp">{formatAbsolute(alert._source['@timestamp'])}</MetaRow>
                      <MetaRow label="Manager">{alert._source.manager?.name || '—'}</MetaRow>
                    </MetaGroup>

                    <MetaGroup title="Triage" data-test-subj="wamAlertMetaTriage">
                      {showDue && (
                        <MetaRow label="Due" className="wamSlaDueLine" data-test-subj="wamAlertDueLine">
                          <SlaDue dueAt={alert._source.reporting!.sla_due_at!} status={alert._source.status} label="Resolve" testSubj="wamAlertOverviewDue" />
                          {alert._source.reporting!.assign_due_at && !alert._source.assigned_to && (
                            <SlaDue dueAt={alert._source.reporting!.assign_due_at} status={alert._source.status} label="Assign" testSubj="wamAlertFlyoutAssignDue" />
                          )}
                        </MetaRow>
                      )}
                      {alert._source.sla?.escalated?.length ? (
                        <MetaRow label="Escalated">
                          <SlaEscalated sla={alert._source.sla} apiService={apiService} testSubj="wamAlertFlyoutEscalated" />
                        </MetaRow>
                      ) : null}
                      {alert._source.status === 'closed' && (alert._source.disposition || alert._source.closure_reason) ? (
                        <MetaRow label="Closure reason" data-test-subj="wamAlertClosureRow">
                          <span className="wamMetaList__inline">
                            <DispositionBadge disposition={alert._source.disposition} status={alert._source.status} className="wamDispositionQueueBadge" testSubj="wamAlertOverviewDisposition" />
                            {alert._source.closure_reason ? (
                              <span className="wamClosureReason" data-test-subj="wamAlertClosureReason">{alert._source.closure_reason}</span>
                            ) : null}
                          </span>
                        </MetaRow>
                      ) : null}
                      <MetaRow label="Enrichment verdict" data-test-subj="wamAlertOverviewEnrichment">
                        {enrichmentVerdict ? (
                          <span className="wamMetaList__inline">
                            <EuiBadge color={ENRICHMENT_VERDICT_COLOR[enrichmentVerdict] || 'hollow'}>{enrichmentVerdict}</EuiBadge>
                            <span className="wamMetaList__muted">
                              {enrichmentCount} stored verdict{enrichmentCount === 1 ? '' : 's'}
                            </span>
                          </span>
                        ) : (
                          <span className="wamMetaList__muted">Not looked up</span>
                        )}
                      </MetaRow>
                      {nativeCaseVisible(alert._source.native_case) ? (
                        // Step 2.6: read-only wazuh.case.* projection, 5.0 builds only; never written back.
                        <MetaRow label="Native case">
                          <NativeCaseChip nativeCase={alert._source.native_case} appUrl={(path) => apiService.appUrl(path)} testSubj="wamAlertNativeCase" />
                        </MetaRow>
                      ) : null}
                    </MetaGroup>

                    <MetaGroup title="Record" data-test-subj="wamAlertMetaRecord">
                      <MetaRow label={`${terms.Unit} ID`} className="wamAlertId">{alert._id}</MetaRow>
                      {alert._source.updated_by && (
                        <MetaRow label="Last updated">
                          {alert._source.updated_by} at {formatAbsolute(alert._source.updated_at)}
                        </MetaRow>
                      )}
                    </MetaGroup>
                  </MetaGrid>

                  <EuiSpacer size="m" />

                  <EuiPanel hasBorder paddingSize="m" className="wamIndicatorsBlock" data-test-subj="wamAlertIndicators">
                    <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false} className="wamPanelHeader">
                      <EuiFlexItem>
                        <EuiTitle size="xs"><h3>Indicators</h3></EuiTitle>
                      </EuiFlexItem>
                      {indicators.length > 0 && (
                        <EuiFlexItem grow={false}>
                          <EuiToolTip content="Copy all values, one per line">
                            <span>
                              <CopyValueButton value={indicatorsAsText(indicators)} label="Copy all indicators" />
                            </span>
                          </EuiToolTip>
                        </EuiFlexItem>
                      )}
                    </EuiFlexGroup>
                    <EuiSpacer size="s" />
                    <EuiText size="xs" color="subdued">
                      <p>
                        Extracted from the projected record. Verdict badges are native hints (VirusTotal / Maltiverse
                        sibling alerts, CDB IOC rules, Wazuh 5.0 engine enrichments); GeoIP comes from the native
                        database and may be stale.
                      </p>
                    </EuiText>
                    <EuiSpacer size="s" />
                    <IndicatorGroups indicators={indicators} />
                  </EuiPanel>
                </div>
            ),
            comments: (
                <div className="wamAlertFlyoutTab">
                  <CommentsThread
                    apiService={apiService}
                    target={{ alertId: alert._id }}
                    onError={onError}
                    onToast={onToast}
                    onCountChanged={setCommentCount}
                  />
                </div>
            ),
            related: (
                <div className="wamAlertFlyoutTab">
                  <RelatedAlertsPanel
                    alertId={alert._id}
                    apiService={apiService}
                    onError={onError}
                    onToast={onToast}
                    onOpenAlert={(a) => onOpenAlert?.(a)}
                    onCountChanged={setRelatedCount}
                  />
                </div>
            ),
            enrichment: (
                <div className="wamAlertFlyoutTab">
                  <EnrichmentPanel
                    indicators={indicators}
                    stored={alert._source.enrichment}
                    apiService={apiService}
                    lookup={async (type, value, refresh) => {
                      const res = await apiService.lookupAlertEnrichment(alert._id, { type, value, refresh });
                      // No results = nothing was stored; the record is unchanged.
                      if (res.results.length) onEnrichmentUpdated?.(alert._id, res.enrichment);
                      return res;
                    }}
                  />
                </div>
            ),
            ai: (
                <div className="wamAlertFlyoutTab">
                  <AiAnalysisTab
                    analysis={alert._source.ai_analysis}
                    apiService={apiService}
                    onGenerate={() => apiService.analyzeAlert(alert._id) as Promise<AiAnalysis>}
                    onGenerated={(analysis) => onAnalysisGenerated?.(alert._id, analysis)}
                    onError={onError}
                    onToast={onToast}
                    emptyMessage="No AI analysis generated yet for this alert."
                  />
                </div>
            ),
            history: (
                <div className="wamAlertFlyoutTab">
                  <HistoryList history={alert._source.history} />
                </div>
            ),
            fields: (
                <div className="wamAlertFlyoutTab">
                  <EuiFieldSearch
                    fullWidth
                    compressed
                    placeholder="Search fields or values"
                    value={fieldSearch}
                    onChange={(event) => setFieldSearch(event.target.value)}
                    aria-label="Search alert fields and values"
                  />
                  <EuiSpacer size="s" />
                  <EuiText size="xs" color="subdued">
                    {fieldRows.length.toLocaleString()} matching field{fieldRows.length === 1 ? '' : 's'}. Only operational fields can be added to the alert query.
                  </EuiText>
                  <EuiSpacer size="s" />
                  <EuiBasicTable
                    className="wamDocumentFields"
                    tableCaption="Alert document fields"
                    compressed
                    items={fieldRows}
                    columns={[
                      { field: 'field', name: 'Field', render: (value: string) => <span className="wamFieldName">{value}</span> },
                      { field: 'display', name: 'Value', render: (value: string) => <span className="wamFieldValue">{value}</span> },
                      { field: 'operational', name: 'Source', width: '105px', render: (value: boolean) => <EuiBadge color={value ? 'primary' : 'hollow'}>{value ? 'Operational' : 'Raw only'}</EuiBadge> },
                      {
                        name: 'Filter', width: '82px', align: 'right',
                        render: (row: FieldRow) => onAddFilter && row.operational && !row.field.includes('[') && row.value != null && typeof row.value !== 'object' ? (
                          <>
                            <EuiToolTip content="Filter for this value"><EuiButtonIcon iconType="plusInCircle" aria-label={`Filter for ${row.field}`} onClick={() => onAddFilter(row.field, row.value, false)} /></EuiToolTip>
                            <EuiToolTip content="Exclude this value"><EuiButtonIcon iconType="minusInCircle" aria-label={`Exclude ${row.field}`} onClick={() => onAddFilter(row.field, row.value, true)} /></EuiToolTip>
                          </>
                        ) : null,
                      },
                    ] as any}
                  />
                </div>
            ),
            raw: (
                <div className="wamAlertFlyoutTab">
                  {alert._source_available === false && (
                    <>
                      <EuiCallOut
                        size="s"
                        color="warning"
                        iconType="clock"
                        title="Original Wazuh evidence is no longer available"
                      >
                        The compact operational record is retained, but its native Wazuh source document could not be retrieved.
                      </EuiCallOut>
                      <EuiSpacer size="s" />
                    </>
                  )}
                  <EuiCodeBlock language="json" isCopyable>
                    {JSON.stringify(alert._raw_source || alert._source, null, 2)}
                  </EuiCodeBlock>
                </div>
            ),
          };
          const counts: AlertSectionCounts = { comments: commentCount, related: relatedCount, enrichment: enrichmentCount };
          return (
            <EuiFlexGroup gutterSize="l" responsive={false} className="wamAlertBody">
              <EuiFlexItem grow={false} className={`wamAlertNavColumn${navCollapsed ? ' wamAlertNavColumn--collapsed' : ''}`}>
                <FlyoutNav<AlertSectionId>
                  sections={ALERT_SECTION_IDS}
                  groups={ALERT_NAV_GROUPS}
                  icons={ALERT_SECTION_ICONS}
                  label={(id) => alertSectionLabel(id, terms.units)}
                  count={(id) => alertSectionCount(id, counts)}
                  activeId={activeSection}
                  onSelect={selectSection}
                  testSubj="wamAlertNav"
                  ariaLabel={`${terms.Unit} sections`}
                  collapsed={navCollapsed}
                  onToggleCollapsed={toggleNavCollapsed}
                />
              </EuiFlexItem>
              <EuiFlexItem className="wamAlertContent">
                <div className="wamAlertSection" data-test-subj={`wamAlertSection-${activeSection}`}>
                  {sections[activeSection]}
                </div>
              </EuiFlexItem>
            </EuiFlexGroup>
          );
        })()}
      </EuiFlyoutBody>
    </EuiFlyout>
  );
};
