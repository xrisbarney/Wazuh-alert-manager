import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  EuiFlyout,
  EuiFlyoutHeader,
  EuiFlyoutBody,
  EuiTabbedContent,
  EuiDescriptionList,
  EuiDescriptionListTitle,
  EuiDescriptionListDescription,
  EuiSpacer,
  EuiButtonGroup,
  EuiLoadingSpinner,
  EuiButtonIcon,
  EuiText,
  EuiTextArea,
  EuiFieldText,
  EuiButton,
  EuiFormRow,
  EuiToolTip,
  EuiModal,
  EuiModalHeader,
  EuiModalHeaderTitle,
  EuiModalBody,
  EuiModalFooter,
  EuiCallOut,
  EuiCheckbox,
  EuiButtonEmpty,
} from '@elastic/eui';
import { Alert, Case, AiAnalysis, AttackGraph } from '../../common';
import { AlertsApiService } from '../services/api';
import { StatusBadge, CASE_SEVERITY_OPTIONS } from './status_badge';
import { statusLabel, formatAbsolute } from '../design';
import { CommentsThread } from './comments_thread';
import { HistoryList } from './history_list';
import { AssigneePicker } from './assignee_picker';
import { AttackPathView } from './attack_path_view';
import { AlertMultiPicker } from './alert_multi_picker';
import { LinkedAlertsTable, LinkedAlert } from './linked_alerts_table';
import { useCaseTheme } from './case_theme';
import { AiAnalysisTab } from './ai_analysis_tab';

interface Props {
  caseId: string;
  apiService: AlertsApiService;
  onClose: () => void;
  onError: (message: string) => void;
  onToast?: (title: string, color: 'success' | 'danger' | 'primary', text?: string) => void;
  onChanged: () => void;
  onOpenAlert?: (alert: Alert) => void;
}

const FILTER_PAGE = 25;
// Tabs that use the console design and follow its Light/Dark choice.
const CONSOLE_TABS = new Set(['alerts', 'attack-path']);

function headerRange(graph: AttackGraph | null) {
  const times = (graph?.hops || []).map((h) => Date.parse(h.timestamp)).filter(Number.isFinite);
  if (!times.length) return null;
  const a = new Date(Math.min(...times));
  const b = new Date(Math.max(...times));
  const day = (d: Date) => d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
  const time = (d: Date) => d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  return day(a) === day(b)
    ? { day: day(a), times: `${time(a)} – ${time(b)}` }
    : { day: `${day(a)} – ${day(b)}`, times: `${time(a)} – ${time(b)}` };
}

// A graph hop carries enough of the alert (and its case relationship) for the
// Linked Alerts table and its actions when the alert isn't on the loaded page.
function hopToLinkedAlert(hop: AttackGraph['hops'][number]): LinkedAlert {
  return {
    _id: hop.alertId,
    _source: {
      '@timestamp': hop.timestamp,
      status: (hop.status || undefined) as any,
      agent: hop.host ? { name: hop.host } : undefined,
      rule: { id: hop.ruleId || undefined, description: hop.ruleDescription, level: hop.level },
    },
    _evidence: hop.evidence ? { ...hop.evidence, alert_id: hop.alertId } : undefined,
  };
}

function describeCaseUpdate(payload: Record<string, any>): string {
  if (payload.status != null) {
    if (payload.status === 'closed') return 'Case closed';
    if (payload.status === 'open') return 'Case reopened';
    return `Case set to ${statusLabel(payload.status)}`;
  }
  if (payload.assignedTo !== undefined) return payload.assignedTo ? `Assigned to ${payload.assignedTo}` : 'Unassigned';
  if (payload.addAlertIds?.length) return 'Alert added to case';
  if (payload.removeAlertIds?.length) return 'Alert removed from case';
  if (payload.severity != null) return 'Severity updated';
  return 'Case updated';
}

export const CaseFlyout: React.FC<Props> = ({ caseId, apiService, onClose, onError, onToast, onChanged, onOpenAlert }) => {
  const [loading, setLoading] = useState(true);
  const [caseDoc, setCaseDoc] = useState<Case | null>(null);
  const [alerts, setAlerts] = useState<Array<Alert & { _evidence?: any }>>([]);
  const [busy, setBusy] = useState(false);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [isExpanded, setIsExpanded] = useState(false);
  const [closeConfirm, setCloseConfirm] = useState<{ openAlerts: Alert[]; excluded: Set<string> } | null>(null);
  const [canManageLifecycle, setCanManageLifecycle] = useState(false);
  const [holdAlert, setHoldAlert] = useState<(Alert & { _evidence?: any }) | null>(null);
  const [holdReason, setHoldReason] = useState('');
  const [evidenceDetail, setEvidenceDetail] = useState<any>(null);
  const [evidenceNextCursor, setEvidenceNextCursor] = useState<string | null>(null);
  const [evidenceTotal, setEvidenceTotal] = useState(0);
  const [loadingMoreEvidence, setLoadingMoreEvidence] = useState(false);
  const [evidencePageIndex, setEvidencePageIndex] = useState(0);
  const [evidencePages, setEvidencePages] = useState<Array<Array<Alert & { _evidence?: any }>>>([]);
  const [evidencePageCursors, setEvidencePageCursors] = useState<Array<string | null>>([null]);
  const [activeTab, setActiveTab] = useState('overview');
  const [theme, setTheme] = useCaseTheme();
  // Attack graph data, shared by the header's date range, the Attack Graph
  // tab and graph-filtered Linked Alerts. Reloaded after every case load.
  const [graph, setGraph] = useState<AttackGraph | null>(null);
  const [graphLoading, setGraphLoading] = useState(false);
  const [graphVersion, setGraphVersion] = useState(0);
  const [linkedFilter, setLinkedFilter] = useState<{ ids: string[]; label: string } | null>(null);
  const [filterPage, setFilterPage] = useState(0);

  const load = useCallback(async () => {
    try {
      setLoading(true);
      const [res, capabilities]: any[] = await Promise.all([
        apiService.fetchCase(caseId),
        apiService.fetchSystemCapabilities(),
      ]);
      setCaseDoc(res.case);
      const relationships = res.evidence?.evidence || [];
      const byAlert = new Map(relationships.map((item: any) => [item.alert_id, item]));
      const expanded: Array<Alert & { _evidence?: any }> = (res.alerts || []).map((item: Alert) => ({
        ...item,
        _evidence: byAlert.get(item._id),
      }));
      const liveIds = new Set(expanded.map((item) => item._id));
      for (const relationship of relationships) {
        if (!liveIds.has(relationship.alert_id)) {
          expanded.push({
            _id: relationship.alert_id,
            _source: relationship.snapshot || {},
            _evidence: relationship,
          } as any);
        }
      }
      setAlerts(expanded);
      setEvidencePages([expanded]);
      setEvidencePageCursors([null, res.evidence?.nextCursor || null]);
      setEvidencePageIndex(0);
      setEvidenceNextCursor(res.evidence?.nextCursor || null);
      setEvidenceTotal(res.evidence?.total || expanded.length);
      setCanManageLifecycle(Boolean(capabilities?.canManageLifecycle));
      setTitle(res.case.title);
      setDescription(res.case.description || '');
      setGraphVersion((v) => v + 1);
    } catch (e) {
      onError('Failed to load case');
    } finally {
      setLoading(false);
    }
  }, [caseId]);

  const changeEvidencePage = async (nextPageIndex: number) => {
    if (nextPageIndex < 0) return;
    if (evidencePages[nextPageIndex]) {
      setAlerts(evidencePages[nextPageIndex]);
      setEvidencePageIndex(nextPageIndex);
      setEvidenceNextCursor(evidencePageCursors[nextPageIndex + 1] || null);
      return;
    }
    const cursor = evidencePageCursors[nextPageIndex];
    if (!cursor) return;
    try {
      setLoadingMoreEvidence(true);
      const page = await apiService.fetchCaseEvidence(caseId, cursor, 25);
      const byAlert = new Map(page.evidence.map((item: any) => [item.alert_id, item]));
      const pageAlerts = (page.alerts || page.evidence.map((item: any) => ({
        _id: item.alert_id,
        _source: item.snapshot || {},
      }))).map((item: Alert) => ({ ...item, _evidence: byAlert.get(item._id) }));
      setEvidencePages((current) => {
        const updated = [...current];
        updated[nextPageIndex] = pageAlerts;
        return updated;
      });
      setEvidencePageCursors((current) => {
        const updated = [...current];
        updated[nextPageIndex + 1] = page.nextCursor;
        return updated;
      });
      setAlerts(pageAlerts);
      setEvidencePageIndex(nextPageIndex);
      setEvidenceNextCursor(page.nextCursor);
      setEvidenceTotal((current) => Math.max(current, page.total));
    } catch (e) {
      onError('Failed to load more case evidence');
    } finally {
      setLoadingMoreEvidence(false);
    }
  };

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!graphVersion) return undefined;
    let cancelled = false;
    setGraphLoading(true);
    apiService.fetchAttackPath(caseId)
      .then((res) => { if (!cancelled) setGraph(res); })
      .catch(() => { if (!cancelled) onError('Failed to load attack path'); })
      .finally(() => { if (!cancelled) setGraphLoading(false); });
    return () => { cancelled = true; };
  }, [caseId, graphVersion]);

  const filteredAlerts = useMemo(() => {
    if (!linkedFilter) return null;
    const loaded = new Map(alerts.map((a) => [a._id, a]));
    const hops = new Map((graph?.hops || []).map((h) => [h.alertId, h]));
    return linkedFilter.ids
      .map((id) => loaded.get(id) || (hops.has(id) ? hopToLinkedAlert(hops.get(id)!) : null))
      .filter((a): a is LinkedAlert => Boolean(a));
  }, [linkedFilter, alerts, graph]);

  const openLinked = (ids: string[], label: string) => {
    setLinkedFilter({ ids, label });
    setFilterPage(0);
    setActiveTab('alerts');
    document.querySelector('.wamCaseFlyout .euiFlyoutBody__overflow')?.scrollTo?.({ top: 0 });
  };

  const update = async (payload: Parameters<AlertsApiService['updateCase']>[1]) => {
    try {
      setBusy(true);
      const updated: any = await apiService.updateCase(caseId, payload);
      // The PUT response is the authoritative new case doc - apply it directly
      // rather than reloading over it. Only a change to the linked-alert SET
      // needs a reload, because updateCase does not return the expanded alerts
      // array that the Linked Alerts tab renders. A plain field edit does not,
      // so we skip the refetch and avoid the flyout-wide flicker.
      const alertsChanged = Boolean(payload.addAlertIds?.length || payload.removeAlertIds?.length);
      if (!alertsChanged) {
        setCaseDoc(updated);
      }
      onChanged();
      onToast?.(describeCaseUpdate(payload), 'success');
      if (alertsChanged) {
        await load();
      }
    } catch (e) {
      onError('Failed to update case');
      await load();
    } finally {
      setBusy(false);
    }
  };

  const requestStatusChange = (status: Case['status']) => {
    if (status === 'closed') {
      if (caseDoc?.status !== 'closed') {
        const openAlerts = alerts.filter((a) => a._source.status !== 'closed');
        setCloseConfirm({ openAlerts, excluded: new Set() });
      }
      return;
    }
    update({ status });
  };

  const confirmClose = async () => {
    if (!closeConfirm) return;
    try {
      setBusy(true);
      const result = await apiService.closeCase(
        caseId,
        closeConfirm.openAlerts.map((alert) => alert._id).filter((id) => closeConfirm.excluded.has(id))
      );
      onChanged();
      if (result.ok) {
        onToast?.(
          'Case closed',
          'success',
          `${result.closedAlerts} linked alert(s) closed; ${result.evidenceOnlyAlertIds.length} archive/snapshot-only link(s) retained.`
        );
      } else {
        onToast?.(
          result.caseClosed ? 'Case closed with partial alert failures' : 'Case close was incomplete',
          'danger',
          result.failedAlertIds.length
            ? `Failed alert IDs: ${result.failedAlertIds.join(', ')}`
            : result.errors.map((error) => error.message).join('; ')
        );
      }
    } catch (e) {
      onError('Failed to close case');
    } finally {
      setBusy(false);
      setCloseConfirm(null);
      load();
    }
  };

  const viewEvidence = async (alert: Alert & { _evidence?: any }) => {
    if (!alert._evidence) {
      onOpenAlert?.(alert);
      return;
    }
    try {
      setBusy(true);
      const detail: any = await apiService.fetchCaseEvidenceAlert(caseId, alert._id);
      if (detail.availability === 'live' && detail.alert) onOpenAlert?.(detail.alert);
      else setEvidenceDetail(detail);
    } catch (e: any) {
      onError(e?.body?.message || 'Failed to resolve case evidence');
    } finally {
      setBusy(false);
    }
  };

  const applyHold = async () => {
    if (!holdAlert || !holdReason.trim()) return;
    try {
      setBusy(true);
      await apiService.setEvidenceHold(caseId, holdAlert._id, holdReason.trim());
      onToast?.('Evidence hold set', 'success');
      setHoldAlert(null);
      setHoldReason('');
      await load();
    } catch (e: any) {
      onError(e?.body?.message || 'Failed to set evidence hold');
    } finally {
      setBusy(false);
    }
  };

  const releaseHold = async (alert: Alert & { _evidence?: any }) => {
    try {
      setBusy(true);
      await apiService.releaseEvidenceHold(caseId, alert._id);
      onToast?.('Evidence hold released', 'success');
      await load();
    } catch (e: any) {
      onError(e?.body?.message || 'Failed to release evidence hold');
    } finally {
      setBusy(false);
    }
  };

  // Keep the existing flyout mounted during refreshes so its selected tab,
  // scroll position, and analyst context are not reset after every mutation.
  if (!caseDoc) {
    return (
      <EuiFlyout onClose={onClose} size="m" className="wamCaseFlyout">
        <EuiFlyoutBody>
          <EuiLoadingSpinner size="xl" />
        </EuiFlyoutBody>
      </EuiFlyout>
    );
  }

  const range = headerRange(graph);

  return (
    <>
    <EuiFlyout
      onClose={onClose}
      size={isExpanded ? '95vw' : 'l'}
      aria-labelledby="case-details-flyout"
      className={`wamCaseFlyout wamAgTokens${theme === 'dark' && CONSOLE_TABS.has(activeTab) ? ' wamAg--dark wamCaseFlyout--dark' : ''}`}
    >
      <EuiFlyoutHeader className="wamCaseHead">
        <div className="wamAg wamAg__head">
          <div className="wamAg__headL">
            <div className="wamAg__eyebrow">Security case</div>
            <h2 id="case-details-flyout" className="wamAg__h1">
              <span>{caseDoc.title}</span>
              <span className={`wamAg__sev wamAg__sev--${caseDoc.severity}`}>
                {caseDoc.severity ? `${caseDoc.severity.charAt(0).toUpperCase()}${caseDoc.severity.slice(1)}` : 'Unknown'} severity
              </span>
            </h2>
          </div>
          <div className="wamAg__headR">
            {range && (
              <div className="wamAg__when">
                <b>{range.day}</b>
                {range.times} · {evidenceTotal.toLocaleString()} alert{evidenceTotal === 1 ? '' : 's'}
              </div>
            )}
            <EuiToolTip content={isExpanded ? 'Collapse' : 'Expand to full screen'}>
              <EuiButtonIcon
                iconType={isExpanded ? 'minimize' : 'expand'}
                aria-label={isExpanded ? 'Collapse' : 'Expand to full screen'}
                onClick={() => setIsExpanded((v) => !v)}
                display="empty"
              />
            </EuiToolTip>
          </div>
        </div>
      </EuiFlyoutHeader>
      <EuiFlyoutBody>
        {(() => {
          const tabs = [
            {
              id: 'overview',
              name: 'Overview',
              content: (
                <div>
                  <EuiSpacer size="m" />
                  <EuiDescriptionList type="column" compressed>
                    <EuiDescriptionListTitle>Status</EuiDescriptionListTitle>
                    <EuiDescriptionListDescription>
                      <StatusBadge status={caseDoc.status} />
                    </EuiDescriptionListDescription>
                    <EuiDescriptionListTitle>Created</EuiDescriptionListTitle>
                    <EuiDescriptionListDescription>
                      {caseDoc.created_by} at {formatAbsolute(caseDoc.created_at)}
                    </EuiDescriptionListDescription>
                    {caseDoc.updated_by && (
                      <>
                        <EuiDescriptionListTitle>Last updated</EuiDescriptionListTitle>
                        <EuiDescriptionListDescription>
                          {caseDoc.updated_by} at {formatAbsolute(caseDoc.updated_at)}
                        </EuiDescriptionListDescription>
                      </>
                    )}
                  </EuiDescriptionList>

                  <EuiSpacer size="m" />
                  <EuiFormRow label="Title" fullWidth>
                    <EuiFieldText fullWidth value={title} onChange={(e) => setTitle(e.target.value)} />
                  </EuiFormRow>
                  <EuiFormRow label="Description" fullWidth>
                    <EuiTextArea fullWidth value={description} onChange={(e) => setDescription(e.target.value)} rows={3} />
                  </EuiFormRow>
                  <EuiButton size="s" onClick={() => update({ title, description })} isLoading={busy}>
                    Save
                  </EuiButton>

                  <EuiSpacer size="m" />
                  <EuiFormRow label="Severity" display="rowCompressed">
                    <EuiButtonGroup
                      legend="Severity"
                      buttonSize="compressed"
                      options={CASE_SEVERITY_OPTIONS.map((o) => ({ id: o.value, label: o.text }))}
                      idSelected={caseDoc.severity}
                      onChange={(id) => update({ severity: id as Case['severity'] })}
                      isDisabled={busy}
                    />
                  </EuiFormRow>
                  <EuiSpacer size="s" />
                  <EuiFormRow label="Status" display="rowCompressed">
                    <EuiButtonGroup
                      legend="Status"
                      buttonSize="compressed"
                      color="primary"
                      options={[
                        { id: 'open', label: 'Open' },
                        { id: 'in_progress', label: 'In progress' },
                        { id: 'closed', label: 'Closed' },
                      ]}
                      idSelected={caseDoc.status}
                      onChange={(id) => requestStatusChange(id as Case['status'])}
                      isDisabled={busy}
                    />
                  </EuiFormRow>
                  <EuiSpacer size="s" />
                  <EuiFormRow label="Assigned to" display="rowCompressed" fullWidth>
                    <AssigneePicker
                      apiService={apiService}
                      value={caseDoc.assigned_to}
                      onChange={(assignee) => update({ assignedTo: assignee })}
                      compressed={false}
                    />
                  </EuiFormRow>
                </div>
              ),
            },
            {
              id: 'alerts',
              name: `Linked Alerts (${evidenceTotal})`,
              content: (
                <div className="wamAg wamAg__page">
                  {linkedFilter && filteredAlerts && (
                    <div className="wamAg__fchip">
                      <span>
                        Showing <b>{filteredAlerts.length.toLocaleString()}</b> of {evidenceTotal.toLocaleString()} alerts linked to <b>{linkedFilter.label}</b>
                      </span>
                      <button type="button" onClick={() => setLinkedFilter(null)}>Clear filter</button>
                    </div>
                  )}
                  <LinkedAlertsTable
                    alerts={filteredAlerts ? filteredAlerts.slice(filterPage * FILTER_PAGE, (filterPage + 1) * FILTER_PAGE) : alerts}
                    canManageLifecycle={canManageLifecycle}
                    onView={viewEvidence}
                    onSetHold={setHoldAlert}
                    onReleaseHold={releaseHold}
                    onRemove={(alert) => update({ removeAlertIds: [alert._id] })}
                  />
                  {filteredAlerts ? (
                    filteredAlerts.length > FILTER_PAGE && (
                      <div className="wamAg__pager">
                        <button type="button" className="wamAg__btn" disabled={filterPage === 0} onClick={() => setFilterPage((p) => p - 1)}>← Previous</button>
                        <span>
                          Page {filterPage + 1} · showing {filterPage * FILTER_PAGE + 1}–{Math.min((filterPage + 1) * FILTER_PAGE, filteredAlerts.length)} of {filteredAlerts.length}
                        </span>
                        <button type="button" className="wamAg__btn" disabled={(filterPage + 1) * FILTER_PAGE >= filteredAlerts.length} onClick={() => setFilterPage((p) => p + 1)}>Next →</button>
                      </div>
                    )
                  ) : (
                    evidenceTotal > 25 && (
                      <div className="wamAg__pager">
                        <button type="button" className="wamAg__btn" disabled={evidencePageIndex === 0 || loadingMoreEvidence} onClick={() => changeEvidencePage(evidencePageIndex - 1)}>← Previous</button>
                        <span>
                          Page {evidencePageIndex + 1} · showing {evidencePageIndex * 25 + 1}–{Math.min((evidencePageIndex + 1) * 25, evidenceTotal)} of {evidenceTotal}
                        </span>
                        <button type="button" className="wamAg__btn" disabled={!evidenceNextCursor || loadingMoreEvidence} onClick={() => changeEvidencePage(evidencePageIndex + 1)}>
                          {loadingMoreEvidence ? 'Loading…' : 'Next →'}
                        </button>
                      </div>
                    )
                  )}
                  <AlertMultiPicker
                    variant="console"
                    apiService={apiService}
                    excludeIds={Array.from(new Set([...(caseDoc.alert_ids || []), ...alerts.map((alert) => alert._id)]))}
                    onLinkSelected={(ids) => update({ addAlertIds: ids })}
                    linking={busy}
                    buttonLabel="Add to case"
                    title="Add an existing alert to this case"
                  />
                </div>
              ),
            },
            {
              id: 'attack-path',
              name: 'Attack Graph',
              content: (
                <div>
                  <EuiSpacer size="m" />
                  <AttackPathView
                    caseId={caseId}
                    graph={graph}
                    loading={graphLoading}
                    theme={theme}
                    onThemeChange={setTheme}
                    onOpenLinked={openLinked}
                  />
                </div>
              ),
            },
            {
              id: 'ai',
              name: 'AI Analysis',
              content: (
                <div>
                  <EuiSpacer size="m" />
                  <AiAnalysisTab
                    analysis={caseDoc.ai_analysis}
                    apiService={apiService}
                    onGenerate={() => apiService.analyzeCase(caseId) as Promise<AiAnalysis>}
                    onGenerated={(analysis) => {
                      setCaseDoc((prev) => (prev ? { ...prev, ai_analysis: analysis } : prev));
                      onChanged();
                    }}
                    onError={onError}
                    onToast={onToast}
                    emptyMessage="No AI analysis generated yet for this case. It will summarize all linked alerts and comments together."
                  />
                </div>
              ),
            },
            {
              id: 'comments',
              name: 'Comments',
              content: (
                <div>
                  <EuiSpacer size="m" />
                  <CommentsThread apiService={apiService} target={{ caseId }} onError={onError} onToast={onToast} />
                </div>
              ),
            },
            {
              id: 'history',
              name: 'History',
              content: (
                <div>
                  <EuiSpacer size="m" />
                  <HistoryList history={caseDoc.history} />
                </div>
              ),
            },
          ];
          return (
            <EuiTabbedContent
              tabs={tabs}
              selectedTab={tabs.find((t) => t.id === activeTab) || tabs[0]}
              onTabClick={(t) => setActiveTab(t.id)}
            />
          );
        })()}
      </EuiFlyoutBody>
    </EuiFlyout>
      {closeConfirm && (
      <EuiModal onClose={() => setCloseConfirm(null)}>
        <EuiModalHeader>
          <EuiModalHeaderTitle>Close this case?</EuiModalHeaderTitle>
        </EuiModalHeader>
        <EuiModalBody>
          <EuiCallOut title="This will also close linked live alerts" color="warning" iconType="alert">
            <p>
              {closeConfirm.openAlerts.length} currently loaded linked alert{closeConfirm.openAlerts.length === 1 ? '' : 's'} still
              open. The server will resolve all relationships and close every linked live alert except those unchecked below;
              archive and snapshot-only evidence stays attached to the case.
            </p>
          </EuiCallOut>
          <EuiSpacer size="m" />
          {closeConfirm.openAlerts.map((a) => (
            <EuiCheckbox
              key={a._id}
              id={`close-with-case-${a._id}`}
              label={`${a._source.rule?.description || a._id} (${a._source.agent?.name || 'unknown agent'})`}
              checked={!closeConfirm.excluded.has(a._id)}
              onChange={(e) => {
                setCloseConfirm((prev) => {
                  if (!prev) return prev;
                  const excluded = new Set(prev.excluded);
                  if (e.target.checked) excluded.delete(a._id);
                  else excluded.add(a._id);
                  return { ...prev, excluded };
                });
              }}
            />
          ))}
        </EuiModalBody>
        <EuiModalFooter>
          <EuiButtonEmpty onClick={() => setCloseConfirm(null)}>Cancel</EuiButtonEmpty>
          <EuiButton color="danger" onClick={confirmClose} isLoading={busy} fill>
            {closeConfirm.openAlerts.length - closeConfirm.excluded.size > 0
              ? `Close case and ${closeConfirm.openAlerts.length - closeConfirm.excluded.size} alert(s)`
              : 'Close case'}
          </EuiButton>
        </EuiModalFooter>
      </EuiModal>
      )}
      {holdAlert && (
        <EuiModal onClose={() => setHoldAlert(null)}>
          <EuiModalHeader><EuiModalHeaderTitle>Place evidence hold</EuiModalHeaderTitle></EuiModalHeader>
          <EuiModalBody>
            <EuiCallOut color="warning" title="Held evidence blocks archive purge">
              Record the investigation, legal, or regulatory reason for retaining full evidence.
            </EuiCallOut>
            <EuiSpacer size="m" />
            <EuiFormRow label="Hold reason" fullWidth>
              <EuiTextArea fullWidth value={holdReason} maxLength={1000} onChange={(e) => setHoldReason(e.target.value)} />
            </EuiFormRow>
          </EuiModalBody>
          <EuiModalFooter>
            <EuiButtonEmpty onClick={() => setHoldAlert(null)}>Cancel</EuiButtonEmpty>
            <EuiButton fill color="warning" disabled={!holdReason.trim()} isLoading={busy} onClick={applyHold}>Place hold</EuiButton>
          </EuiModalFooter>
        </EuiModal>
      )}
      {evidenceDetail && (
        <EuiModal onClose={() => setEvidenceDetail(null)} style={{ width: 760 }}>
          <EuiModalHeader><EuiModalHeaderTitle>Archived alert evidence</EuiModalHeaderTitle></EuiModalHeader>
          <EuiModalBody>
            <EuiCallOut
              color={evidenceDetail.availability === 'archived' ? 'success' : evidenceDetail.availability === 'purged' ? 'warning' : 'primary'}
              title={`Evidence availability: ${String(evidenceDetail.availability).replace('_', ' ')}`}
            >
              Full evidence is resolved server-side from the trusted locator stored on this case relationship. The browser cannot choose an index.
            </EuiCallOut>
            <EuiSpacer size="m" />
            <EuiDescriptionList type="column" compressed>
              <EuiDescriptionListTitle>Alert ID</EuiDescriptionListTitle>
              <EuiDescriptionListDescription>{evidenceDetail.evidence?.alert_id}</EuiDescriptionListDescription>
              <EuiDescriptionListTitle>Archive state</EuiDescriptionListTitle>
              <EuiDescriptionListDescription>{evidenceDetail.evidence?.relationship_state}</EuiDescriptionListDescription>
              <EuiDescriptionListTitle>Archived at</EuiDescriptionListTitle>
              <EuiDescriptionListDescription>{formatAbsolute(evidenceDetail.evidence?.archived_at)}</EuiDescriptionListDescription>
            </EuiDescriptionList>
            <EuiSpacer size="m" />
            <EuiText size="s"><h4>Resolved full alert or retained snapshot</h4></EuiText>
            <pre style={{ maxHeight: 360, overflow: 'auto', whiteSpace: 'pre-wrap' }}>
              {JSON.stringify(evidenceDetail.alert?._source || evidenceDetail.evidence?.snapshot || {}, null, 2)}
            </pre>
          </EuiModalBody>
          <EuiModalFooter><EuiButton onClick={() => setEvidenceDetail(null)}>Close</EuiButton></EuiModalFooter>
        </EuiModal>
      )}
    </>
  );
};
