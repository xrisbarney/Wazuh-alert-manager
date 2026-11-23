import { useTerminology } from '../terminology';
import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import {
  EuiFlyout,
  EuiFlyoutHeader,
  EuiFlyoutBody,
  EuiTitle,
  EuiDescriptionList,
  EuiDescriptionListTitle,
  EuiDescriptionListDescription,
  EuiSpacer,
  EuiButtonGroup,
  EuiLoadingSpinner,
  EuiBasicTable,
  EuiButtonIcon,
  EuiText,
  EuiTextArea,
  EuiFieldText,
  EuiButton,
  EuiFormRow,
  EuiFlexGroup,
  EuiFlexItem,
  EuiToolTip,
  EuiModal,
  EuiModalHeader,
  EuiModalHeaderTitle,
  EuiModalBody,
  EuiModalFooter,
  EuiCallOut,
  EuiCheckbox,
  EuiButtonEmpty,
  EuiBadge,
  EuiCodeBlock,
  EuiCopy,
  EuiPopover,
  EuiContextMenuPanel,
  EuiContextMenuItem,
  EuiAccordion,
} from '@elastic/eui';
import { Alert, Case, AiAnalysis, AttackGraph, CaseIndicatorsResponse, CaseIndicator } from '../../common';
import {
  INDICATOR_ACTIONS_CELL,
  INDICATOR_BADGE_CELL,
  INDICATOR_NARROW_CELL,
  INDICATOR_TYPE_LABELS,
  INDICATOR_VALUE_CELL,
  IndicatorSeenCell,
  IndicatorValueCell,
  VerdictBadges,
  indicatorsAsText,
  useIndicatorTableCompact,
} from './indicator_list';
import { EnrichmentLookupControls, EnrichmentVerdictBadges, ctiExplorerUrlFor, isLookupableIndicator, lookupKey, useEnrichmentLookups } from './enrichment_panel';
import { AlertsApiService, CaseReportFormat, downloadBlob } from '../services/api';
import { StatusBadge, CaseSeverityBadge, CASE_SEVERITY_OPTIONS, DispositionBadge } from './status_badge';
import { CaseFlyoutNav, CaseSectionId, isCaseSectionId, useCaseNavCollapsed } from './case_flyout_nav';
import { MetaGrid, MetaGroup, MetaRow } from './meta_grid';
import { CloseCaseDialog, CloseOutcome } from './close_case_dialog';
import { statusLabel, formatAbsolute } from '../design';
import { SlaDue } from './sla_due';
import { SlaEscalated } from './sla_escalated';
import { CommentsThread } from './comments_thread';
import { HistoryList } from './history_list';
import { AssigneePicker } from './assignee_picker';
import { AttackPathView } from './attack_path_view';
import { AlertMultiPicker } from './alert_multi_picker';
import { AiAnalysisTab } from './ai_analysis_tab';
import {
  AssetContextChips,
  AssetContextCountBadges,
  AssetContextSource,
  AssetContextSummary,
  aggregateAssetSummaries,
  assetContextErrorMessage,
  summarizeAssetContext,
} from './asset_context_chips';
import { AttachmentsTab } from './attachments_tab';
import { CaseTasksChip, CaseTasksTab, tasksChipLabel } from './case_tasks_tab';
import { CaseTimelineTab } from './case_timeline_tab';

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

type LinkedAlert = Alert & { _evidence?: any };

/** One distinct agent among the linked alerts (the Assets section lists them, step 11.4). */
export interface CaseContextAgent {
  key: string;
  id: string | null;
  name: string | null;
}

/** Distinct agents of the loaded linked alerts, in first-seen order; exported for tests. */
export function distinctContextAgents(alerts: Array<Pick<Alert, '_source'>>): CaseContextAgent[] {
  const seen = new Map<string, CaseContextAgent>();
  for (const item of alerts) {
    const id = item._source?.agent?.id || null;
    const name = item._source?.agent?.name || null;
    if (!id && !name) continue;
    const key = id ? `id:${id}` : `name:${name}`;
    if (!seen.has(key)) seen.set(key, { key, id, name });
  }
  return Array.from(seen.values());
}

/**
 * Test-subject-safe suffix for an agent row (`wamCaseAssetRow-<suffix>`),
 * derived from the unique key so an id-keyed agent and a name-only agent (or
 * two names that sanitise alike) never share a DOM id: `<id>` for id-bearing
 * agents (the step 11.3 selectors), `name-<name>` for name-only ones.
 */
export function contextAgentSubject(agent: CaseContextAgent): string {
  const sanitize = (value: string) => value.replace(/[^A-Za-z0-9_.-]/g, '_');
  return agent.id ? sanitize(agent.id) : `name-${sanitize(agent.name || '')}`;
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
  const terms = useTerminology();
  const [, setLoading] = useState(true);
  const [caseDoc, setCaseDoc] = useState<Case | null>(null);
  const [alerts, setAlerts] = useState<Array<Alert & { _evidence?: any }>>([]);
  const [busy, setBusy] = useState(false);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [isExpanded, setIsExpanded] = useState(false);
  // Collapsed icon rail preference (step 10.1), restored from localStorage.
  const [navCollapsed, toggleNavCollapsed] = useCaseNavCollapsed();
  // Report popover (step 5.2): Markdown / HTML downloads and the print view.
  const [reportMenuOpen, setReportMenuOpen] = useState(false);
  const [reportBusy, setReportBusy] = useState(false);
  const [closeConfirm, setCloseConfirm] = useState<{ openAlerts: Alert[]; excluded: Set<string> } | null>(null);
  const [canManageLifecycle, setCanManageLifecycle] = useState(false);
  const [holdAlert, setHoldAlert] = useState<(Alert & { _evidence?: any }) | null>(null);
  const [holdReason, setHoldReason] = useState('');
  const [evidenceDetail, setEvidenceDetail] = useState<any>(null);
  const [evidenceNextCursor, setEvidenceNextCursor] = useState<string | null>(null);
  const [evidenceTotal, setEvidenceTotal] = useState(0);
  // Assets section (step 11.4): one cached context response per agent key,
  // fetched by the flyout itself (not by the chip row) so the header counts
  // fill in without visiting the section and a remounted row costs nothing;
  // plus which rows the analyst opened/closed. Both reset with the case.
  const [assetContexts, setAssetContexts] = useState<Record<string, AssetContextSource>>({});
  const [assetRowOpen, setAssetRowOpen] = useState<Record<string, boolean>>({});
  // Keys whose fetch was started for the current case (a loading entry is
  // only visible to the effect after the commit, so this guards re-entry).
  const assetRequestedRef = useRef<Set<string>>(new Set());
  const [loadingMoreEvidence, setLoadingMoreEvidence] = useState(false);
  const [evidencePageIndex, setEvidencePageIndex] = useState(0);
  const [evidencePages, setEvidencePages] = useState<Array<Array<Alert & { _evidence?: any }>>>([]);
  const [evidencePageCursors, setEvidencePageCursors] = useState<Array<string | null>>([null]);
  const [activeTab, setActiveTab] = useState<CaseSectionId>('overview');
  // Section nav counts (step 8.1) that only a tab knows: reported by the tab
  // once it has fetched its list, null until then. Never fetched for the badge.
  const [attachmentCount, setAttachmentCount] = useState<number | null>(null);
  const [commentCount, setCommentCount] = useState<number | null>(null);
  // Attack graph data is fetched only when the analyst opens the tab. Building
  // it can resolve thousands of evidence relationships, so opening a case's
  // Overview must not pay that cost.
  const [graph, setGraph] = useState<AttackGraph | null>(null);
  const [graphLoading, setGraphLoading] = useState(false);
  const [graphStale, setGraphStale] = useState(true);
  // Signature of the linked-evidence set the loaded graph was derived from.
  // A reload that leaves the set unchanged (hold set/released, comment added)
  // must not refetch the graph (holds flip `relationship_state` to `held`, so
  // only the alert ids count): the tab effect would otherwise run twice when
  // the reload settles after the Attack graph section was opened.
  const graphEvidenceRef = useRef<string | null>(null);
  // Case indicators follow the same lazy pattern: aggregated server-side over
  // every evidence relationship, fetched only when the tab is open.
  const [indicators, setIndicators] = useState<CaseIndicatorsResponse | null>(null);
  const [indicatorsLoading, setIndicatorsLoading] = useState(false);
  const [indicatorsError, setIndicatorsError] = useState<string | null>(null);
  // The stale flag is a ref, not an effect dependency (step 10.5b): clearing
  // it from inside the load promise used to re-run the effect, whose cleanup
  // cancelled the very load that was finishing, so `(refreshing...)` never
  // cleared. `indicatorsRefresh` is the trigger that re-runs the effect.
  const indicatorsStale = useRef(true);
  const [indicatorsRefresh, setIndicatorsRefresh] = useState(0);
  const markIndicatorsStale = useCallback(() => {
    indicatorsStale.current = true;
    setIndicatorsRefresh((tick) => tick + 1);
  }, []);
  const { ref: indicatorsRef, compact: indicatorsCompact } = useIndicatorTableCompact();
  // Case-level lookups are session-only (nothing to hang them off); stored
  // verdicts come from the member alerts through `CaseIndicator.enrichment`.
  const caseLookup = useCallback(
    (type: any, value: string, refresh?: boolean) => apiService.lookupEnrichment({ type, value, refresh }),
    [apiService]
  );
  const enrichmentLookups = useEnrichmentLookups(caseLookup);
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
      // A case reload may follow an evidence-link mutation. Mark an already
      // loaded graph stale only when the evidence set changed; the tab effect
      // refreshes it now if visible, or defers that work until the next visit.
      const evidenceSignature = expanded
        .map((item) => item._id)
        .sort()
        .join('|');
      if (graphEvidenceRef.current !== evidenceSignature) {
        graphEvidenceRef.current = evidenceSignature;
        setGraphStale(true);
      }
      markIndicatorsStale();
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
    setGraph(null);
    setGraphStale(true);
    graphEvidenceRef.current = null;
    setIndicators(null);
    markIndicatorsStale();
    setIndicatorsError(null);
    setLinkedFilter(null);
    setActiveTab('overview');
    setAttachmentCount(null);
    setCommentCount(null);
    setAssetContexts({});
    setAssetRowOpen({});
    assetRequestedRef.current = new Set();
  }, [caseId]);

  const selectSection = useCallback((id: string) => {
    if (isCaseSectionId(id)) setActiveTab(id);
  }, []);

  useEffect(() => {
    if (activeTab !== 'indicators' || !indicatorsStale.current) return undefined;
    indicatorsStale.current = false;
    let cancelled = false;
    let settled = false;
    setIndicatorsLoading(true);
    setIndicatorsError(null);
    apiService.fetchCaseIndicators(caseId)
      .then((res) => {
        if (!cancelled) setIndicators(res);
      })
      .catch((e: any) => {
        if (cancelled) return;
        const status = e?.response?.status ?? e?.body?.statusCode;
        const message = status === 403
          ? "You do not have access to this case's evidence."
          : status === 404
          ? 'Case not found.'
          : e?.body?.message || e?.message || 'Failed to load case indicators';
        setIndicatorsError(message);
        onError('Failed to load case indicators');
      })
      .finally(() => {
        settled = true;
        if (!cancelled) setIndicatorsLoading(false);
      });
    return () => {
      cancelled = true;
      // A load abandoned mid-flight (section or case changed) is redone on
      // the next visit; a finished one is not.
      if (!settled) indicatorsStale.current = true;
    };
  }, [activeTab, caseId, indicatorsRefresh]);

  useEffect(() => {
    if (activeTab !== 'attack-path' || !graphStale) return undefined;
    let cancelled = false;
    setGraphLoading(true);
    apiService.fetchAttackPath(caseId)
      .then((res) => {
        if (!cancelled) {
          setGraph(res);
          setGraphStale(false);
        }
      })
      .catch(() => { if (!cancelled) onError('Failed to load attack path'); })
      .finally(() => { if (!cancelled) setGraphLoading(false); });
    return () => { cancelled = true; };
  }, [activeTab, caseId, graphStale]);

  const filteredAlerts = useMemo(() => {
    if (!linkedFilter) return null;
    const loaded = new Map(alerts.map((a) => [a._id, a]));
    const hops = new Map((graph?.hops || []).map((h) => [h.alertId, h]));
    return linkedFilter.ids
      .map((id) => loaded.get(id) || (hops.has(id) ? hopToLinkedAlert(hops.get(id)!) : null))
      .filter((a): a is LinkedAlert => Boolean(a));
  }, [linkedFilter, alerts, graph]);

  // Asset context (step 6.4b, moved into the Assets section in 11.4): one
  // collapsible row per distinct agent among every loaded evidence page (not
  // the page the Linked alerts table shows, so paging only grows the list).
  // A row's context is fetched the first time it is open, so a wide case
  // never fans out into dozens of native reads; the header summary aggregates
  // whatever rows have loaded. A single-agent case opens its only row by
  // default so the summary fills in; that default is pinned into
  // `assetRowOpen` so a later second agent does not collapse it.
  const contextAgentList = useMemo(() => distinctContextAgents(evidencePages.flat()), [evidencePages]);
  const singleAgent = contextAgentList.length === 1;
  const isAssetRowOpen = (key: string) => assetRowOpen[key] ?? singleAgent;
  useEffect(() => {
    if (!singleAgent) return;
    const key = contextAgentList[0].key;
    setAssetRowOpen((prev) => (prev[key] === undefined ? { ...prev, [key]: true } : prev));
  }, [singleAgent, contextAgentList]);
  const assetSummaries = useMemo(() => {
    const out: Record<string, AssetContextSummary> = {};
    for (const [key, source] of Object.entries(assetContexts)) {
      if (source.status === 'ready') out[key] = summarizeAssetContext(source.context);
      else if (source.status === 'failed') out[key] = summarizeAssetContext(null);
    }
    return out;
  }, [assetContexts]);
  const assetSummary = useMemo(
    () => aggregateAssetSummaries(contextAgentList.map((agent) => assetSummaries[agent.key]).filter((s): s is AssetContextSummary => Boolean(s))),
    [contextAgentList, assetSummaries]
  );
  const toggleAssetRow = (key: string, open: boolean) => {
    setAssetRowOpen((prev) => ({ ...prev, [key]: open }));
  };
  // Fetch the context of every open row that has none yet. The result is
  // kept until the case changes (a late response for a previous case is
  // dropped), so leaving and re-entering the section never refetches.
  useEffect(() => {
    const requested = assetRequestedRef.current;
    for (const agent of contextAgentList) {
      if (!isAssetRowOpen(agent.key) || requested.has(agent.key)) continue;
      requested.add(agent.key);
      const { key, id, name } = agent;
      setAssetContexts((prev) => ({ ...prev, [key]: { status: 'loading' } }));
      apiService
        .fetchAssetContext({ agentId: id, agentName: name })
        .then((context) => {
          if (assetRequestedRef.current !== requested) return;
          setAssetContexts((prev) => ({ ...prev, [key]: { status: 'ready', context } }));
        })
        .catch((e: any) => {
          if (assetRequestedRef.current !== requested) return;
          setAssetContexts((prev) => ({ ...prev, [key]: { status: 'failed', error: assetContextErrorMessage(e) } }));
        });
    }
    // `isAssetRowOpen` derives from assetRowOpen/singleAgent; the service is stable.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [caseId, contextAgentList, assetRowOpen, singleAgent]);

  // Removing alerts can shrink the filtered list below the current page.
  const filterPageCount = filteredAlerts ? Math.max(1, Math.ceil(filteredAlerts.length / FILTER_PAGE)) : 1;
  const safeFilterPage = Math.min(filterPage, filterPageCount - 1);
  useEffect(() => {
    if (filterPage !== safeFilterPage) setFilterPage(safeFilterPage);
  }, [filterPage, safeFilterPage]);

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

  const confirmClose = async (outcome: CloseOutcome) => {
    if (!closeConfirm) return;
    try {
      setBusy(true);
      const result = await apiService.closeCase(caseId, {
        excludeAlertIds: closeConfirm.openAlerts.map((alert) => alert._id).filter((id) => closeConfirm.excluded.has(id)),
        disposition: outcome.disposition,
        closureReason: outcome.closureReason,
      });
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

  const downloadReport = useCallback(async (format: CaseReportFormat) => {
    setReportMenuOpen(false);
    setReportBusy(true);
    try {
      const result = await apiService.downloadCaseReport(caseId, format);
      downloadBlob(result.filename, result.blob);
      onToast?.(`Report downloaded (${format === 'markdown' ? 'Markdown' : 'HTML'})`, 'success', result.filename);
    } catch (e: any) {
      onError(e?.body?.message || e?.message || 'Failed to build the case report');
    } finally {
      setReportBusy(false);
    }
  }, [apiService, caseId, onError, onToast]);

  const openPrintReport = useCallback(() => {
    setReportMenuOpen(false);
    // Same-origin GET: the dashboard session cookie applies, no XSRF header needed.
    window.open(apiService.caseReportUrl(caseId, { print: true }), '_blank', 'noopener');
  }, [apiService, caseId]);

  // Overview edit form (step 8.1): Save is enabled only when the title or
  // description differs from the stored case; Cancel restores them.
  const editsDirty = caseDoc ? title !== caseDoc.title || description !== (caseDoc.description || '') : false;
  const resetEdits = () => {
    if (!caseDoc) return;
    setTitle(caseDoc.title);
    setDescription(caseDoc.description || '');
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

  return (
    <>
    <EuiFlyout
      onClose={onClose}
      hideCloseButton
      size={isExpanded ? '95vw' : 'l'}
      aria-labelledby="case-details-flyout"
      className={`wamCaseFlyout${isExpanded ? ' wamCaseFlyout--expanded' : ''}`}
    >
      <EuiFlyoutHeader hasBorder>
        <EuiFlexGroup alignItems="center" gutterSize="s" responsive={false} wrap className="wamCaseFlyoutTitleRow">
          <EuiFlexItem grow={false}>
            <EuiTitle size="m">
              <h2 id="case-details-flyout" className="wamCaseFlyoutTitle" data-test-subj="wamCaseFlyoutTitle">{caseDoc.title}</h2>
            </EuiTitle>
          </EuiFlexItem>
        </EuiFlexGroup>
        <EuiSpacer size="s" />
        <EuiFlexGroup alignItems="center" gutterSize="m" responsive={false} wrap className="wamCaseFlyoutMeta" data-test-subj="wamCaseFlyoutMeta">
          <EuiFlexItem grow={false}>
            <StatusBadge status={caseDoc.status} />
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <CaseSeverityBadge severity={caseDoc.severity} />
          </EuiFlexItem>
          {caseDoc.status === 'closed' && caseDoc.disposition ? (
            <EuiFlexItem grow={false}>
              <DispositionBadge disposition={caseDoc.disposition} status={caseDoc.status} testSubj="wamCaseFlyoutDisposition" />
            </EuiFlexItem>
          ) : null}
          <EuiFlexItem grow={false}>
            <EuiText size="xs" color="subdued" className="wamCaseFlyoutMeta__text" data-test-subj="wamCaseFlyoutAssignee">
              {caseDoc.assigned_to ? `Assigned to ${caseDoc.assigned_to}` : 'Unassigned'}
            </EuiText>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiText size="xs" color="subdued" className="wamCaseFlyoutMeta__text" data-test-subj="wamCaseFlyoutTimes">
              Created {formatAbsolute(caseDoc.created_at)}
              {caseDoc.updated_by ? ` · updated ${formatAbsolute(caseDoc.updated_at)}` : ''}
            </EuiText>
          </EuiFlexItem>
          {caseDoc.sla_due_at && caseDoc.status !== 'closed' && (
            <EuiFlexItem grow={false} data-test-subj="wamCaseDueLine">
              <SlaDue dueAt={caseDoc.sla_due_at} status={caseDoc.status} label="Due" testSubj="wamCaseFlyoutDue" />
            </EuiFlexItem>
          )}
          {tasksChipLabel(caseDoc.task_counts) ? (
            <EuiFlexItem grow={false}>
              <CaseTasksChip counts={caseDoc.task_counts} testSubj="wamCaseFlyoutTasksChip" />
            </EuiFlexItem>
          ) : null}
          <EuiFlexItem grow={false} className="wamCaseFlyoutActions" data-test-subj="wamCaseFlyoutActions">
            <EuiFlexGroup alignItems="center" gutterSize="xs" responsive={false}>
              <EuiFlexItem grow={false}>
                <EuiPopover
                  id="wamCaseReportPopover"
                  button={
                    <EuiButtonEmpty
                      size="s"
                      iconType="document"
                      iconSide="left"
                      className="wamCaseReportButton"
                      data-test-subj="wamCaseReportButton"
                      onClick={() => setReportMenuOpen((v) => !v)}
                      isLoading={reportBusy}
                    >
                      Report
                    </EuiButtonEmpty>
                  }
                  isOpen={reportMenuOpen}
                  closePopover={() => setReportMenuOpen(false)}
                  panelPaddingSize="none"
                  anchorPosition="downRight"
                >
                  <EuiContextMenuPanel
                    className="wamCaseReportMenu"
                    items={[
                      <EuiContextMenuItem key="markdown" icon="download" data-test-subj="wamCaseReportMarkdown" onClick={() => downloadReport('markdown')}>
                        Download Markdown
                      </EuiContextMenuItem>,
                      <EuiContextMenuItem key="html" icon="download" data-test-subj="wamCaseReportHtml" onClick={() => downloadReport('html')}>
                        Download HTML
                      </EuiContextMenuItem>,
                      <EuiContextMenuItem key="print" icon="popout" data-test-subj="wamCaseReportPrint" onClick={openPrintReport}>
                        Print / PDF
                      </EuiContextMenuItem>,
                    ]}
                  />
                </EuiPopover>
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiButtonEmpty
                  size="s"
                  iconType={isExpanded ? 'minimize' : 'expand'}
                  iconSide="left"
                  aria-label={isExpanded ? 'Collapse' : 'Expand to full screen'}
                  data-test-subj="wamCaseFlyoutExpand"
                  onClick={() => setIsExpanded((v) => !v)}
                >
                  {isExpanded ? 'Collapse' : 'Expand'}
                </EuiButtonEmpty>
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiButtonEmpty size="s" iconType="cross" iconSide="left" aria-label="Close details" data-test-subj="wamCaseFlyoutClose" onClick={onClose}>
                  Close
                </EuiButtonEmpty>
              </EuiFlexItem>
            </EuiFlexGroup>
          </EuiFlexItem>
        </EuiFlexGroup>
        {caseDoc.sla?.escalated?.length ? (
          <div className="wamSlaDueLine wamCaseEscalatedLine" data-test-subj="wamCaseEscalatedLine">
            <SlaEscalated sla={caseDoc.sla} apiService={apiService} testSubj="wamCaseFlyoutEscalated" />
          </div>
        ) : null}
        {contextAgentList.length > 0 && (
          <div className="wamCaseAssetSummaryLine">
            <EuiButtonEmpty
              size="xs"
              iconType="storage"
              iconSide="left"
              flush="left"
              className="wamCaseAssetSummary"
              data-test-subj="wamCaseAssetSummary"
              title="Open the Assets section"
              onClick={() => selectSection('assets')}
            >
              <span className="wamCaseAssetSummary__agents" data-test-subj="wamCaseAssetSummaryAgents">
                {contextAgentList.length} agent{contextAgentList.length === 1 ? '' : 's'}
              </span>
              <AssetContextCountBadges summary={assetSummary} testSubj="wamCaseAssetSummaryCounts" />
            </EuiButtonEmpty>
          </div>
        )}
      </EuiFlyoutHeader>
      <EuiFlyoutBody>
        {(() => {
          const sections: Record<CaseSectionId, React.ReactNode> = {
            overview: (
              <div data-test-subj="wamCaseOverview">
                {/* 11.6: the editable fields first (title, the controls row, description,
                    Cancel / Save), then the read-only record facts as a grouped meta grid;
                    Status / Severity / Assigned to are only shown once, as the controls. */}
                <EuiFormRow label="Title" fullWidth>
                  <EuiFieldText fullWidth value={title} onChange={(e) => setTitle(e.target.value)} data-test-subj="wamCaseEditTitle" />
                </EuiFormRow>
                <EuiSpacer size="m" />
                <EuiFlexGroup gutterSize="m" responsive={false} wrap className="wamCaseFormGrid">
                  <EuiFlexItem grow={false}>
                    <EuiFormRow label="Severity">
                      <EuiButtonGroup
                        legend="Severity"
                        buttonSize="compressed"
                        options={CASE_SEVERITY_OPTIONS.map((o) => ({ id: o.value, label: o.text }))}
                        idSelected={caseDoc.severity}
                        onChange={(id) => update({ severity: id as Case['severity'] })}
                        isDisabled={busy}
                      />
                    </EuiFormRow>
                  </EuiFlexItem>
                  <EuiFlexItem grow={false}>
                    <EuiFormRow label="Status">
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
                  </EuiFlexItem>
                  <EuiFlexItem>
                    <EuiFormRow label="Assigned to" fullWidth data-test-subj="wamCaseOverviewAssignee">
                      <AssigneePicker
                        apiService={apiService}
                        value={caseDoc.assigned_to}
                        onChange={(assignee) => update({ assignedTo: assignee })}
                        compressed={false}
                        fullWidth
                      />
                    </EuiFormRow>
                  </EuiFlexItem>
                </EuiFlexGroup>
                <EuiSpacer size="m" />
                <EuiFormRow label="Description" fullWidth>
                  <EuiTextArea fullWidth value={description} onChange={(e) => setDescription(e.target.value)} rows={3} data-test-subj="wamCaseEditDescription" />
                </EuiFormRow>
                <EuiSpacer size="m" />
                <EuiFlexGroup justifyContent="flexEnd" gutterSize="s" responsive={false}>
                  <EuiFlexItem grow={false}>
                    <EuiButtonEmpty size="s" onClick={resetEdits} isDisabled={!editsDirty || busy} data-test-subj="wamCaseEditCancel">
                      Cancel
                    </EuiButtonEmpty>
                  </EuiFlexItem>
                  <EuiFlexItem grow={false}>
                    <EuiButton fill size="s" onClick={() => update({ title, description })} isLoading={busy} isDisabled={!editsDirty} data-test-subj="wamCaseEditSave">
                      Save
                    </EuiButton>
                  </EuiFlexItem>
                </EuiFlexGroup>

                <EuiSpacer size="m" />

                <MetaGrid className="wamMetaList" data-test-subj="wamCaseMeta">
                  <MetaGroup title="Record" data-test-subj="wamCaseMetaRecord">
                    <MetaRow label="Created">
                      {caseDoc.created_by} at {formatAbsolute(caseDoc.created_at)}
                    </MetaRow>
                    {caseDoc.updated_by && (
                      <MetaRow label="Last updated">
                        {caseDoc.updated_by} at {formatAbsolute(caseDoc.updated_at)}
                      </MetaRow>
                    )}
                    {caseDoc.status === 'closed' && (
                      <MetaRow label="Closed" data-test-subj="wamCaseClosedRow">
                        {formatAbsolute(caseDoc.closed_at)}
                      </MetaRow>
                    )}
                    {caseDoc.status === 'closed' && caseDoc.disposition ? (
                      <MetaRow label="Disposition" data-test-subj="wamCaseDispositionRow">
                        <span className="wamMetaList__inline">
                          <DispositionBadge disposition={caseDoc.disposition} status={caseDoc.status} testSubj="wamCaseOverviewDisposition" />
                          {caseDoc.closure_reason ? (
                            <span className="wamClosureReason" data-test-subj="wamCaseClosureReason">{caseDoc.closure_reason}</span>
                          ) : null}
                        </span>
                      </MetaRow>
                    ) : null}
                  </MetaGroup>
                  {(caseDoc.sla_due_at && caseDoc.status !== 'closed') || tasksChipLabel(caseDoc.task_counts) ? (
                    <MetaGroup title="Progress" data-test-subj="wamCaseMetaProgress">
                      {caseDoc.sla_due_at && caseDoc.status !== 'closed' ? (
                        <MetaRow label="SLA due">
                          <SlaDue dueAt={caseDoc.sla_due_at} status={caseDoc.status} testSubj="wamCaseOverviewDue" />
                        </MetaRow>
                      ) : null}
                      {tasksChipLabel(caseDoc.task_counts) ? (
                        <MetaRow label="Tasks" data-test-subj="wamCaseOverviewTasks">
                          {Number(caseDoc.task_counts?.done ?? 0)} of {Number(caseDoc.task_counts?.done ?? 0) + Number(caseDoc.task_counts?.open ?? 0)} done
                        </MetaRow>
                      ) : null}
                    </MetaGroup>
                  ) : null}
                </MetaGrid>
              </div>
            ),
            'alerts': (
              <div>
                {linkedFilter && filteredAlerts && (
                  <>
                    <EuiCallOut size="s" iconType="filter" title={`Showing ${filteredAlerts.length.toLocaleString()} of ${evidenceTotal.toLocaleString()} alerts linked to ${linkedFilter.label}`}>
                      <EuiButtonEmpty size="xs" flush="left" onClick={() => setLinkedFilter(null)}>
                        Clear filter
                      </EuiButtonEmpty>
                    </EuiCallOut>
                    <EuiSpacer size="s" />
                  </>
                )}
                <EuiBasicTable
                  items={filteredAlerts ? filteredAlerts.slice(safeFilterPage * FILTER_PAGE, (safeFilterPage + 1) * FILTER_PAGE) : alerts}
                  columns={[
                    {
                      field: '_source',
                      name: 'Timestamp',
                      render: (v: Alert['_source']) => formatAbsolute(v['@timestamp']),
                    },
                    { field: '_source', name: 'Rule ID', width: '90px', render: (v: Alert['_source']) => v.rule?.id || '—' },
                    { field: '_source', name: 'Agent', render: (v: Alert['_source']) => v.agent?.name || '—' },
                    {
                      field: '_source',
                      name: 'Status',
                      render: (v: Alert['_source']) => <StatusBadge status={v.status} />,
                    },
                    {
                      field: '_evidence',
                      name: 'Evidence',
                      render: (v: any) => v ? (
                        <EuiToolTip content={v.hold_reason || (v.archive_index ? `Trusted archive: ${v.archive_index}` : 'Live relationship snapshot')}>
                          <EuiBadge color={v.hold_reason ? 'warning' : v.relationship_state === 'archived' ? 'primary' : v.relationship_state === 'purged' ? 'danger' : 'hollow'}>
                            {v.hold_reason ? 'Held' : v.relationship_state === 'archived' ? 'Archived' : v.relationship_state === 'purged' ? 'Purged snapshot' : v.relationship_state === 'legacy' ? 'Legacy link' : 'Live'}
                          </EuiBadge>
                        </EuiToolTip>
                      ) : <EuiBadge color="hollow">Legacy link</EuiBadge>,
                    },
                    { field: '_source', name: 'Description', render: (v: Alert['_source']) => v.rule?.description || '—' },
                    {
                      name: 'Actions',
                      actions: [
                        {
                          render: (alert: LinkedAlert) => (
                            <>
                              <EuiButtonIcon iconType="eye" aria-label="View evidence" onClick={() => viewEvidence(alert)} />
                              {alert._evidence && canManageLifecycle && (
                                <EuiButtonIcon
                                  iconType={alert._evidence.hold_reason ? 'lockOpen' : 'lock'}
                                  aria-label={alert._evidence.hold_reason ? 'Release evidence hold' : 'Set evidence hold'}
                                  onClick={() => alert._evidence.hold_reason ? releaseHold(alert) : setHoldAlert(alert)}
                                />
                              )}
                              <EuiButtonIcon
                                iconType="unlink"
                                aria-label="Remove from case"
                                onClick={() => update({ removeAlertIds: [alert._id] })}
                              />
                            </>
                          ),
                        },
                      ],
                    },
                  ]}
                />
                {filteredAlerts ? (
                  filteredAlerts.length > FILTER_PAGE && (
                    <>
                      <EuiSpacer size="s" />
                      <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" gutterSize="s" responsive={false}>
                        <EuiFlexItem grow={false}>
                          <EuiButtonEmpty
                            size="s"
                            iconType="arrowLeft"
                            isDisabled={safeFilterPage === 0}
                            onClick={() => setFilterPage(safeFilterPage - 1)}
                          >
                            Previous
                          </EuiButtonEmpty>
                        </EuiFlexItem>
                        <EuiFlexItem grow={false}>
                          <EuiText size="s" color="subdued">
                            Page {safeFilterPage + 1} · showing {safeFilterPage * FILTER_PAGE + 1}–{Math.min((safeFilterPage + 1) * FILTER_PAGE, filteredAlerts.length)} of {filteredAlerts.length}
                          </EuiText>
                        </EuiFlexItem>
                        <EuiFlexItem grow={false}>
                          <EuiButtonEmpty
                            size="s"
                            iconType="arrowRight"
                            iconSide="right"
                            isDisabled={safeFilterPage + 1 >= filterPageCount}
                            onClick={() => setFilterPage((p) => p + 1)}
                          >
                            Next
                          </EuiButtonEmpty>
                        </EuiFlexItem>
                      </EuiFlexGroup>
                    </>
                  )
                ) : (
                  evidenceTotal > 25 && (
                    <>
                      <EuiSpacer size="s" />
                      <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" gutterSize="s" responsive={false}>
                        <EuiFlexItem grow={false}>
                          <EuiButtonEmpty
                            size="s"
                            iconType="arrowLeft"
                            isDisabled={evidencePageIndex === 0 || loadingMoreEvidence}
                            data-test-subj="wamCaseEvidencePrev"
                            onClick={() => changeEvidencePage(evidencePageIndex - 1)}
                          >
                            Previous
                          </EuiButtonEmpty>
                        </EuiFlexItem>
                        <EuiFlexItem grow={false}>
                          <EuiText size="s" color="subdued">
                            Page {evidencePageIndex + 1} · showing {evidencePageIndex * 25 + 1}–{Math.min((evidencePageIndex + 1) * 25, evidenceTotal)} of {evidenceTotal}
                          </EuiText>
                        </EuiFlexItem>
                        <EuiFlexItem grow={false}>
                          <EuiButtonEmpty
                            size="s"
                            iconType="arrowRight"
                            iconSide="right"
                            isLoading={loadingMoreEvidence}
                            isDisabled={!evidenceNextCursor}
                            data-test-subj="wamCaseEvidenceNext"
                            onClick={() => changeEvidencePage(evidencePageIndex + 1)}
                          >
                            Next
                          </EuiButtonEmpty>
                        </EuiFlexItem>
                      </EuiFlexGroup>
                    </>
                  )
                )}
                <EuiSpacer size="l" />
                <AlertMultiPicker
                  apiService={apiService}
                  excludeIds={Array.from(new Set([...(caseDoc.alert_ids || []), ...alerts.map((alert) => alert._id)]))}
                  onLinkSelected={(ids) => update({ addAlertIds: ids })}
                  linking={busy}
                  buttonLabel="Add to case"
                  title="Add an existing alert to this case"
                />
              </div>
            ),
            'assets': (
              <div className="wamCaseAssets" data-test-subj="wamCaseAssets">
                {contextAgentList.length === 0 ? (
                  <EuiText size="s" color="subdued" data-test-subj="wamCaseAssetsEmpty">
                    No agent among the linked {terms.units} yet.
                  </EuiText>
                ) : (
                  <>
                    <EuiText size="xs" color="subdued" className="wamCaseAssets__intro" data-test-subj="wamCaseAssetsIntro">
                      {contextAgentList.length} agent{contextAgentList.length === 1 ? '' : 's'} among the linked {terms.units}. Expand a row to read its asset context
                      (operating system, addresses, open ports, vulnerabilities, SCA) from the Wazuh states indices.
                    </EuiText>
                    {contextAgentList.map((agent) => {
                      const subject = contextAgentSubject(agent);
                      const open = isAssetRowOpen(agent.key);
                      const summary = assetSummaries[agent.key];
                      return (
                        <EuiAccordion
                          key={agent.key}
                          id={`wamCaseAssetRow-${subject}`}
                          className="wamCaseAssetRow"
                          data-test-subj={`wamCaseAssetRow-${subject}`}
                          forceState={open ? 'open' : 'closed'}
                          onToggle={(isOpen: boolean) => toggleAssetRow(agent.key, isOpen)}
                          paddingSize="s"
                          buttonClassName="wamCaseAssetRow__button"
                          buttonProps={{ 'data-test-subj': `wamCaseAssetRowToggle-${subject}` } as any}
                          buttonContent={
                            <span className="wamCaseAssetRow__title">
                              <span className="wamCaseAssetRow__name" data-test-subj={`wamCaseAssetRowName-${subject}`}>
                                {agent.name || agent.id}
                              </span>
                              {agent.id && agent.name ? (
                                <span className="wamCaseAssetRow__id" data-test-subj={`wamCaseAssetRowId-${subject}`}>
                                  {agent.id}
                                </span>
                              ) : null}
                              {summary ? <AssetContextCountBadges summary={summary} testSubj={`wamCaseAssetRowCounts-${subject}`} /> : null}
                            </span>
                          }
                        >
                          {open || assetContexts[agent.key] ? (
                            <AssetContextChips
                              apiService={apiService}
                              agentId={agent.id}
                              agentName={agent.name}
                              testSubj="wamCaseAssetContext"
                              source={assetContexts[agent.key] || { status: 'loading' }}
                            />
                          ) : null}
                        </EuiAccordion>
                      );
                    })}
                  </>
                )}
              </div>
            ),
            'timeline': (
              <div>
                {activeTab === 'timeline' && (
                  <CaseTimelineTab
                    apiService={apiService}
                    caseId={caseId}
                    onError={onError}
                    // Same resolution path as the Alerts tab: live records open the
                    // alert flyout, archived / snapshot evidence the detail panel.
                    onOpenAlert={(alertId) => viewEvidence({ _id: alertId, _evidence: true } as Alert & { _evidence?: any })}
                  />
                )}
              </div>
            ),
            'attack-path': (
              <div>
                <AttackPathView
                  caseId={caseId}
                  graph={graph}
                  loading={graphLoading}
                  onOpenLinked={openLinked}
                />
              </div>
            ),
            'indicators': (
              <div data-test-subj="wamCaseIndicators" ref={indicatorsRef}>
                {indicatorsLoading && !indicators ? (
                  <EuiLoadingSpinner size="l" />
                ) : (
                  <>
                    <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false} wrap>
                      <EuiFlexItem grow={false}>
                        <EuiText size="s" color="subdued">
                          <p>
                            {indicators
                              ? `${indicators.indicators.length} indicator(s) across ${indicators.includedAlerts} linked ${terms.units}`
                              : 'Indicators are aggregated over every alert linked to this case.'}
                            {indicatorsLoading ? ' (refreshing...)' : ''}
                          </p>
                        </EuiText>
                      </EuiFlexItem>
                      <EuiFlexItem grow={false}>
                        <EuiCopy textToCopy={indicatorsAsText(indicators?.indicators || [])}>
                          {(copy) => (
                            <EuiButton
                              size="s"
                              iconType="copyClipboard"
                              onClick={copy}
                              isDisabled={!indicators || indicators.indicators.length === 0}
                              data-test-subj="wamCaseIndicatorsCopyAll"
                            >
                              Copy all
                            </EuiButton>
                          )}
                        </EuiCopy>
                      </EuiFlexItem>
                      <EuiFlexItem grow={false}>
                        <EuiButtonEmpty size="s" iconType="refresh" onClick={markIndicatorsStale} isDisabled={indicatorsLoading} data-test-subj="wamCaseIndicatorsRefresh">
                          Refresh
                        </EuiButtonEmpty>
                      </EuiFlexItem>
                      <EuiFlexItem grow={false}>
                        <EuiToolTip content="Look up every IP, domain, URL and hash through the configured enrichment sources (results are shown here and cached, not stored on the case)">
                          <EuiButton
                            size="s"
                            iconType="search"
                            isLoading={enrichmentLookups.runningAll}
                            isDisabled={!indicators || !indicators.indicators.some((row) => isLookupableIndicator(row.type, row.value)) || Object.keys(enrichmentLookups.pending).length > 0}
                            onClick={() => enrichmentLookups.runAll(indicators?.indicators || [])}
                            data-test-subj="wamCaseIndicatorsLookupAll"
                          >
                            Lookup all
                          </EuiButton>
                        </EuiToolTip>
                      </EuiFlexItem>
                    </EuiFlexGroup>
                    {indicators?.truncated && (
                      <>
                        <EuiSpacer size="s" />
                        <EuiCallOut size="s" color="warning" title={`Only the first ${indicators.limit} linked ${terms.units} were aggregated.`} />
                      </>
                    )}
                    <EuiSpacer size="s" />
                    {indicatorsError && !indicators && (
                      <>
                        <EuiCallOut size="s" color="danger" iconType="alert" title="Indicators are unavailable" data-test-subj="wamCaseIndicatorsError">
                          <p>{indicatorsError}</p>
                        </EuiCallOut>
                        <EuiSpacer size="s" />
                      </>
                    )}
                    {!(indicatorsError && !indicators) && (
                    <EuiBasicTable<CaseIndicator>
                      className="wamIndicatorTable"
                      compressed
                      tableLayout="auto"
                      items={indicators?.indicators || []}
                      itemId={(row) => `${row.type}:${row.value}`}
                      noItemsMessage={indicators ? 'No indicators could be extracted from the linked records.' : indicatorsLoading ? 'Loading...' : 'Indicators have not been loaded.'}
                      columns={[
                        {
                          field: 'type',
                          name: 'Type',
                          className: INDICATOR_NARROW_CELL,
                          render: (type: CaseIndicator['type']) => <EuiBadge color="hollow">{INDICATOR_TYPE_LABELS[type]}</EuiBadge>,
                        },
                        {
                          field: 'value',
                          name: 'Value',
                          className: INDICATOR_VALUE_CELL,
                          render: (value: string, row: CaseIndicator) => <IndicatorValueCell value={value} fields={row.fields} tags={row.tags} />,
                        },
                        {
                          field: 'count',
                          name: terms.Units,
                          align: 'right',
                          className: INDICATOR_NARROW_CELL,
                          render: (count: number, row: CaseIndicator) => (
                            <EuiToolTip content={row.alert_ids.join(', ')}>
                              <span>{count}</span>
                            </EuiToolTip>
                          ),
                        },
                        ...(indicatorsCompact
                          ? [
                              {
                                field: 'last_seen',
                                name: 'Seen',
                                className: INDICATOR_NARROW_CELL,
                                render: (_v: string | null, row: CaseIndicator) => <IndicatorSeenCell firstSeen={row.first_seen} lastSeen={row.last_seen} />,
                              },
                            ]
                          : [
                              { field: 'first_seen', name: 'First seen', className: INDICATOR_NARROW_CELL, render: (v: string | null) => formatAbsolute(v) },
                              { field: 'last_seen', name: 'Last seen', className: INDICATOR_NARROW_CELL, render: (v: string | null) => formatAbsolute(v) },
                            ]),
                        {
                          field: 'verdictHints',
                          name: 'Native verdicts',
                          className: INDICATOR_BADGE_CELL,
                          render: (hints: CaseIndicator['verdictHints']) => (hints.length ? <VerdictBadges hints={hints} /> : <EuiText size="xs" color="subdued">none</EuiText>),
                        },
                        {
                          name: 'Lookups',
                          className: INDICATOR_BADGE_CELL,
                          render: (row: CaseIndicator) => {
                            const key = lookupKey(row.type, row.value);
                            const error = enrichmentLookups.errors[key];
                            return (
                              <div>
                                <EnrichmentVerdictBadges stored={row.enrichment || []} session={enrichmentLookups.results[key]} />
                                {error && (
                                  <EuiText size="xs" color="danger">
                                    <span>{error}</span>
                                  </EuiText>
                                )}
                              </div>
                            );
                          },
                        },
                        {
                          name: 'Actions',
                          align: 'right',
                          className: INDICATOR_ACTIONS_CELL,
                          render: (row: CaseIndicator) => (
                            <EnrichmentLookupControls
                              type={row.type}
                              value={row.value}
                              pending={Boolean(enrichmentLookups.pending[lookupKey(row.type, row.value)])}
                              onLookup={(refresh) => enrichmentLookups.run(row.type as any, row.value, refresh)}
                              ctiUrl={ctiExplorerUrlFor(apiService, terms.wazuhMajor, row.value)}
                            />
                          ),
                        },
                      ]}
                    />
                    )}
                  </>
                )}
              </div>
            ),
            'ai': (
              <div>
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
            'tasks': (
              <div>
                {activeTab === 'tasks' && (
                  <CaseTasksTab
                    apiService={apiService}
                    caseId={caseId}
                    readOnly={caseDoc.status === 'closed'}
                    onError={onError}
                    onToast={onToast}
                    onCountsChanged={(task_counts) => {
                      setCaseDoc((current) => (current ? { ...current, task_counts } : current));
                      onChanged();
                    }}
                  />
                )}
              </div>
            ),
            'attachments': (
              <div>
                {activeTab === 'attachments' && (
                  <AttachmentsTab apiService={apiService} caseId={caseId} onError={onError} onToast={onToast} onCountChanged={setAttachmentCount} />
                )}
              </div>
            ),
            'comments': (
              <div>
                <CommentsThread apiService={apiService} target={{ caseId }} onError={onError} onToast={onToast} onCountChanged={setCommentCount} />
              </div>
            ),
            'history': (
              <div>
                <HistoryList history={caseDoc.history} />
              </div>
            ),
          };
          return (
            <EuiFlexGroup gutterSize="l" responsive={false} className="wamCaseBody">
              <EuiFlexItem grow={false} className={`wamCaseNavColumn${navCollapsed ? ' wamCaseNavColumn--collapsed' : ''}`}>
                <CaseFlyoutNav
                  activeId={activeTab}
                  unitsLabel={terms.units}
                  onSelect={selectSection}
                  collapsed={navCollapsed}
                  onToggleCollapsed={toggleNavCollapsed}
                  counts={{
                    alerts: evidenceTotal,
                    assets: contextAgentList.length,
                    tasks: caseDoc.task_counts,
                    attachments: attachmentCount,
                    comments: commentCount,
                  }}
                />
              </EuiFlexItem>
              <EuiFlexItem className="wamCaseContent">
                <div className="wamCaseSection" data-test-subj={`wamCaseSection-${activeTab}`}>
                  {sections[activeTab]}
                </div>
              </EuiFlexItem>
            </EuiFlexGroup>
          );
        })()}
      </EuiFlyoutBody>
    </EuiFlyout>
      {closeConfirm && (
      <CloseCaseDialog
        title="Close this case?"
        confirmLabel={closeConfirm.openAlerts.length - closeConfirm.excluded.size > 0
          ? `Close case and ${closeConfirm.openAlerts.length - closeConfirm.excluded.size} alert(s)`
          : 'Close case'}
        busy={busy}
        onCancel={() => setCloseConfirm(null)}
        onConfirm={confirmClose}
        testSubj="wamCaseCloseDialog"
      >
          <EuiCallOut title="This will also close linked live alerts" color="warning" iconType="alert">
            <p>
              {closeConfirm.openAlerts.length} currently loaded linked alert{closeConfirm.openAlerts.length === 1 ? '' : 's'} still
              open. The server will resolve all relationships and close every linked live alert except those unchecked below,
              stamping the disposition above on each of them; archive and snapshot-only evidence stays attached to the case.
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
      </CloseCaseDialog>
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
            <EuiCodeBlock language="json" isCopyable overflowHeight={360}>
              {JSON.stringify(evidenceDetail.alert?._source || evidenceDetail.evidence?.snapshot || {}, null, 2)}
            </EuiCodeBlock>
          </EuiModalBody>
          <EuiModalFooter><EuiButton onClick={() => setEvidenceDetail(null)}>Close</EuiButton></EuiModalFooter>
        </EuiModal>
      )}
    </>
  );
};
