import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  EuiFlexGroup,
  EuiFlexItem,
  EuiPanel,
  EuiStat,
  EuiSpacer,
  EuiSuperDatePicker,
  EuiLoadingSpinner,
  EuiText,
  EuiCallOut,
  EuiBasicTable,
  EuiTitle,
  EuiHorizontalRule,
  EuiIconTip,
  EuiTabbedContent,
} from '@elastic/eui';
import { ReportMetrics } from '../../common';
import { AlertsApiService } from '../services/api';
import { formatDuration, STATUS_HEX, SEVERITY_HEX, STATUS_LABEL } from '../design';
import { AlertTrendChart, StatusTrendChart } from './report_charts';
import { DonutBreakdown } from './donut_breakdown';
import { DeltaChip } from './delta_chip';

// Resolve a picker value (absolute ISO or simple date-math like 'now-7d') to
// epoch ms. Best-effort: anything it can't parse returns null, which just
// suppresses the period-over-period delta rather than erroring the report.
function resolveMs(s: string, now = Date.now()): number | null {
  if (!s) return null;
  if (s === 'now') return now;
  const m = /^now([+-])(\d+)([smhdwMy])(?:\/[smhdwMy])?$/.exec(s.trim());
  if (m) {
    const sign = m[1] === '-' ? -1 : 1;
    const n = Number(m[2]);
    const unitMs: Record<string, number> = {
      s: 1000,
      m: 60000,
      h: 3600000,
      d: 86400000,
      w: 604800000,
      M: 2592000000,
      y: 31536000000,
    };
    return now + sign * n * (unitMs[m[3]] || 0);
  }
  const t = Date.parse(s);
  return isNaN(t) ? null : t;
}

// The equal-length window immediately preceding [start, end].
function previousWindow(start: string, end: string): { from: string; to: string } | null {
  const now = Date.now();
  const s = resolveMs(start, now);
  const e = resolveMs(end, now);
  if (s == null || e == null || e <= s) return null;
  const span = e - s;
  return { from: new Date(s - span).toISOString(), to: new Date(s).toISOString() };
}
import {
  AnalystWorkloadTab,
  AnalystPerformanceTab,
  CaseAnalystTab,
  LeaderboardTab,
} from './analyst_reports';

interface Props {
  apiService: AlertsApiService;
  onToast: (title: string, color: 'success' | 'danger' | 'primary', text?: string) => void;
}

function slaColor(pct: number | null): string {
  if (pct == null) return 'subdued';
  if (pct >= 90) return 'success';
  if (pct >= 70) return 'warning';
  return 'danger';
}

const REPORT_SCOPE =
  'Operational metric over live, unarchived alerts and cases only. Archived alerts and cases are excluded; retired activity can make timing incomplete. This is not an immutable compliance record.';

export const ReportsView: React.FC<Props> = ({ apiService, onToast }) => {
  // start/end are date-math or absolute-ISO strings; the reports API feeds them
  // straight into an OpenSearch range query, which accepts both. EuiSuperDatePicker
  // provides the quick ranges AND absolute custom range selection.
  const [start, setStart] = useState('now-7d');
  const [end, setEnd] = useState('now');
  const [loading, setLoading] = useState(true);
  const [metrics, setMetrics] = useState<ReportMetrics | null>(null);
  const [prev, setPrev] = useState<ReportMetrics | null>(null);
  const loadGeneration = useRef(0);
  const onToastRef = useRef(onToast);
  onToastRef.current = onToast;

  const load = useCallback(async (from: string, to: string) => {
    const generation = ++loadGeneration.current;
    setLoading(true);
    setMetrics(null);
    setPrev(null);
    try {
      const pw = previousWindow(from, to);
      const [currentResult, previousResult] = await Promise.allSettled([
        apiService.fetchReportMetrics(from, to),
        pw ? apiService.fetchReportMetrics(pw.from, pw.to) : Promise.resolve(null),
      ]);
      if (generation !== loadGeneration.current) return;
      if (currentResult.status === 'rejected') throw currentResult.reason;
      setMetrics(currentResult.value);
      setPrev(previousResult.status === 'fulfilled' ? previousResult.value : null);
    } catch (e: any) {
      if (generation !== loadGeneration.current) return;
      onToastRef.current('Failed to load report', 'danger', e?.body?.message || e?.message);
    } finally {
      if (generation === loadGeneration.current) setLoading(false);
    }
  }, [apiService]);

  useEffect(() => {
    load(start, end);
    return () => {
      loadGeneration.current += 1;
    };
  }, [load, start, end]);

  const slaBreakdownWithTotals = (metrics?.slaBreakdown || []).map((b) => ({
    ...b,
    total: b.met + b.breached,
    compliancePct: b.met + b.breached ? (b.met / (b.met + b.breached)) * 100 : null,
  }));
  const timingPrevious = metrics && prev ? prev : null;
  const timingLabel = 'Exact cohort';
  const timingPopulationLabel = 'Cohort';
  const backfillPending =
    (metrics?.coverage?.closedMissingReporting ?? 0) + (metrics?.coverage?.assignedMissingReporting ?? 0) > 0;

  return (
    <div>
      <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" gutterSize="m" wrap>
        <EuiFlexItem>
          <EuiTitle size="s">
            <h2>Reporting</h2>
          </EuiTitle>
          <EuiText size="s" color="subdued">
            Operational outcomes for alerts that occurred in the selected cohort.{' '}
            <EuiIconTip type="iInCircle" content={REPORT_SCOPE} aria-label="Report data scope" />
          </EuiText>
        </EuiFlexItem>
        <EuiFlexItem grow={false} className="wamReportDatePicker">
          <EuiSuperDatePicker
            start={start}
            end={end}
            onTimeChange={({ start: s, end: e }) => {
              setStart(s);
              setEnd(e);
            }}
            onRefresh={({ start: s, end: e }) => {
              if (s === start && e === end) load(s, e);
              else {
                setStart(s);
                setEnd(e);
              }
            }}
            isLoading={loading}
            showUpdateButton
          />
        </EuiFlexItem>
      </EuiFlexGroup>

      <EuiSpacer size="l" />

      {loading && !metrics ? (
        <EuiLoadingSpinner size="xl" />
      ) : !metrics ? (
        <EuiText color="subdued">No data.</EuiText>
      ) : (
        <EuiTabbedContent
          className="wamReportTabs"
          size="s"
          tabs={[
            {
              id: 'overview',
              name: 'Overview',
              content: (
                <>
                  <EuiSpacer size="m" />
                  <EuiCallOut
                    title={`${metrics.totalAlerts.toLocaleString()} alerts occurred in this cohort`}
                    color="primary"
                    iconType="calendar"
                    size="s"
                  >
                    Alert volume, current-disposition counts, timing, and SLA are all computed exactly
                    over the live, unarchived cohort.
                  </EuiCallOut>
                  <EuiSpacer size="m" />
                  {backfillPending && (
            <>
              <EuiCallOut
                title="Some timing is unavailable for this cohort"
                color="warning"
                iconType="clock"
                size="s"
              >
                Resolution or assignment timing is unavailable for{' '}
                {metrics.coverage.closedMissingReporting.toLocaleString()} closed and{' '}
                {metrics.coverage.assignedMissingReporting.toLocaleString()} assigned alerts that predate the
                write-time reporting fields (their activity history is no longer live). Their timing and SLA
                figures are omitted rather than estimated.
              </EuiCallOut>
              <EuiSpacer size="m" />
            </>
          )}

          <EuiFlexGroup gutterSize="s" wrap className="wamReportStats">
            <EuiFlexItem style={{ minWidth: 160 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat title={metrics.totalAlerts.toLocaleString()} description="Alerts in cohort" />
                <DeltaChip current={metrics.totalAlerts} previous={prev?.totalAlerts} higherIsBetter={false} />
              </EuiPanel>
            </EuiFlexItem>
            <EuiFlexItem style={{ minWidth: 160 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat title={metrics.statusBreakdown.open} description="Currently open" titleColor="primary" />
              </EuiPanel>
            </EuiFlexItem>
            <EuiFlexItem style={{ minWidth: 160 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat title={metrics.statusBreakdown.in_progress} description="Currently in progress" titleColor="accent" />
              </EuiPanel>
            </EuiFlexItem>
            <EuiFlexItem style={{ minWidth: 160 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat title={metrics.statusBreakdown.closed} description="Currently closed" titleColor="subdued" />
              </EuiPanel>
            </EuiFlexItem>
          </EuiFlexGroup>

          <EuiSpacer size="m" />

          <EuiFlexGroup gutterSize="m" wrap className="wamReportCharts">
            <EuiFlexItem style={{ minWidth: 320 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiTitle size="xxs">
                  <h4>Alert cohort by day</h4>
                </EuiTitle>
                <EuiText size="xs" color="subdued">Alerts grouped by occurrence date</EuiText>
                <EuiSpacer size="s" />
                <AlertTrendChart data={metrics.alertsPerDay || []} />
              </EuiPanel>
            </EuiFlexItem>
            <EuiFlexItem style={{ minWidth: 320 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiTitle size="xxs">
                  <h4>Current disposition by occurrence date</h4>
                </EuiTitle>
                <EuiText size="xs" color="subdued">
                  Current status of alerts that occurred on each day, not historical status at that time
                </EuiText>
                <EuiSpacer size="s" />
                <StatusTrendChart data={metrics.statusPerDay || []} />
              </EuiPanel>
            </EuiFlexItem>
            <EuiFlexItem style={{ minWidth: 300 }} grow={false}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiTitle size="xxs">
                  <h4>Current cohort disposition</h4>
                </EuiTitle>
                <EuiSpacer size="m" />
                <DonutBreakdown
                  centerLabel="alerts"
                  segments={[
                    { label: STATUS_LABEL.open, value: metrics.statusBreakdown.open, color: STATUS_HEX.open },
                    { label: STATUS_LABEL.in_progress, value: metrics.statusBreakdown.in_progress, color: STATUS_HEX.in_progress },
                    { label: STATUS_LABEL.closed, value: metrics.statusBreakdown.closed, color: STATUS_HEX.closed },
                  ]}
                />
              </EuiPanel>
            </EuiFlexItem>
          </EuiFlexGroup>

          <EuiSpacer size="m" />

          <EuiTitle size="xs"><h3>Response outcomes</h3></EuiTitle>
          <EuiText size="xs" color="subdued">
            Exact for the live, unarchived cohort. Disposition is evaluated now; reopened alerts are excluded.
          </EuiText>
          <EuiSpacer size="s" />
          <EuiFlexGroup gutterSize="m" wrap className="wamOutcomeStats">
            <EuiFlexItem style={{ minWidth: 200 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat
                  title={formatDuration(metrics.meanTimeToAssignMinutes)}
                  description={
                    <>
                      Mean time to assign{' '}
                      <EuiIconTip
                        type="questionInCircle"
                        content={`Average time from an alert's timestamp to its first explicit assignment. ${timingLabel}; bulk status changes are not counted as assignments. ${REPORT_SCOPE}`}
                      />
                    </>
                  }
                  titleSize="m"
                />
                <DeltaChip
                  current={metrics.meanTimeToAssignMinutes}
                  previous={timingPrevious?.meanTimeToAssignMinutes}
                  higherIsBetter={false}
                  format={(n) => formatDuration(n)}
                />
                <EuiText size="xs" color="subdued">
                  {timingPopulationLabel}: {metrics.assignedCount.toLocaleString()} alerts with assignment history
                </EuiText>
              </EuiPanel>
            </EuiFlexItem>
            <EuiFlexItem style={{ minWidth: 200 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat
                  title={formatDuration(metrics.meanTimeToResolveMinutes)}
                  description={
                    <>
                      Mean time to resolve{' '}
                      <EuiIconTip
                        type="questionInCircle"
                        content={`Average time from an alert's timestamp to when it was closed. ${timingLabel}. ${REPORT_SCOPE}`}
                      />
                    </>
                  }
                  titleSize="m"
                />
                <DeltaChip
                  current={metrics.meanTimeToResolveMinutes}
                  previous={timingPrevious?.meanTimeToResolveMinutes}
                  higherIsBetter={false}
                  format={(n) => formatDuration(n)}
                />
                <EuiText size="xs" color="subdued">
                  {timingPopulationLabel}: {metrics.resolvedCount.toLocaleString()} currently closed alerts with resolution history
                </EuiText>
              </EuiPanel>
            </EuiFlexItem>
            <EuiFlexItem style={{ minWidth: 200 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat
                  title={metrics.slaCompliancePct != null ? `${metrics.slaCompliancePct.toFixed(0)}%` : 'N/A'}
                  description={
                    <>
                      SLA compliance{' '}
                      <EuiIconTip
                        type="questionInCircle"
                        content={`Share of resolved alerts closed within the severity-based target time. ${timingLabel}. ${REPORT_SCOPE}`}
                      />
                    </>
                  }
                  titleSize="m"
                  titleColor={slaColor(metrics.slaCompliancePct)}
                />
                <DeltaChip
                  current={metrics.slaCompliancePct}
                  previous={timingPrevious?.slaCompliancePct}
                  higherIsBetter
                  format={(n) => `${n.toFixed(0)}%`}
                />
                <EuiText size="xs" color="subdued">
                  {timingPopulationLabel}: currently closed alerts with resolution history
                </EuiText>
              </EuiPanel>
            </EuiFlexItem>
          </EuiFlexGroup>

          <EuiSpacer size="l" />
          <EuiHorizontalRule margin="none" />
          <EuiSpacer size="m" />

          <EuiTitle size="xs">
            <h3>SLA breakdown by severity</h3>
          </EuiTitle>
          <EuiText size="xs" color="subdued">
            Targets: Critical (level 12+) 1h &middot; High (7+) 4h &middot; Medium (4+) 24h &middot; Low 3d
          </EuiText>
          <EuiSpacer size="s" />
          {slaBreakdownWithTotals.length === 0 ? (
            <EuiText size="s" color="subdued">
              No closed alerts with a resolution time in this period yet.
            </EuiText>
          ) : (
            <EuiBasicTable
              items={slaBreakdownWithTotals}
              columns={[
                { field: 'label', name: 'Severity' },
                { field: 'total', name: 'Resolved' },
                { field: 'met', name: 'Within SLA' },
                { field: 'breached', name: 'Breached' },
                {
                  field: 'compliancePct',
                  name: 'Compliance',
                  render: (pct: number | null) => (pct != null ? `${pct.toFixed(0)}%` : 'N/A'),
                },
              ]}
            />
          )}

          <EuiSpacer size="l" />
          <EuiHorizontalRule margin="none" />
          <EuiSpacer size="m" />

          <EuiTitle size="xs">
            <h3>Cases</h3>
          </EuiTitle>
          <EuiText size="xs" color="subdued">
            {metrics.caseBasis === 'exact_cohort'
              ? 'Exact cohort: cases created in this period. Status cards show their current disposition.'
              : 'Case metrics are unavailable for this period.'}
          </EuiText>
          <EuiSpacer size="s" />

          {metrics.caseBasis === 'unavailable' ? (
            <EuiCallOut title="Case metrics could not be loaded" color="danger" iconType="alert" size="s" />
          ) : (
            <div>
          <EuiFlexGroup gutterSize="m" wrap>
            <EuiFlexItem style={{ minWidth: 160 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat title={metrics.cases.totalCases.toLocaleString()} description="Cases created" />
              </EuiPanel>
            </EuiFlexItem>
            <EuiFlexItem style={{ minWidth: 140 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat title={metrics.cases.statusBreakdown.open} description="Currently open" titleColor="primary" />
              </EuiPanel>
            </EuiFlexItem>
            <EuiFlexItem style={{ minWidth: 140 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat
                  title={metrics.cases.statusBreakdown.in_progress ?? 0}
                  description="Currently in progress"
                  titleColor="accent"
                />
              </EuiPanel>
            </EuiFlexItem>
            <EuiFlexItem style={{ minWidth: 140 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat title={metrics.cases.statusBreakdown.closed} description="Currently closed" titleColor="subdued" />
              </EuiPanel>
            </EuiFlexItem>
            <EuiFlexItem style={{ minWidth: 200 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat
                  title={formatDuration(metrics.cases.meanTimeToCloseMinutes)}
                  description={<>Mean time to close <EuiIconTip type="questionInCircle" content={`Average time to close for live cases created in the selected period. ${REPORT_SCOPE}`} /></>}
                  titleSize="m"
                />
                <EuiText size="xs" color="subdued">
                  Based on {metrics.cases.closedCount.toLocaleString()} closed case{metrics.cases.closedCount === 1 ? '' : 's'}
                </EuiText>
              </EuiPanel>
            </EuiFlexItem>
          </EuiFlexGroup>

          <EuiSpacer size="m" />
          {metrics.cases.totalCases === 0 ? (
            <EuiText size="s" color="subdued">
              No cases created in this period.
            </EuiText>
          ) : (
            <EuiFlexGroup gutterSize="m" wrap>
              <EuiFlexItem style={{ minWidth: 300 }} grow={false}>
                <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                  <EuiTitle size="xxs">
                    <h4>Cases by severity</h4>
                  </EuiTitle>
                  <EuiSpacer size="m" />
                  <DonutBreakdown
                    centerLabel="cases"
                    segments={['critical', 'high', 'medium', 'low'].map((k) => ({
                      label: k.charAt(0).toUpperCase() + k.slice(1),
                      value: metrics.cases.severityBreakdown[k as keyof typeof metrics.cases.severityBreakdown] || 0,
                      color: SEVERITY_HEX[k],
                    }))}
                  />
                </EuiPanel>
              </EuiFlexItem>
            </EuiFlexGroup>
          )}
            </div>
          )}
                </>
              ),
            },
            { id: 'workload', name: 'Workload', content: <AnalystWorkloadTab metrics={metrics} /> },
            { id: 'performance', name: 'Performance', content: <AnalystPerformanceTab metrics={metrics} /> },
            { id: 'cases-by-analyst', name: 'Cases by analyst', content: <CaseAnalystTab metrics={metrics} /> },
            { id: 'leaderboard', name: 'Leaderboard', content: <LeaderboardTab metrics={metrics} /> },
          ]}
        />
      )}
    </div>
  );
};
