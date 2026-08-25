import React, { useState, useEffect, useCallback } from 'react';
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

export const ReportsView: React.FC<Props> = ({ apiService, onToast }) => {
  // start/end are date-math or absolute-ISO strings; the reports API feeds them
  // straight into an OpenSearch range query, which accepts both. EuiSuperDatePicker
  // provides the quick ranges AND absolute custom range selection.
  const [start, setStart] = useState('now-7d');
  const [end, setEnd] = useState('now');
  const [loading, setLoading] = useState(true);
  const [metrics, setMetrics] = useState<ReportMetrics | null>(null);
  const [prev, setPrev] = useState<ReportMetrics | null>(null);

  const load = useCallback(async () => {
    try {
      setLoading(true);
      const res = await apiService.fetchReportMetrics(start, end);
      setMetrics(res);
      // Fetch the preceding equal-length window for period-over-period deltas.
      // Non-blocking failure — deltas just don't render.
      const pw = previousWindow(start, end);
      if (pw) {
        apiService
          .fetchReportMetrics(pw.from, pw.to)
          .then(setPrev)
          .catch(() => setPrev(null));
      } else {
        setPrev(null);
      }
    } catch (e: any) {
      onToast('Failed to load report', 'danger', e?.body?.message || e.message);
    } finally {
      setLoading(false);
    }
  }, [start, end]);

  useEffect(() => {
    load();
  }, [load]);

  const slaBreakdownWithTotals = (metrics?.slaBreakdown || []).map((b) => ({
    ...b,
    total: b.met + b.breached,
    compliancePct: b.met + b.breached ? (b.met / (b.met + b.breached)) * 100 : null,
  }));

  return (
    <div>
      <EuiFlexGroup alignItems="center" gutterSize="m" wrap>
        <EuiFlexItem grow={false}>
          <EuiTitle size="s">
            <h2>Reporting</h2>
          </EuiTitle>
        </EuiFlexItem>
        <EuiFlexItem grow={false} style={{ minWidth: 340 }}>
          <EuiSuperDatePicker
            start={start}
            end={end}
            onTimeChange={({ start: s, end: e }) => {
              setStart(s);
              setEnd(e);
            }}
            onRefresh={({ start: s, end: e }) => {
              setStart(s);
              setEnd(e);
            }}
            isLoading={loading}
            showUpdateButton
            width="auto"
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
          size="s"
          tabs={[
            {
              id: 'overview',
              name: 'Overview',
              content: (
                <>
                  <EuiSpacer size="m" />
          {metrics.truncated && (
            <>
              <EuiCallOut
                title={`Based on a sample of ${metrics.sampledAlerts.toLocaleString()} of ${metrics.totalAlerts.toLocaleString()} matching alerts`}
                color="warning"
                iconType="alert"
                size="s"
              >
                Narrow the time period for exact figures on very high-volume periods.
              </EuiCallOut>
              <EuiSpacer size="m" />
            </>
          )}

          <EuiFlexGroup gutterSize="m" wrap>
            <EuiFlexItem style={{ minWidth: 160 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat title={metrics.totalAlerts.toLocaleString()} description="Total alerts" />
                <DeltaChip current={metrics.totalAlerts} previous={prev?.totalAlerts} higherIsBetter={false} />
              </EuiPanel>
            </EuiFlexItem>
            <EuiFlexItem style={{ minWidth: 160 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat title={metrics.statusBreakdown.open} description="Open" titleColor="primary" />
              </EuiPanel>
            </EuiFlexItem>
            <EuiFlexItem style={{ minWidth: 160 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat title={metrics.statusBreakdown.in_progress} description="In progress" titleColor="accent" />
              </EuiPanel>
            </EuiFlexItem>
            <EuiFlexItem style={{ minWidth: 160 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat title={metrics.statusBreakdown.closed} description="Closed" titleColor="subdued" />
              </EuiPanel>
            </EuiFlexItem>
          </EuiFlexGroup>

          <EuiSpacer size="m" />

          <EuiFlexGroup gutterSize="m" wrap>
            <EuiFlexItem style={{ minWidth: 320 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiTitle size="xxs">
                  <h4>Alert volume per day</h4>
                </EuiTitle>
                <EuiSpacer size="s" />
                <AlertTrendChart data={metrics.alertsPerDay || []} />
              </EuiPanel>
            </EuiFlexItem>
            <EuiFlexItem style={{ minWidth: 320 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiTitle size="xxs">
                  <h4>Status over time</h4>
                </EuiTitle>
                <EuiText size="xs" color="subdued">
                  Each day's alerts by current disposition (open / in progress / closed)
                </EuiText>
                <EuiSpacer size="s" />
                <StatusTrendChart data={metrics.statusPerDay || []} />
              </EuiPanel>
            </EuiFlexItem>
            <EuiFlexItem style={{ minWidth: 300 }} grow={false}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiTitle size="xxs">
                  <h4>Alerts by status</h4>
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

          <EuiFlexGroup gutterSize="m" wrap>
            <EuiFlexItem style={{ minWidth: 200 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat
                  title={formatDuration(metrics.meanTimeToAssignMinutes)}
                  description={
                    <>
                      Mean time to assign{' '}
                      <EuiIconTip
                        type="questionInCircle"
                        content="Average time from an alert's timestamp to its first explicit assignment. Computed over the alerts sampled in this period; bulk status changes are not counted as assignments."
                      />
                    </>
                  }
                  titleSize="m"
                />
                <DeltaChip
                  current={metrics.meanTimeToAssignMinutes}
                  previous={prev?.meanTimeToAssignMinutes}
                  higherIsBetter={false}
                  format={(n) => formatDuration(n)}
                />
                <EuiText size="xs" color="subdued">
                  Based on {metrics.assignedCount.toLocaleString()} assigned alert{metrics.assignedCount === 1 ? '' : 's'}
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
                        content="Average time from an alert's timestamp to when it was closed. Computed over the alerts sampled in this period."
                      />
                    </>
                  }
                  titleSize="m"
                />
                <DeltaChip
                  current={metrics.meanTimeToResolveMinutes}
                  previous={prev?.meanTimeToResolveMinutes}
                  higherIsBetter={false}
                  format={(n) => formatDuration(n)}
                />
                <EuiText size="xs" color="subdued">
                  Based on {metrics.resolvedCount.toLocaleString()} closed alert{metrics.resolvedCount === 1 ? '' : 's'}
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
                        content="Share of resolved alerts that were closed within the severity-based target time (targets listed in the SLA breakdown below). Based on the sampled alerts that have a resolution time."
                      />
                    </>
                  }
                  titleSize="m"
                  titleColor={slaColor(metrics.slaCompliancePct)}
                />
                <DeltaChip
                  current={metrics.slaCompliancePct}
                  previous={prev?.slaCompliancePct}
                  higherIsBetter
                  format={(n) => `${n.toFixed(0)}%`}
                />
                <EuiText size="xs" color="subdued">
                  Resolved-in-time vs. severity-based target
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
            Cases created in this period
          </EuiText>
          <EuiSpacer size="s" />

          <EuiFlexGroup gutterSize="m" wrap>
            <EuiFlexItem style={{ minWidth: 160 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat title={metrics.cases.totalCases.toLocaleString()} description="Cases created" />
              </EuiPanel>
            </EuiFlexItem>
            <EuiFlexItem style={{ minWidth: 140 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat title={metrics.cases.statusBreakdown.open} description="Open" titleColor="primary" />
              </EuiPanel>
            </EuiFlexItem>
            <EuiFlexItem style={{ minWidth: 140 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat
                  title={metrics.cases.statusBreakdown.in_progress ?? 0}
                  description="In progress"
                  titleColor="accent"
                />
              </EuiPanel>
            </EuiFlexItem>
            <EuiFlexItem style={{ minWidth: 140 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat title={metrics.cases.statusBreakdown.closed} description="Closed" titleColor="subdued" />
              </EuiPanel>
            </EuiFlexItem>
            <EuiFlexItem style={{ minWidth: 200 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat title={formatDuration(metrics.cases.meanTimeToCloseMinutes)} description="Mean time to close" titleSize="m" />
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
