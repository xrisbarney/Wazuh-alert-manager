import React, { useState, useEffect, useCallback } from 'react';
import {
  EuiFlexGroup,
  EuiFlexItem,
  EuiPanel,
  EuiStat,
  EuiSpacer,
  EuiButton,
  EuiButtonGroup,
  EuiLoadingSpinner,
  EuiText,
  EuiCallOut,
  EuiBasicTable,
  EuiTitle,
  EuiHorizontalRule,
} from '@elastic/eui';
import { ReportMetrics } from '../../common';
import { AlertsApiService } from '../services/api';

interface Props {
  apiService: AlertsApiService;
  onToast: (title: string, color: 'success' | 'danger' | 'primary', text?: string) => void;
}

const QUICK_RANGES = [
  { id: '24h', label: 'Last 24 hours', from: 'now-24h' },
  { id: '7d', label: 'Last 7 days', from: 'now-7d' },
  { id: '30d', label: 'Last 30 days', from: 'now-30d' },
  { id: '90d', label: 'Last 90 days', from: 'now-90d' },
];

function formatMinutes(minutes: number | null): string {
  if (minutes == null) return 'N/A';
  if (minutes < 60) return `${Math.round(minutes)}m`;
  if (minutes < 60 * 24) return `${(minutes / 60).toFixed(1)}h`;
  return `${(minutes / (60 * 24)).toFixed(1)}d`;
}

function slaColor(pct: number | null): string {
  if (pct == null) return 'subdued';
  if (pct >= 90) return 'success';
  if (pct >= 70) return 'warning';
  return 'danger';
}

export const ReportsView: React.FC<Props> = ({ apiService, onToast }) => {
  const [rangeId, setRangeId] = useState('7d');
  const [loading, setLoading] = useState(true);
  const [metrics, setMetrics] = useState<ReportMetrics | null>(null);

  const load = useCallback(async () => {
    const range = QUICK_RANGES.find((r) => r.id === rangeId) || QUICK_RANGES[1];
    try {
      setLoading(true);
      const res = await apiService.fetchReportMetrics(range.from, 'now');
      setMetrics(res);
    } catch (e: any) {
      onToast('Failed to load report', 'danger', e?.body?.message || e.message);
    } finally {
      setLoading(false);
    }
  }, [rangeId]);

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
      <EuiFlexGroup alignItems="center" gutterSize="m">
        <EuiFlexItem grow={false}>
          <EuiTitle size="s">
            <h2>Reporting</h2>
          </EuiTitle>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiButtonGroup
            legend="Time period"
            options={QUICK_RANGES.map((r) => ({ id: r.id, label: r.label }))}
            idSelected={rangeId}
            onChange={setRangeId}
            buttonSize="s"
          />
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiButton size="s" iconType="refresh" onClick={load} isLoading={loading}>
            Refresh
          </EuiButton>
        </EuiFlexItem>
      </EuiFlexGroup>

      <EuiSpacer size="l" />

      {loading && !metrics ? (
        <EuiLoadingSpinner size="xl" />
      ) : !metrics ? (
        <EuiText color="subdued">No data.</EuiText>
      ) : (
        <>
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
              </EuiPanel>
            </EuiFlexItem>
            <EuiFlexItem style={{ minWidth: 160 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat title={metrics.statusBreakdown.open} description="Open" titleColor="danger" />
              </EuiPanel>
            </EuiFlexItem>
            <EuiFlexItem style={{ minWidth: 160 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat title={metrics.statusBreakdown.in_progress} description="In Progress" titleColor="warning" />
              </EuiPanel>
            </EuiFlexItem>
            <EuiFlexItem style={{ minWidth: 160 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat title={metrics.statusBreakdown.closed} description="Closed" titleColor="success" />
              </EuiPanel>
            </EuiFlexItem>
          </EuiFlexGroup>

          <EuiSpacer size="m" />

          <EuiFlexGroup gutterSize="m" wrap>
            <EuiFlexItem style={{ minWidth: 200 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat
                  title={formatMinutes(metrics.meanTimeToAssignMinutes)}
                  description="Mean time to assign"
                  titleSize="m"
                />
                <EuiText size="xs" color="subdued">
                  Based on {metrics.assignedCount.toLocaleString()} assigned alert{metrics.assignedCount === 1 ? '' : 's'}
                </EuiText>
              </EuiPanel>
            </EuiFlexItem>
            <EuiFlexItem style={{ minWidth: 200 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat
                  title={formatMinutes(metrics.meanTimeToResolveMinutes)}
                  description="Mean time to resolve"
                  titleSize="m"
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
                  description="SLA compliance"
                  titleSize="m"
                  titleColor={slaColor(metrics.slaCompliancePct)}
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
        </>
      )}
    </div>
  );
};
