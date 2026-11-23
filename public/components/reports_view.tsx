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
import { ReportMetrics, SlaPolicyResponse, DISPOSITIONS, DISPOSITION_LABELS } from '../../common';
import type { Disposition, FalsePositiveByRuleRow } from '../../common';
import { slaTargetsText } from './sla_targets_text';
import { AlertsApiService } from '../services/api';
import { formatDuration, STATUS_HEX, SEVERITY_HEX, STATUS_LABEL } from '../design';
import { AlertTrendChart, StatusTrendChart } from './report_charts';
import { DonutBreakdown } from './donut_breakdown';
import { DeltaChip } from './delta_chip';
import { ReportExportMenu } from './report_export_menu';

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

const SLA_BAND_LABEL: Record<string, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };

/**
 * SLA enforcement (step 3.4): what the escalation scanner sees right now and
 * what it did in the selected period. "Currently breached" is bound to now,
 * not to the cohort; the breach and escalation counts come from the
 * scanner's activity events whose timestamp falls in the period.
 */
// Concrete fills for the dispositions donut (SVG needs hex, not EUI tokens);
// the same semantics as DISPOSITION_BADGE_COLOR: true positive = danger red,
// false positive = neutral grey, benign = green, duplicate = light blue,
// undetermined = amber.
export const DISPOSITION_HEX: Record<Disposition, string> = {
  true_positive: '#BD271E',
  false_positive: '#98A2B3',
  benign: '#54B399',
  duplicate: '#6092C0',
  undetermined: '#FEC514',
};

/**
 * Dispositions (step 2.4): donut of the alerts closed in the period by
 * outcome and the false-positive rate by rule. Renders nothing for a payload
 * without the figures (an older server).
 */
export const DispositionsSection: React.FC<{ metrics: ReportMetrics }> = ({ metrics }) => {
  const dispositions = metrics.dispositions;
  const byRule = metrics.falsePositiveByRule;
  if (!dispositions && !byRule) return null;
  const closedInPeriod = dispositions ? DISPOSITIONS.reduce((sum, value) => sum + (dispositions[value] ?? 0), 0) : 0;
  return (
    <div className="wamReportDispositions" data-test-subj="wamReportDispositions">
      <EuiSpacer size="l" />
      <EuiHorizontalRule margin="none" />
      <EuiSpacer size="m" />
      <EuiTitle size="xs"><h3>Dispositions</h3></EuiTitle>
      <EuiText size="xs" color="subdued">
        Outcome recorded on the alerts closed in this period (by close time; an alert closed without a disposition counts as undetermined).
      </EuiText>
      <EuiSpacer size="s" />
      <EuiFlexGroup gutterSize="m" wrap className="wamReportCharts">
        <EuiFlexItem style={{ minWidth: 300 }} grow={false}>
          <EuiPanel paddingSize="m" hasShadow={false} hasBorder className="wamReportPanel">
            <EuiTitle size="xxs"><h4>Alerts closed by disposition</h4></EuiTitle>
            <EuiText size="xs" color="subdued">Outcome recorded on the alerts closed in the period</EuiText>
            <EuiSpacer size="s" />
            {dispositions ? (
              <div data-test-subj="wamReportDispositionsDonut">
                <DonutBreakdown
                  centerLabel="closed"
                  centerValue={closedInPeriod}
                  segments={DISPOSITIONS.map((value) => ({ label: DISPOSITION_LABELS[value], value: dispositions[value] ?? 0, color: DISPOSITION_HEX[value] }))}
                />
              </div>
            ) : null}
          </EuiPanel>
        </EuiFlexItem>
        <EuiFlexItem style={{ minWidth: 360 }}>
          <EuiPanel paddingSize="m" hasShadow={false} hasBorder className="wamReportPanel">
            <EuiTitle size="xxs"><h4>False-positive rate by rule</h4></EuiTitle>
            <EuiText size="xs" color="subdued">Top {byRule?.length ?? 0} rules by alerts closed in the period.</EuiText>
            <EuiSpacer size="s" />
            {!byRule || byRule.length === 0 ? (
              <EuiText size="s" color="subdued" data-test-subj="wamReportFalsePositiveEmpty">No alerts were closed in this period.</EuiText>
            ) : (
              <EuiBasicTable<FalsePositiveByRuleRow>
                className="wamReportFalsePositiveTable"
                data-test-subj="wamReportFalsePositiveTable"
                items={byRule}
                columns={[
                  { field: 'rule_id', name: 'Rule', width: '110px' },
                  { field: 'description', name: 'Description', render: (value: string | null) => value || '-' },
                  { field: 'closed', name: 'Closed', width: '90px', align: 'right' },
                  { field: 'false_positive', name: 'False positives', width: '130px', align: 'right' },
                  { field: 'rate', name: 'Rate', width: '90px', align: 'right', render: (rate: number) => `${(rate * 100).toFixed(0)}%` },
                ]}
              />
            )}
          </EuiPanel>
        </EuiFlexItem>
      </EuiFlexGroup>
    </div>
  );
};

export const SlaEnforcementSection: React.FC<{ metrics: ReportMetrics; slaPolicy: SlaPolicyResponse | null }> = ({
  metrics,
  slaPolicy,
}) => {
  const breached = metrics.slaCurrentlyBreached;
  const breaches = metrics.slaBreachesInPeriod;
  const escalations = metrics.slaEscalationsInPeriod;
  if (!breached && !breaches && !escalations) return null;
  const policyEscalations = slaPolicy?.policy?.escalations;
  const policyHasNoEscalations = Array.isArray(policyEscalations) && policyEscalations.length === 0;
  const rows = escalations?.byEscalation || [];
  const bandSummary = breached
    ? Object.keys(SLA_BAND_LABEL)
        .filter((band) => (breached.byBand?.[band as keyof typeof breached.byBand] ?? 0) > 0)
        .map((band) => `${SLA_BAND_LABEL[band]} ${breached.byBand[band as keyof typeof breached.byBand]}`)
        .join(' · ')
    : '';
  return (
    <div className="wamReportSlaEnforcement" data-test-subj="wamReportSlaEnforcement">
      <EuiSpacer size="l" />
      <EuiHorizontalRule margin="none" />
      <EuiSpacer size="m" />
      <EuiTitle size="xs">
        <h3>SLA enforcement</h3>
      </EuiTitle>
      <EuiText size="xs" color="subdued">
        Currently breached is a live count (not bound to the period): open or in-progress alerts and open cases past their
        resolve target. Breaches and escalations in period are the scanner&apos;s events whose time falls in the selected period.
      </EuiText>
      <EuiSpacer size="s" />
      <EuiFlexGroup gutterSize="m" wrap className="wamReportStats">
        <EuiFlexItem style={{ minWidth: 200 }}>
          <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
            <EuiStat
              title={breached ? `${breached.alerts.toLocaleString()} / ${breached.cases.toLocaleString()}` : 'N/A'}
              description={
                <>
                  Currently breached (alerts / cases){' '}
                  <EuiIconTip
                    type="questionInCircle"
                    content="Open or in-progress alerts and open cases that carry a breach stamp or whose resolve due date has passed, as of the last refresh. Not bound to the selected period."
                  />
                </>
              }
              titleSize="m"
              titleColor={breached && breached.alerts + breached.cases > 0 ? 'danger' : 'subdued'}
              data-test-subj="wamReportSlaBreachedNow"
            />
            {breached ? (
              <EuiText size="xs" color="subdued" data-test-subj="wamReportSlaBreachedNowBands">
                {bandSummary ? `By severity: ${bandSummary}` : 'Nothing is breached right now.'}
              </EuiText>
            ) : null}
          </EuiPanel>
        </EuiFlexItem>
        <EuiFlexItem style={{ minWidth: 200 }}>
          <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
            <EuiStat
              title={breaches ? breaches.total.toLocaleString() : 'N/A'}
              description={
                <>
                  Breaches in period{' '}
                  <EuiIconTip
                    type="questionInCircle"
                    content="SLA breach events the scanner recorded in the selected period (one per alert or case, when its resolve due date first passed)."
                  />
                </>
              }
              titleSize="m"
              titleColor={breaches && breaches.total > 0 ? 'warning' : 'subdued'}
              data-test-subj="wamReportSlaBreachesInPeriod"
            />
            {breaches ? (
              <EuiText size="xs" color="subdued">
                {breaches.alerts.toLocaleString()} alerts, {breaches.cases.toLocaleString()} cases
              </EuiText>
            ) : null}
          </EuiPanel>
        </EuiFlexItem>
        <EuiFlexItem style={{ minWidth: 200 }}>
          <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
            <EuiStat
              title={escalations ? escalations.total.toLocaleString() : 'N/A'}
              description={
                <>
                  Escalations in period{' '}
                  <EuiIconTip
                    type="questionInCircle"
                    content="Escalation rules the scanner applied in the selected period (one event per rule and record)."
                  />
                </>
              }
              titleSize="m"
              titleColor={escalations && escalations.total > 0 ? 'accent' : 'subdued'}
              data-test-subj="wamReportSlaEscalationsInPeriod"
            />
            {escalations ? (
              <EuiText size="xs" color="subdued">
                {rows.length.toLocaleString()} rule{rows.length === 1 ? '' : 's'} applied
              </EuiText>
            ) : null}
          </EuiPanel>
        </EuiFlexItem>
      </EuiFlexGroup>
      {escalations ? (
        <>
          <EuiSpacer size="s" />
          {rows.length === 0 ? (
            <EuiText size="s" color="subdued" data-test-subj="wamReportSlaEscalationEmpty">
              {policyHasNoEscalations
                ? 'No escalation rules are configured. Add them under Settings > SLA to auto-assign, comment on or raise the severity of records that are running late.'
                : 'No escalations were applied in this period.'}
            </EuiText>
          ) : (
            <EuiBasicTable
              className="wamReportSlaEscalationTable"
              data-test-subj="wamReportSlaEscalationTable"
              items={rows}
              columns={[
                { field: 'name', name: 'Escalation' },
                { field: 'id', name: 'Rule id' },
                { field: 'count', name: 'Applied', align: 'right', render: (count: unknown) => Number(count).toLocaleString() },
              ]}
            />
          )}
        </>
      ) : null}
    </div>
  );
};

export const ReportsView: React.FC<Props> = ({ apiService, onToast }) => {
  // start/end are date-math or absolute-ISO strings; the reports API feeds them
  // straight into an OpenSearch range query, which accepts both. EuiSuperDatePicker
  // provides the quick ranges AND absolute custom range selection.
  const [start, setStart] = useState('now-7d');
  const [end, setEnd] = useState('now');
  const [loading, setLoading] = useState(true);
  const [metrics, setMetrics] = useState<ReportMetrics | null>(null);
  // The SLA policy the targets text cites (step 3.1); fetched once, independent of the date range.
  const [slaPolicy, setSlaPolicy] = useState<SlaPolicyResponse | null>(null);
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
    let active = true;
    apiService
      .fetchSlaPolicy()
      .then((res) => { if (active) setSlaPolicy(res); })
      .catch(() => { if (active) setSlaPolicy(null); });
    return () => { active = false; };
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
      <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" gutterSize="m" wrap className="wamReportToolbar">
        <EuiFlexItem>
          <EuiTitle size="s">
            <h2>Cohort</h2>
          </EuiTitle>
          <EuiText size="s" color="subdued">
            Alerts that occurred in the selected period, with their current status and outcomes.{' '}
            <EuiIconTip type="iInCircle" content={REPORT_SCOPE} aria-label="Report data scope" />
          </EuiText>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <ReportExportMenu apiService={apiService} from={start} to={end} disabled={loading || !metrics} onToast={onToast} />
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
        <EuiText size="s" color="subdued">No data.</EuiText>
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
                <EuiStat title={metrics.totalAlerts.toLocaleString()} description="Alerts in cohort" titleSize="m" />
                <DeltaChip current={metrics.totalAlerts} previous={prev?.totalAlerts} higherIsBetter={false} />
              </EuiPanel>
            </EuiFlexItem>
            <EuiFlexItem style={{ minWidth: 160 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat title={metrics.statusBreakdown.open} description="Currently open" titleColor="primary" titleSize="m" />
              </EuiPanel>
            </EuiFlexItem>
            <EuiFlexItem style={{ minWidth: 160 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat title={metrics.statusBreakdown.in_progress} description="Currently in progress" titleColor="accent" titleSize="m" />
              </EuiPanel>
            </EuiFlexItem>
            <EuiFlexItem style={{ minWidth: 160 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat title={metrics.statusBreakdown.closed} description="Currently closed" titleColor="subdued" titleSize="m" />
              </EuiPanel>
            </EuiFlexItem>
          </EuiFlexGroup>

          <EuiSpacer size="m" />

          <EuiFlexGroup gutterSize="m" wrap className="wamReportCharts">
            <EuiFlexItem style={{ minWidth: 320 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder className="wamReportPanel">
                <EuiTitle size="xxs">
                  <h4>Alert cohort by day</h4>
                </EuiTitle>
                <EuiText size="xs" color="subdued">Alerts grouped by occurrence date</EuiText>
                <EuiSpacer size="s" />
                <AlertTrendChart data={metrics.alertsPerDay || []} />
              </EuiPanel>
            </EuiFlexItem>
            <EuiFlexItem style={{ minWidth: 320 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder className="wamReportPanel">
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
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder className="wamReportPanel">
                <EuiTitle size="xxs">
                  <h4>Current cohort disposition</h4>
                </EuiTitle>
                <EuiText size="xs" color="subdued">Current status of the alerts in the cohort</EuiText>
                <EuiSpacer size="s" />
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

          <DispositionsSection metrics={metrics} />

          <EuiSpacer size="l" />
          <EuiHorizontalRule margin="none" />
          <EuiSpacer size="m" />

          <EuiTitle size="xs">
            <h3>SLA breakdown by severity</h3>
          </EuiTitle>
          <EuiText size="xs" color="subdued">
            {slaTargetsText(slaPolicy, metrics)}
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
                  render: (pct: unknown) => (typeof pct === 'number' ? `${pct.toFixed(0)}%` : 'N/A'),
                },
              ]}
            />
          )}

          <SlaEnforcementSection metrics={metrics} slaPolicy={slaPolicy} />

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
          <EuiFlexGroup gutterSize="m" wrap className="wamReportStats">
            <EuiFlexItem style={{ minWidth: 160 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat title={metrics.cases.totalCases.toLocaleString()} description="Cases created" titleSize="m" />
              </EuiPanel>
            </EuiFlexItem>
            <EuiFlexItem style={{ minWidth: 140 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat title={metrics.cases.statusBreakdown.open} description="Currently open" titleColor="primary" titleSize="m" />
              </EuiPanel>
            </EuiFlexItem>
            <EuiFlexItem style={{ minWidth: 140 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat
                  title={metrics.cases.statusBreakdown.in_progress ?? 0}
                  description="Currently in progress"
                  titleColor="accent"
                  titleSize="m"
                />
              </EuiPanel>
            </EuiFlexItem>
            <EuiFlexItem style={{ minWidth: 140 }}>
              <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
                <EuiStat title={metrics.cases.statusBreakdown.closed} description="Currently closed" titleColor="subdued" titleSize="m" />
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
            <EuiFlexGroup gutterSize="m" wrap className="wamReportCharts">
              <EuiFlexItem style={{ minWidth: 300 }} grow={false}>
                <EuiPanel paddingSize="m" hasShadow={false} hasBorder className="wamReportPanel">
                  <EuiTitle size="xxs">
                    <h4>Cases by severity</h4>
                  </EuiTitle>
                  <EuiText size="xs" color="subdued">Cases created in the period, by severity</EuiText>
                  <EuiSpacer size="s" />
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
