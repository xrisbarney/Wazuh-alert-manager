/**
 * @jest-environment jsdom
 */
import React from 'react';
import { configure, fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { ReportMetrics, SlaPolicyResponse } from '../../common';
import { DispositionsSection, ReportsView, SlaEnforcementSection } from './reports_view';

// The trend charts are @elastic/charts canvases; jsdom cannot lay them out and
// the SLA section does not depend on them.
jest.mock('./report_charts', () => ({
  AlertTrendChart: () => <div data-test-subj="chartStub" />,
  StatusTrendChart: () => <div data-test-subj="chartStub" />,
}));

configure({ testIdAttribute: 'data-test-subj' });

const metrics: ReportMetrics = {
  from: '2026-11-14T00:00:00.000Z',
  to: '2026-11-21T00:00:00.000Z',
  totalAlerts: 12,
  exact: true,
  alertBasis: 'exact_cohort',
  timingBasis: 'exact_cohort',
  caseBasis: 'exact_cohort',
  coverage: { closedMissingReporting: 0, assignedMissingReporting: 0 },
  statusBreakdown: { open: 5, in_progress: 2, closed: 5 },
  alertsPerDay: [],
  statusPerDay: [],
  resolvedCount: 5,
  assignedCount: 7,
  meanTimeToResolveMinutes: 30,
  meanTimeToAssignMinutes: 5,
  slaCompliancePct: 80,
  slaBreakdown: [{ label: 'critical', met: 4, breached: 1 }],
  slaPolicy: [],
  analysts: [],
  caseAnalysts: [],
  cases: {
    totalCases: 1,
    statusBreakdown: { open: 1, in_progress: 0, closed: 0 },
    severityBreakdown: { low: 0, medium: 0, high: 1, critical: 0 },
    meanTimeToCloseMinutes: null,
    closedCount: 0,
  },
  slaCurrentlyBreached: { asOf: '2026-11-21T10:00:00.000Z', alerts: 3, cases: 1, byBand: { critical: 2, high: 2, medium: 0, low: 0 } },
  slaBreachesInPeriod: { total: 6, alerts: 5, cases: 1 },
  slaEscalationsInPeriod: {
    total: 4,
    byEscalation: [
      { id: 'crit-unassigned', name: 'Critical unassigned', count: 3 },
      { id: 'high-stale', name: 'High stale', count: 1 },
    ],
  },
};

const escalation = {
  id: 'crit-unassigned',
  name: 'Critical unassigned',
  target: 'alert' as const,
  thresholdPercent: 50,
  condition: 'unassigned' as const,
  actions: { assignTo: 'soc-lead' },
  enabled: true,
};

function policyWith(escalations: any[]): SlaPolicyResponse {
  const targets = {
    critical: { resolveMinutes: 60, assignMinutes: 15 },
    high: { resolveMinutes: 240, assignMinutes: 60 },
    medium: { resolveMinutes: 1440, assignMinutes: 360 },
    low: { resolveMinutes: 4320, assignMinutes: 1080 },
  };
  return { policy: { targets, escalations }, defaults: { targets, escalations: [] } } as SlaPolicyResponse;
}

describe('SlaEnforcementSection', () => {
  test('renders the currently breached, breaches and escalations tiles with the escalation table', () => {
    render(<SlaEnforcementSection metrics={metrics} slaPolicy={policyWith([escalation])} />);
    expect(screen.getByTestId('wamReportSlaBreachedNow').textContent).toContain('3 / 1');
    expect(screen.getByTestId('wamReportSlaBreachedNowBands').textContent).toBe('By severity: Critical 2 · High 2');
    expect(screen.getByTestId('wamReportSlaBreachesInPeriod').textContent).toContain('6');
    expect(screen.getByText('5 alerts, 1 cases')).toBeTruthy();
    expect(screen.getByTestId('wamReportSlaEscalationsInPeriod').textContent).toContain('4');
    const table = screen.getByTestId('wamReportSlaEscalationTable');
    expect(table.textContent).toContain('Critical unassigned');
    expect(table.textContent).toContain('crit-unassigned');
    expect(table.textContent).toContain('High stale');
    expect(screen.queryByTestId('wamReportSlaEscalationEmpty')).toBeNull();
  });

  test('tells the reader the policy has no escalations when none are configured', () => {
    render(
      <SlaEnforcementSection
        metrics={{ ...metrics, slaCurrentlyBreached: { ...metrics.slaCurrentlyBreached!, alerts: 0, cases: 0, byBand: { critical: 0, high: 0, medium: 0, low: 0 } }, slaEscalationsInPeriod: { total: 0, byEscalation: [] } }}
        slaPolicy={policyWith([])}
      />
    );
    expect(screen.getByTestId('wamReportSlaBreachedNow').textContent).toContain('0 / 0');
    expect(screen.getByTestId('wamReportSlaBreachedNowBands').textContent).toBe('Nothing is breached right now.');
    expect(screen.getByTestId('wamReportSlaEscalationsInPeriod').textContent).toContain('0');
    expect(screen.queryByTestId('wamReportSlaEscalationTable')).toBeNull();
    expect(screen.getByTestId('wamReportSlaEscalationEmpty').textContent).toContain('No escalation rules are configured');
  });

  test('distinguishes "rules exist but none applied" from "no rules", and tolerates an unknown policy', () => {
    const none = { ...metrics, slaEscalationsInPeriod: { total: 0, byEscalation: [] } };
    const { unmount } = render(<SlaEnforcementSection metrics={none} slaPolicy={policyWith([escalation])} />);
    expect(screen.getByTestId('wamReportSlaEscalationEmpty').textContent).toBe('No escalations were applied in this period.');
    unmount();
    render(<SlaEnforcementSection metrics={none} slaPolicy={null} />);
    expect(screen.getByTestId('wamReportSlaEscalationEmpty').textContent).toBe('No escalations were applied in this period.');
  });

  test('renders nothing for a payload without the enforcement figures', () => {
    const { container } = render(
      <SlaEnforcementSection
        metrics={{ ...metrics, slaCurrentlyBreached: undefined, slaBreachesInPeriod: undefined, slaEscalationsInPeriod: undefined }}
        slaPolicy={policyWith([escalation])}
      />
    );
    expect(container.innerHTML).toBe('');
  });
});

describe('ReportsView', () => {
  test('shows the SLA enforcement section under the SLA breakdown of the overview', async () => {
    const apiService = {
      fetchReportMetrics: jest.fn(async () => metrics),
      fetchSlaPolicy: jest.fn(async () => policyWith([escalation])),
    } as any;
    render(<ReportsView apiService={apiService} onToast={jest.fn()} />);
    await waitFor(() => expect(screen.getByTestId('wamReportSlaEnforcement')).toBeTruthy());
    expect(screen.getByTestId('wamReportSlaBreachedNow').textContent).toContain('3 / 1');
    expect(screen.getByTestId('wamReportSlaEscalationTable').textContent).toContain('Critical unassigned');
    const overview = screen.getByTestId('wamReportSlaEnforcement').parentElement!;
    expect(overview.textContent!.indexOf('SLA breakdown by severity')).toBeLessThan(overview.textContent!.indexOf('SLA enforcement'));
  });

  test('the header carries the Export menu for the selected window (step 10.3), enabled once the metrics are in', async () => {
    const apiService = {
      fetchReportMetrics: jest.fn(async () => metrics),
      fetchSlaPolicy: jest.fn(async () => policyWith([escalation])),
      downloadReportExport: jest.fn(async () => ({ blob: new Blob(['x']), filename: 'wam-report-2026-11-21-now-7d_now.md', truncated: false })),
      reportExportUrl: jest.fn(() => '/api/wazuh_alert_manager/reports/export?format=html&inline=1&from=now-7d&to=now&print=1'),
    } as any;
    render(<ReportsView apiService={apiService} onToast={jest.fn()} />);
    await waitFor(() => expect(screen.getByTestId('wamReportSlaEnforcement')).toBeTruthy());
    const button = screen.getByTestId('wamReportExport') as HTMLButtonElement;
    expect(button.closest('.wamReportToolbar')).not.toBeNull();
    expect(button.disabled).toBe(false);
    fireEvent.click(button);
    for (const format of ['html', 'markdown', 'csv', 'json', 'pdf']) expect(screen.getByTestId(`wamReportExport-${format}`)).toBeTruthy();
    fireEvent.click(screen.getByTestId('wamReportExport-markdown'));
    await waitFor(() => expect(apiService.downloadReportExport).toHaveBeenCalledWith('now-7d', 'now', 'markdown'));
  });
});

describe('DispositionsSection (step 2.4)', () => {
  const withDispositions: ReportMetrics = {
    ...metrics,
    dispositions: { true_positive: 2, false_positive: 6, benign: 1, duplicate: 0, undetermined: 1 },
    falsePositiveByRule: [
      { rule_id: '5710', description: 'sshd: brute force', closed: 8, false_positive: 6, rate: 0.75 },
      { rule_id: '100002', description: null, closed: 2, false_positive: 0, rate: 0 },
    ],
  };

  test('renders the donut legend and the false-positive table', () => {
    render(<DispositionsSection metrics={withDispositions} />);
    const section = screen.getByTestId('wamReportDispositions');
    expect(section.textContent).toContain('Dispositions');
    const donut = screen.getByTestId('wamReportDispositionsDonut');
    expect(donut.textContent).toContain('False positive');
    expect(donut.textContent).toContain('True positive');
    const table = screen.getByTestId('wamReportFalsePositiveTable');
    expect(table.textContent).toContain('5710');
    expect(table.textContent).toContain('sshd: brute force');
    expect(table.textContent).toContain('75%');
    expect(table.textContent).toContain('100002');
    expect(screen.queryByTestId('wamReportFalsePositiveEmpty')).toBeNull();
  });

  test('an empty period says so; a payload without the figures renders nothing', () => {
    render(<DispositionsSection metrics={{ ...withDispositions, dispositions: { true_positive: 0, false_positive: 0, benign: 0, duplicate: 0, undetermined: 0 }, falsePositiveByRule: [] }} />);
    expect(screen.getByTestId('wamReportFalsePositiveEmpty').textContent).toBe('No alerts were closed in this period.');
    const { container } = render(<DispositionsSection metrics={metrics} />);
    expect(container.innerHTML).toBe('');
  });

  test('the overview places the section between the response outcomes and the SLA breakdown', async () => {
    const apiService = {
      fetchReportMetrics: jest.fn(async () => withDispositions),
      fetchSlaPolicy: jest.fn(async () => policyWith([escalation])),
    } as any;
    render(<ReportsView apiService={apiService} onToast={jest.fn()} />);
    await waitFor(() => expect(screen.getByTestId('wamReportDispositions')).toBeTruthy());
    const overview = screen.getByTestId('wamReportDispositions').parentElement!;
    const text = overview.textContent!;
    expect(text.indexOf('Response outcomes')).toBeLessThan(text.indexOf('False-positive rate by rule'));
    expect(text.indexOf('False-positive rate by rule')).toBeLessThan(text.indexOf('SLA breakdown by severity'));
  });
});
