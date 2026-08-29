import React from 'react';
import { EuiBasicTable, EuiEmptyPrompt, EuiSpacer, EuiText, EuiBadge } from '@elastic/eui';
import { ReportMetrics } from '../../common';
import { formatDuration } from '../design';

const emptyAnalysts = (
  <EuiEmptyPrompt
    iconType="usersRolesApp"
    titleSize="xs"
    title={<h4>No assigned alerts in this period</h4>}
    body={
      <p>
        Assign alerts to analysts (from the row status area or the alert flyout) to see per-analyst breakdowns here. On
        older installations the assignment field may not be aggregatable until the index is reindexed.
      </p>
    }
  />
);

/** Workload: how many alerts each analyst holds, by status. Exact (aggregation). */
export const AnalystWorkloadTab: React.FC<{ metrics: ReportMetrics }> = ({ metrics }) => {
  const rows = metrics.analysts || [];
  if (rows.length === 0) return emptyAnalysts;
  return (
    <>
      <EuiSpacer size="m" />
      <EuiText size="s" color="subdued">
        Alerts currently assigned to each analyst in this period, by status. Exact counts.
      </EuiText>
      <EuiSpacer size="s" />
      <EuiBasicTable
        items={rows}
        columns={[
          { field: 'assignee', name: 'Analyst', sortable: true },
          { field: 'open', name: 'Open', render: (n: number) => <EuiBadge color="primary">{n}</EuiBadge> },
          { field: 'in_progress', name: 'In progress', render: (n: number) => <EuiBadge color="accent">{n}</EuiBadge> },
          { field: 'closed', name: 'Closed', render: (n: number) => <EuiBadge color="hollow">{n}</EuiBadge> },
          { field: 'total', name: 'Total', render: (n: number) => <strong>{n}</strong> },
        ]}
      />
    </>
  );
};

/** Performance: resolution throughput per analyst. Exact (write-time fields). */
export const AnalystPerformanceTab: React.FC<{ metrics: ReportMetrics }> = ({ metrics }) => {
  const rows = (metrics.analysts || []).filter((a) => a.resolvedCount > 0);
  if ((metrics.analysts || []).length === 0) return emptyAnalysts;
  return (
    <>
      <EuiSpacer size="m" />
      {rows.length === 0 ? (
        <EuiText size="s" color="subdued">
          No alerts have been resolved by an assigned analyst in this period.
        </EuiText>
      ) : (
        <EuiBasicTable
          items={rows}
          columns={[
            { field: 'assignee', name: 'Analyst', sortable: true },
            { field: 'resolvedCount', name: 'Resolved', sortable: true, render: (n: number) => <strong>{n}</strong> },
            {
              field: 'meanTimeToResolveMinutes',
              name: 'Mean time to resolve',
              render: (m: number | null) => formatDuration(m),
            },
          ]}
        />
      )}
    </>
  );
};

/** Cases owned per analyst. */
export const CaseAnalystTab: React.FC<{ metrics: ReportMetrics }> = ({ metrics }) => {
  const rows = metrics.caseAnalysts || [];
  if (rows.length === 0) {
    return (
      <EuiEmptyPrompt
        iconType="folderClosed"
        titleSize="xs"
        title={<h4>No assigned cases in this period</h4>}
        body={<p>Assign cases to analysts to see per-analyst case workload here.</p>}
      />
    );
  }
  return (
    <>
      <EuiSpacer size="m" />
      <EuiText size="s" color="subdued">
        Cases owned by each analyst, created in this period.
      </EuiText>
      <EuiSpacer size="s" />
      <EuiBasicTable
        items={rows}
        columns={[
          { field: 'assignee', name: 'Analyst', sortable: true },
          { field: 'open', name: 'Open', render: (n: number) => <EuiBadge color="primary">{n}</EuiBadge> },
          { field: 'in_progress', name: 'In progress', render: (n: number) => <EuiBadge color="accent">{n}</EuiBadge> },
          { field: 'closed', name: 'Closed', render: (n: number) => <EuiBadge color="hollow">{n}</EuiBadge> },
          { field: 'total', name: 'Total', render: (n: number) => <strong>{n}</strong> },
          {
            field: 'meanTimeToCloseMinutes',
            name: 'Mean time to close',
            render: (m: number | null) => formatDuration(m),
          },
        ]}
      />
    </>
  );
};

/** Leaderboard: analysts ranked by resolution throughput. */
export const LeaderboardTab: React.FC<{ metrics: ReportMetrics }> = ({ metrics }) => {
  const rows = [...(metrics.analysts || [])].sort((a, b) => b.resolvedCount - a.resolvedCount).slice(0, 25);
  if (rows.length === 0 || rows.every((r) => r.resolvedCount === 0)) return emptyAnalysts;
  return (
    <>
      <EuiSpacer size="m" />
      <EuiText size="s" color="subdued">
        Analysts ranked by alerts resolved in this period (exact).
      </EuiText>
      <EuiSpacer size="s" />
      <EuiBasicTable
        items={rows.map((r, i) => ({ ...r, rank: i + 1 }))}
        columns={[
          {
            field: 'rank',
            name: '#',
            width: '50px',
            render: (n: number) => (n <= 3 ? <EuiBadge color="warning">{n}</EuiBadge> : <span>{n}</span>),
          },
          { field: 'assignee', name: 'Analyst' },
          { field: 'resolvedCount', name: 'Resolved', render: (n: number) => <strong>{n}</strong> },
          { field: 'total', name: 'Assigned' },
          {
            field: 'meanTimeToResolveMinutes',
            name: 'Avg resolve',
            render: (m: number | null) => formatDuration(m),
          },
        ]}
      />
    </>
  );
};
