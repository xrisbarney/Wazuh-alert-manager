import React, { useState, useEffect, useCallback } from 'react';
import {
  EuiFlexGroup,
  EuiFlexItem,
  EuiPanel,
  EuiStat,
  EuiSpacer,
  EuiLoadingSpinner,
  EuiText,
  EuiBasicTable,
  EuiTitle,
  EuiCommentList,
  EuiComment,
  EuiHealth,
  EuiBadge,
} from '@elastic/eui';
import { AttackGraph } from '../../common';
import { AlertsApiService } from '../services/api';

interface Props {
  caseId: string;
  apiService: AlertsApiService;
  onError: (message: string) => void;
}

const levelColor = (level: number) => (level >= 7 ? 'danger' : level >= 5 ? 'warning' : 'success');

export const AttackPathView: React.FC<Props> = ({ caseId, apiService, onError }) => {
  const [loading, setLoading] = useState(true);
  const [graph, setGraph] = useState<AttackGraph | null>(null);

  const load = useCallback(async () => {
    try {
      setLoading(true);
      const res = await apiService.fetchAttackPath(caseId);
      setGraph(res);
    } catch (e) {
      onError('Failed to load attack path');
    } finally {
      setLoading(false);
    }
  }, [caseId]);

  useEffect(() => {
    load();
  }, [load]);

  if (loading) return <EuiLoadingSpinner size="xl" />;
  if (!graph) return <EuiText color="subdued">No data.</EuiText>;

  const hostCount = graph.nodes.filter((n) => n.type === 'host').length;
  const userCount = graph.nodes.filter((n) => n.type === 'user').length;
  const techniqueCount = graph.nodes.filter((n) => n.type === 'technique').length;

  return (
    <div>
      <EuiText size="s" color="subdued">
        Entities and MITRE ATT&amp;CK phases derived from this case's linked alerts - a starting point for tracing
        how the incident unfolded. Full graph visualization is planned; see the README roadmap.
      </EuiText>
      <EuiSpacer size="m" />

      <EuiFlexGroup gutterSize="m">
        <EuiFlexItem>
          <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
            <EuiStat title={hostCount} description="Hosts involved" titleSize="m" />
          </EuiPanel>
        </EuiFlexItem>
        <EuiFlexItem>
          <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
            <EuiStat title={userCount} description="Accounts involved" titleSize="m" />
          </EuiPanel>
        </EuiFlexItem>
        <EuiFlexItem>
          <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
            <EuiStat title={techniqueCount} description="ATT&CK techniques" titleSize="m" />
          </EuiPanel>
        </EuiFlexItem>
      </EuiFlexGroup>

      <EuiSpacer size="l" />

      <EuiTitle size="xs">
        <h3>Kill-chain phases</h3>
      </EuiTitle>
      <EuiSpacer size="s" />
      {graph.killChain.length === 0 ? (
        <EuiText size="s" color="subdued">
          No alerts in this case carry MITRE ATT&amp;CK tactic/technique data.
        </EuiText>
      ) : (
        <EuiBasicTable
          items={graph.killChain}
          columns={[
            { field: 'tactic', name: 'Tactic' },
            {
              field: 'techniques',
              name: 'Techniques',
              render: (techniques: string[]) => techniques.map((t) => <EuiBadge key={t}>{t}</EuiBadge>),
            },
            { field: 'alertCount', name: 'Alerts' },
            { field: 'firstSeen', name: 'First seen', render: (v: string) => new Date(v).toLocaleString() },
            { field: 'lastSeen', name: 'Last seen', render: (v: string) => new Date(v).toLocaleString() },
          ]}
        />
      )}

      <EuiSpacer size="l" />

      <EuiTitle size="xs">
        <h3>Chronological path</h3>
      </EuiTitle>
      <EuiSpacer size="s" />
      {graph.hops.length === 0 ? (
        <EuiText size="s" color="subdued">
          No hops to show.
        </EuiText>
      ) : (
        <EuiCommentList>
          {graph.hops.map((hop, idx) => (
            <EuiComment
              key={`${hop.alertId}-${idx}`}
              username={hop.host || 'unknown host'}
              timestamp={new Date(hop.timestamp).toLocaleString()}
              event={hop.ruleDescription}
              timelineAvatarAriaLabel="alert"
            >
              <EuiFlexGroup gutterSize="s" alignItems="center" wrap>
                <EuiFlexItem grow={false}>
                  <EuiHealth color={levelColor(hop.level)}>Level {hop.level}</EuiHealth>
                </EuiFlexItem>
                {hop.users.map((u) => (
                  <EuiFlexItem grow={false} key={u}>
                    <EuiBadge color="hollow">user: {u}</EuiBadge>
                  </EuiFlexItem>
                ))}
                {hop.tactics.map((t) => (
                  <EuiFlexItem grow={false} key={t}>
                    <EuiBadge color="primary">{t}</EuiBadge>
                  </EuiFlexItem>
                ))}
                {hop.techniques.map((t) => (
                  <EuiFlexItem grow={false} key={t}>
                    <EuiBadge color="default">{t}</EuiBadge>
                  </EuiFlexItem>
                ))}
              </EuiFlexGroup>
            </EuiComment>
          ))}
        </EuiCommentList>
      )}
    </div>
  );
};
