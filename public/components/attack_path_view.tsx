import React, { useState, useEffect, useCallback } from 'react';
import {
  EuiFlexGroup,
  EuiFlexItem,
  EuiSpacer,
  EuiLoadingSpinner,
  EuiText,
  EuiBasicTable,
  EuiTitle,
  EuiCommentList,
  EuiComment,
  EuiHealth,
  EuiBadge,
  EuiButtonGroup,
} from '@elastic/eui';
import { AttackGraph } from '../../common';
import { AlertsApiService } from '../services/api';
import { severityBand, formatAbsolute } from '../design';
import { AttackGraphCanvas } from './attack_graph_canvas';

interface Props {
  caseId: string;
  apiService: AlertsApiService;
  onError: (message: string) => void;
  onOpenAlert?: (alertId: string) => void;
}

// Aligned with the shared severity bands (12/7/4) - see public/design.ts - so a
// level reads the same here as in the alert table and the SLA report.
const levelColor = (level: number) => {
  const band = severityBand(level);
  if (band === 'critical' || band === 'high') return 'danger';
  if (band === 'medium') return 'warning';
  return 'subdued';
};

export const AttackPathView: React.FC<Props> = ({ caseId, apiService, onError, onOpenAlert }) => {
  const [loading, setLoading] = useState(true);
  const [graph, setGraph] = useState<AttackGraph | null>(null);
  const [mode, setMode] = useState<'graph' | 'timeline'>('graph');

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

  return (
    <div>
      <EuiFlexGroup alignItems="center" gutterSize="m" responsive={false} wrap>
        <EuiFlexItem grow={false}>
          <EuiText size="s" color="subdued">
            Entities and MITRE ATT&amp;CK phases derived from this case's linked alerts.
          </EuiText>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiButtonGroup
            legend="View"
            buttonSize="compressed"
            options={[
              { id: 'graph', label: 'Graph' },
              { id: 'timeline', label: 'Timeline' },
            ]}
            idSelected={mode}
            onChange={(id) => setMode(id as 'graph' | 'timeline')}
          />
        </EuiFlexItem>
      </EuiFlexGroup>

      <EuiSpacer size="m" />

      {mode === 'graph' ? (
        <>
          <AttackGraphCanvas graph={graph} onSelectAlert={onOpenAlert} />

          <EuiSpacer size="l" />
          <EuiTitle size="xs">
            <h3>Kill-chain phases</h3>
          </EuiTitle>
          <EuiSpacer size="s" />
          {graph.killChain.length === 0 ? (
            <EuiText size="s" color="subdued">
              No alerts in this case carry MITRE ATT&amp;CK tactic/technique data — common with default Wazuh rulesets.
              The graph above still maps hosts and accounts.
            </EuiText>
          ) : (
            <EuiBasicTable
              items={graph.killChain}
              columns={[
                { field: 'tactic', name: 'Tactic', width: '18%' },
                {
                  field: 'techniques',
                  name: 'Techniques',
                  width: '32%',
                  render: (techniques: string[]) => (
                    <EuiFlexGroup gutterSize="xs" wrap responsive={false} style={{ paddingRight: 12 }}>
                      {techniques.map((t) => (
                        <EuiFlexItem grow={false} key={t}>
                          <EuiBadge>{t}</EuiBadge>
                        </EuiFlexItem>
                      ))}
                    </EuiFlexGroup>
                  ),
                },
                { field: 'alertCount', name: 'Alerts', width: '80px', align: 'right' },
                { field: 'firstSeen', name: 'First seen', render: (v: string) => formatAbsolute(v) },
                { field: 'lastSeen', name: 'Last seen', render: (v: string) => formatAbsolute(v) },
              ] as any}
            />
          )}
        </>
      ) : (
        <>
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
                  timestamp={formatAbsolute(hop.timestamp)}
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
                    {onOpenAlert && (
                      <EuiFlexItem grow={false}>
                        <EuiBadge color="hollow" iconType="expand" onClick={() => onOpenAlert(hop.alertId)} onClickAriaLabel="Open alert">
                          Open alert
                        </EuiBadge>
                      </EuiFlexItem>
                    )}
                  </EuiFlexGroup>
                </EuiComment>
              ))}
            </EuiCommentList>
          )}
        </>
      )}
    </div>
  );
};
