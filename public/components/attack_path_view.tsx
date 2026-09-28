import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import {
  EuiFlexGroup,
  EuiFlexItem,
  EuiSpacer,
  EuiLoadingSpinner,
  EuiText,
  EuiTitle,
  EuiCommentList,
  EuiComment,
  EuiHealth,
  EuiBadge,
  EuiCallOut,
} from '@elastic/eui';
import { AttackGraph, buildAttackStory, TACTIC_PLAIN, TECHNIQUE_PLAIN } from '../../common';
import { AlertsApiService } from '../services/api';
import { severityBand, formatAbsolute, formatDuration } from '../design';
import { AttackGraphCanvas, StorySelection } from './attack_graph_canvas';
import { storyTone, TONE_HEX } from './attack_story_tone';

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

// The graph's Light/Dark choice is a per-browser preference, like the design's.
const THEME_KEY = 'wamAttackGraphTheme';
type GraphTheme = 'light' | 'dark';
const readTheme = (): GraphTheme => {
  try {
    return window.localStorage.getItem(THEME_KEY) === 'dark' ? 'dark' : 'light';
  } catch (e) {
    return 'light';
  }
};

const SunIcon = () => (
  <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></svg>
);
const MoonIcon = () => (
  <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" /></svg>
);

const plural = (n: number, word: string) => `${n.toLocaleString()} ${word}${n === 1 ? '' : 's'}`;

function timeRange(first: string | null, last: string | null): string | null {
  if (!first || !last) return null;
  const a = new Date(first);
  const b = new Date(last);
  if (isNaN(a.getTime()) || isNaN(b.getTime())) return null;
  const day = (d: Date) => d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
  const time = (d: Date) => d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const minutes = (b.getTime() - a.getTime()) / 60000;
  const span = minutes >= 1 ? ` (~${formatDuration(minutes)})` : '';
  return day(a) === day(b)
    ? `${day(a)} · ${time(a)} → ${time(b)}${span}`
    : `${day(a)} ${time(a)} → ${day(b)} ${time(b)}${span}`;
}

export const AttackPathView: React.FC<Props> = ({ caseId, apiService, onError, onOpenAlert }) => {
  const [loading, setLoading] = useState(true);
  const [graph, setGraph] = useState<AttackGraph | null>(null);
  const [mode, setMode] = useState<'graph' | 'timeline'>('graph');
  const [selection, setSelection] = useState<StorySelection>(null);
  const [theme, setThemeState] = useState<GraphTheme>(readTheme);
  const setTheme = (next: GraphTheme) => {
    setThemeState(next);
    try { window.localStorage.setItem(THEME_KEY, next); } catch (e) { /* preference just isn't remembered */ }
  };
  const graphRef = useRef<HTMLDivElement>(null);

  const load = useCallback(async () => {
    try {
      setLoading(true);
      const res = await apiService.fetchAttackPath(caseId);
      setGraph(res);
      setSelection(null);
    } catch (e) {
      onError('Failed to load attack path');
    } finally {
      setLoading(false);
    }
  }, [caseId]);

  useEffect(() => {
    load();
  }, [load]);

  const story = useMemo(() => (graph ? buildAttackStory(graph) : null), [graph]);

  if (loading) return <EuiLoadingSpinner size="xl" />;
  if (!graph || !story) return <EuiText color="subdued">No data.</EuiText>;

  const maxTechnique = Math.max(1, ...story.techniques.map((t) => t.alertCount));
  const range = timeRange(story.firstSeen, story.lastSeen);
  const showInGraph = (nodeId: string) => {
    setSelection({ kind: 'node', id: nodeId });
    graphRef.current?.scrollIntoView?.({ behavior: 'smooth', block: 'start' });
  };

  return (
    // The dark theme only applies to the graph: the alert timeline is standard
    // dashboard UI and stays on the dashboard's own theme.
    <div className={`wamAg${mode === 'graph' && theme === 'dark' ? ' wamAg--dark' : ''}`}>
      <div className="wamAg__viewbar">
        <p>Entity co-occurrence and MITRE ATT&amp;CK context derived from this case's linked alerts.</p>
        <div className="wamAg__seg" role="group" aria-label="View">
          {([['graph', 'Entity graph'], ['timeline', 'Alert timeline']] as const).map(([id, label]) => (
            <button type="button" key={id} className={mode === id ? 'wamAg__on' : ''} aria-pressed={mode === id} onClick={() => setMode(id)}>
              {label}
            </button>
          ))}
        </div>
      </div>

      {(graph as any).truncated && (
        <>
          <EuiCallOut
            size="s"
            color="warning"
            title={`Graph limited to ${(graph as any).limit?.toLocaleString() || 'the configured limit'} linked alerts`}
          >
            This visualization includes {(graph as any).includedAlerts?.toLocaleString() || 0} resolvable alerts.
            Use the linked-alert table and narrower cases for complete evidence review.
          </EuiCallOut>
          <EuiSpacer size="m" />
        </>
      )}

      {mode === 'graph' ? (
        story.nodes.length === 0 ? (
          <EuiText size="s" color="subdued">No entities could be extracted from this case's alerts.</EuiText>
        ) : (
          <div className="wamAg__body">
            <div ref={graphRef}>
              <AttackGraphCanvas
                story={story}
                storageKey={`wamAttackGraphLayout:v1:${caseId}`}
                selection={selection}
                onSelectionChange={setSelection}
                onSelectAlert={onOpenAlert}
                headerActions={
                  <div className="wamAg__seg" role="group" aria-label="Graph theme">
                    <button type="button" className={theme === 'light' ? 'wamAg__on' : ''} aria-pressed={theme === 'light'} onClick={() => setTheme('light')}><SunIcon />Light</button>
                    <button type="button" className={theme === 'dark' ? 'wamAg__on' : ''} aria-pressed={theme === 'dark'} onClick={() => setTheme('dark')}><MoonIcon />Dark</button>
                  </div>
                }
              />
            </div>

            <div className="wamAg__panel wamAg__sec">
              <div className="wamAg__sech">
                <h2 className="wamAg__h2">How the attacker tried to get in</h2>
                {story.techniques.length > 0 && (
                  <span>MITRE ATT&amp;CK · {plural(story.techniques.length, 'technique')} · click to show in graph</span>
                )}
              </div>
              {story.techniques.length === 0 ? (
                <p className="wamAg__empty">
                  No alerts in this case carry MITRE ATT&amp;CK tactic/technique data — common with default Wazuh rulesets.
                  The graph above still maps hosts and accounts.
                </p>
              ) : (
                <div className="wamAg__tech">
                  {story.techniques.map((t) => {
                    const color = TONE_HEX[storyTone(t.maxLevel)];
                    const plain = TECHNIQUE_PLAIN[t.id];
                    return (
                      <button type="button" key={t.id} className="wamAg__tc" onClick={() => showInGraph(t.nodeId)} aria-label={`${t.label}, ${plural(t.alertCount, 'alert')}. Show in graph.`}>
                        <h3><span className="wamAg__dot" style={{ background: color }} />{t.label}</h3>
                        {t.id !== t.label && <code>{t.id}</code>}
                        <p>{plain || ' '}</p>
                        <div className="wamAg__bar">
                          <div><i style={{ width: `${(t.alertCount / maxTechnique) * 100}%`, background: color }} /></div>
                          <span>{t.alertCount.toLocaleString()}</span>
                        </div>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>

            <div className="wamAg__panel wamAg__sec">
              <div className="wamAg__sech">
                <h2 className="wamAg__h2">Kill-chain phases</h2>
                {range && <span className="wamAg__mono">{range}</span>}
              </div>
              {story.phases.length === 0 ? (
                <p className="wamAg__empty">
                  No alerts in this case carry MITRE ATT&amp;CK tactic/technique data — common with default Wazuh rulesets.
                  The graph above still maps hosts and accounts.
                </p>
              ) : (
                <div className="wamAg__phases">
                  {story.phases.map((p, i) => {
                    const tone = storyTone(p.maxLevel);
                    const color = TONE_HEX[tone];
                    return (
                      <React.Fragment key={p.tactic}>
                        {i > 0 && <div className="wamAg__chev" aria-hidden="true">›</div>}
                        <div className={`wamAg__ph${tone === 'high' ? ' wamAg__ph--hot' : ''}`} title={`First seen ${formatAbsolute(p.firstSeen)} · last seen ${formatAbsolute(p.lastSeen)}`}>
                          <h3><span className="wamAg__num" style={{ borderColor: color, color: tone === 'med' ? 'var(--ag-medink)' : tone === 'low' ? 'var(--ag-lowink)' : color }}>{i + 1}</span>{p.tactic}</h3>
                          {TACTIC_PLAIN[p.tactic] && <p>{TACTIC_PLAIN[p.tactic]}</p>}
                          <div className="wamAg__tags">
                            {p.techniques.map((t) => <span key={t} className="wamAg__tag">{t}</span>)}
                          </div>
                          <div className="wamAg__cnt"><span className="wamAg__dot" style={{ background: color }} />{plural(p.alertCount, 'alert')}</div>
                        </div>
                      </React.Fragment>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        )
      ) : (
        <>
          <EuiTitle size="xs">
            <h3>Alert chronology</h3>
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
                    {(hop.sources || []).map((ip) => (
                      <EuiFlexItem grow={false} key={`src-${ip}`}>
                        <EuiBadge color="hollow">source: {ip}</EuiBadge>
                      </EuiFlexItem>
                    ))}
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
