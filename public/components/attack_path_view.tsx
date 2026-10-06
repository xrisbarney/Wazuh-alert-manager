import React, { useState, useMemo, useRef, useEffect } from 'react';
import {
  EuiBadge,
  EuiButtonGroup,
  EuiCallOut,
  EuiIcon,
  EuiLoadingSpinner,
  EuiSpacer,
  EuiText,
  EuiTitle,
  htmlIdGenerator,
} from '@elastic/eui';
import { AttackGraph, buildAttackStory, TACTIC_PLAIN, TECHNIQUE_PLAIN } from '../../common';
import { formatAbsolute, formatDuration } from '../design';
import { AttackGraphCanvas, StorySelection } from './attack_graph_canvas';
import { AttackTimeline } from './attack_timeline';
import { storyTone, TONE_HEX } from './attack_story_tone';

interface Props {
  caseId: string;
  graph: AttackGraph | null;
  loading: boolean;
  /** Opens the Linked Alerts tab filtered to these alerts. */
  onOpenLinked?: (alertIds: string[], label: string) => void;
}

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

export const AttackPathView: React.FC<Props> = ({ caseId, graph, loading, onOpenLinked }) => {
  const [mode, setMode] = useState<'graph' | 'timeline'>('graph');
  const [selection, setSelection] = useState<StorySelection>(null);
  const graphRef = useRef<HTMLDivElement>(null);
  // EuiButtonGroup option ids become DOM ids, so keep them unique per instance.
  const viewIds = useMemo(() => {
    const id = htmlIdGenerator('wamAgView')();
    return { graph: `${id}-graph`, timeline: `${id}-timeline` };
  }, []);

  const story = useMemo(() => (graph ? buildAttackStory(graph) : null), [graph]);
  useEffect(() => setSelection(null), [graph]);

  if (loading && !graph) return <EuiLoadingSpinner size="xl" />;
  if (!graph || !story) return <EuiText color="subdued">No data.</EuiText>;

  const maxTechnique = Math.max(1, ...story.techniques.map((t) => t.alertCount));
  const range = timeRange(story.firstSeen, story.lastSeen);
  const showInGraph = (nodeId: string) => {
    setMode('graph');
    setSelection({ kind: 'node', id: nodeId });
    graphRef.current?.scrollIntoView?.({ behavior: 'smooth', block: 'start' });
  };
  const noMitre = 'No alerts in this case carry MITRE ATT&CK tactic/technique data — common with default Wazuh rulesets. The graph above still maps hosts and accounts.';

  return (
    <div className="wamAg">
      <div className="wamAg__viewbar">
        <EuiText size="s" color="subdued">
          <p>Entity relationships and MITRE ATT&amp;CK context derived from this case's linked alerts.</p>
        </EuiText>
        <EuiButtonGroup
          legend="View"
          buttonSize="compressed"
          options={[
            { id: viewIds.graph, label: 'Entity graph' },
            { id: viewIds.timeline, label: 'Alert timeline' },
          ]}
          idSelected={mode === 'timeline' ? viewIds.timeline : viewIds.graph}
          onChange={(id: string) => setMode(id === viewIds.timeline ? 'timeline' : 'graph')}
        />
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

      <div ref={graphRef}>
        {mode === 'graph' ? (
          story.nodes.length === 0 ? (
            <div className="wamAg__panel"><p className="wamAg__empty">No entities could be extracted from this case's alerts.</p></div>
          ) : (
            <AttackGraphCanvas
              story={story}
              storageKey={`wamAttackGraphLayout:v2:${caseId}`}
              selection={selection}
              onSelectionChange={setSelection}
              hops={graph.hops}
              onOpenLinked={onOpenLinked}
            />
          )
        ) : (
          <AttackTimeline hops={graph.hops} onOpenLinked={onOpenLinked} />
        )}
      </div>

      <div className="wamAg__panel wamAg__sec">
        <div className="wamAg__sech">
          <EuiTitle size="xs"><h2 className="wamAg__h2">How the attacker tried to get in</h2></EuiTitle>
          {story.techniques.length > 0 && (
            <span>MITRE ATT&amp;CK · {plural(story.techniques.length, 'technique')} · click to show in graph</span>
          )}
        </div>
        {story.techniques.length === 0 ? (
          <p className="wamAg__empty">{noMitre}</p>
        ) : (
          <div className="wamAg__tech">
            {story.techniques.map((t) => {
              const color = TONE_HEX[storyTone(t.maxLevel)];
              const plain = TECHNIQUE_PLAIN[t.id];
              return (
                <button type="button" key={t.id} className="wamAg__tc" onClick={() => showInGraph(t.nodeId)} aria-label={`${t.label}, ${plural(t.alertCount, 'alert')}. Show in graph.`}>
                  <EuiTitle size="xxs"><h3><span className="wamAg__dot" style={{ background: color }} />{t.label}</h3></EuiTitle>
                  {t.id !== t.label && <span className="wamAg__tid">{t.id}</span>}
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
          <EuiTitle size="xs"><h2 className="wamAg__h2">Kill-chain phases</h2></EuiTitle>
          {range && <span>{range}</span>}
        </div>
        {story.phases.length === 0 ? (
          <p className="wamAg__empty">{noMitre}</p>
        ) : (
          <div className="wamAg__phases">
            {story.phases.map((p, i) => {
              const tone = storyTone(p.maxLevel);
              const color = TONE_HEX[tone];
              return (
                <React.Fragment key={p.tactic}>
                  {i > 0 && <div className="wamAg__chev" aria-hidden="true"><EuiIcon type="arrowRight" color="subdued" /></div>}
                  <div className={`wamAg__ph${tone === 'high' ? ' wamAg__ph--hot' : ''}`}>
                    <EuiTitle size="xxs">
                      <h3><span className="wamAg__num" style={{ borderColor: color, color: tone === 'med' ? 'var(--ag-medink)' : tone === 'low' ? 'var(--ag-lowink)' : color }}>{i + 1}</span>{p.tactic}</h3>
                    </EuiTitle>
                    {TACTIC_PLAIN[p.tactic] && <p>{TACTIC_PLAIN[p.tactic]}</p>}
                    <div className="wamAg__tags">
                      {p.techniques.map((t) => <EuiBadge key={t} color="hollow" className="wamAg__tag">{t}</EuiBadge>)}
                    </div>
                    <dl className="wamAg__pts">
                      <div><dt>First seen</dt><dd>{formatAbsolute(p.firstSeen)}</dd></div>
                      <div><dt>Last seen</dt><dd>{formatAbsolute(p.lastSeen)}</dd></div>
                    </dl>
                    <div className="wamAg__cnt"><span className="wamAg__dot" style={{ background: color }} />{plural(p.alertCount, 'alert')}</div>
                  </div>
                </React.Fragment>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};
