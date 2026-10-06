import React, { useEffect, useMemo, useRef, useState } from 'react';
import { EuiBadge, EuiButtonEmpty, EuiSelect, EuiSwitch, EuiText, EuiTitle } from '@elastic/eui';
import { AttackGraphHop } from '../../common';
import { severityBand } from '../design';
import { storyTone, TONE_HEX } from './attack_story_tone';
import { SeverityBadge } from './status_badge';

// The case's alerts in time order: a per-host strip of dots (one per alert) and
// a rail of alert cards below it, with consecutive repeats of the same rule on
// the same host folded into one card. Dots and cards select each other.

const ROW_PAGE = 150;
const GAP_SECONDS = 600; // show a "… later" marker between rows further apart than this
const UNKNOWN_HOST = 'unknown host';

// Dot size follows the shared severity bands, so bigger always means worse.
const DOT_SIZE = { critical: 18, high: 14, medium: 12, low: 11 } as const;

const ServerIcon = () => (
  <svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="4" width="16" height="7" rx="1.5" /><rect x="4" y="13" width="16" height="7" rx="1.5" /></svg>
);

const hostOf = (h: AttackGraphHop) => h.host || UNKNOWN_HOST;
const timeOf = (h: AttackGraphHop) => Date.parse(h.timestamp);
const clockOf = (ms: number) => new Date(ms).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
const dayOf = (ms: number) => new Date(ms).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
const plural = (n: number, word: string) => `${n.toLocaleString()} ${word}${n === 1 ? '' : 's'}`;

const duration = (seconds: number) => {
  if (seconds < 90) return plural(Math.round(seconds), 'sec').replace('secs', 'sec');
  const minutes = seconds / 60;
  if (minutes < 90) return `${Math.round(minutes)} min`;
  const hours = minutes / 60;
  if (hours < 36) return plural(Math.round(hours), 'hour');
  return plural(Math.round(hours / 24), 'day');
};

// Axis ticks on round local-time boundaries, about 6-8 across the strip.
const TICK_MINUTES = [1, 2, 5, 10, 15, 30, 60, 120, 180, 360, 720, 1440, 2880, 10080];
function ticksFor(start: number, end: number) {
  const span = end - start;
  const stepMin = TICK_MINUTES.find((m) => span / (m * 60000) <= 8) || TICK_MINUTES[TICK_MINUTES.length - 1];
  const step = stepMin * 60000;
  const tz = -new Date(start).getTimezoneOffset() * 60000;
  const out: Array<{ t: number; label: string }> = [];
  for (let t = Math.ceil((start + tz) / step) * step - tz; t <= end; t += step) {
    const d = new Date(t);
    const label = stepMin >= 1440
      ? d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
      : d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
    out.push({ t, label });
  }
  return out;
}

interface Row {
  hops: AttackGraphHop[];
}

interface Props {
  hops: AttackGraphHop[];
  onOpenLinked?: (alertIds: string[], label: string) => void;
}

export const AttackTimeline: React.FC<Props> = ({ hops, onOpenLinked }) => {
  const [host, setHost] = useState<string>('all');
  const [group, setGroup] = useState(true);
  const [selected, setSelected] = useState<{ ids: Set<string>; single: string | null } | null>(null);
  const [limit, setLimit] = useState(ROW_PAGE);
  const rowRefs = useRef<Record<number, HTMLDivElement | null>>({});
  const pendingScroll = useRef<string | null>(null);

  const sorted = useMemo(() => [...hops].sort((a, b) => timeOf(a) - timeOf(b)), [hops]);
  const hosts = useMemo(() => {
    const counts = new Map<string, number>();
    sorted.forEach((h) => counts.set(hostOf(h), (counts.get(hostOf(h)) || 0) + 1));
    return Array.from(counts.entries()).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([name]) => name);
  }, [sorted]);

  // The time domain spans every alert (not just the filtered host) so dots
  // keep their positions when switching the host filter.
  const domain = useMemo(() => {
    const times = sorted.map(timeOf).filter(Number.isFinite);
    if (!times.length) return null;
    const min = Math.min(...times);
    const max = Math.max(...times);
    const pad = Math.max(60000, (max - min) * 0.025) || 300000;
    return { start: min - pad, end: max + pad };
  }, [sorted]);
  const pct = (t: number) => (domain ? `${(((t - domain.start) / (domain.end - domain.start)) * 100).toFixed(2)}%` : '0%');

  const visible = useMemo(() => sorted.filter((h) => host === 'all' || hostOf(h) === host), [sorted, host]);
  const lanes = host === 'all' ? hosts : [host];

  const rows = useMemo(() => {
    const out: Row[] = [];
    for (const h of visible) {
      const last = out[out.length - 1];
      const head = last?.hops[0];
      const same = head && hostOf(head) === hostOf(h) && (head.ruleId || head.ruleDescription) === (h.ruleId || h.ruleDescription);
      if (group && same) last!.hops.push(h);
      else out.push({ hops: [h] });
    }
    return out;
  }, [visible, group]);

  useEffect(() => { setSelected(null); setLimit(ROW_PAGE); }, [host, group, hops]);

  // After a dot click the matching card may only just have been rendered.
  useEffect(() => {
    const id = pendingScroll.current;
    if (!id) return;
    const index = rows.findIndex((r) => r.hops.some((h) => h.alertId === id));
    const el = rowRefs.current[index];
    if (el) {
      pendingScroll.current = null;
      el.scrollIntoView?.({ behavior: 'smooth', block: 'center' });
    }
  });

  const selectDot = (h: AttackGraphHop) => {
    if (selected?.single === h.alertId && selected.ids.size === 1) {
      setSelected(null);
      return;
    }
    setSelected({ ids: new Set([h.alertId]), single: h.alertId });
    const index = rows.findIndex((r) => r.hops.some((x) => x.alertId === h.alertId));
    if (index >= limit) setLimit(index + 1);
    pendingScroll.current = h.alertId;
  };
  const selectRow = (row: Row) => {
    const ids = row.hops.map((h) => h.alertId);
    const already = selected && selected.single == null && selected.ids.size === ids.length && ids.every((id) => selected.ids.has(id));
    setSelected(already ? null : { ids: new Set(ids), single: null });
  };
  const openRow = (row: Row) => {
    const head = row.hops[0];
    const label = `${head.ruleId ? `Rule ${head.ruleId}` : head.ruleDescription || 'Alert'} on ${hostOf(head)}`;
    onOpenLinked?.([...row.hops].sort((a, b) => timeOf(b) - timeOf(a)).map((h) => h.alertId), label);
  };

  if (!sorted.length || !domain) {
    return (
      <div className="wamAg__panel">
        <EuiTitle size="xs"><h2 className="wamAg__h2">Alert chronology</h2></EuiTitle>
        <p className="wamAg__empty">No hops to show.</p>
      </div>
    );
  }

  const ticks = ticksFor(domain.start, domain.end);
  let prevEnd: number | null = null;
  let prevDay: string | null = null;

  return (
    <div className="wamAg__panel">
      <div className="wamAg__ptop">
        <div>
          <EuiTitle size="xs"><h2 className="wamAg__h2">Alert chronology</h2></EuiTitle>
          <EuiText size="s" color="subdued" className="wamAg__lede">
            <p>
              Every linked alert in time order. Each dot on the strip is one alert, placed by time and grouped by host.
              Bigger, warmer dots are higher level. Click a dot or a row to highlight it in both places.
              Repeated alerts are grouped so the pattern is easy to spot.
            </p>
          </EuiText>
        </div>
        <div className="wamAg__actions">
          {/* A select rather than a button group: a case can span many hosts with long names. */}
          <div className="wamAg__host">
            <EuiSelect
              compressed
              prepend="Host"
              aria-label="Filter by host"
              options={[{ value: 'all', text: 'All hosts' }, ...hosts.map((name) => ({ value: name, text: name }))]}
              value={host}
              onChange={(e) => setHost(e.target.value)}
            />
          </div>
          <EuiSwitch compressed label="Group repeats" checked={group} onChange={(e) => setGroup(e.target.checked)} />
        </div>
      </div>

      <div className={`wamAg__strip${selected ? ' wamAg__strip--has' : ''}`}>
        {lanes.map((name) => {
          const laneHops = visible.filter((h) => hostOf(h) === name);
          return (
            <div className="wamAg__lane" key={name}>
              <div className="wamAg__lanel" title={name}>
                <ServerIcon />
                <span className="wamAg__lanen">{name}</span>
                <span className="wamAg__lanec">{laneHops.length.toLocaleString()}</span>
              </div>
              <div className="wamAg__track">
                {laneHops.map((h) => {
                  const band = severityBand(h.level);
                  const on = Boolean(selected?.ids.has(h.alertId));
                  return (
                    <button
                      type="button"
                      key={h.alertId}
                      className={`wamAg__pt${on ? ' wamAg__on' : ''}`}
                      style={{ left: pct(timeOf(h)), '--c': TONE_HEX[storyTone(h.level)], '--s': `${DOT_SIZE[band]}px` } as React.CSSProperties}
                      title={`${clockOf(timeOf(h))} · ${h.ruleId ? `Rule ${h.ruleId} · ` : ''}${h.ruleDescription}`}
                      aria-label={`${clockOf(timeOf(h))}, level ${h.level}${h.ruleId ? `, rule ${h.ruleId}` : ''}: ${h.ruleDescription}`}
                      aria-pressed={on}
                      onClick={() => selectDot(h)}
                    />
                  );
                })}
              </div>
            </div>
          );
        })}
        <div className="wamAg__axis">
          <div />
          <div className="wamAg__ticks">
            {ticks.map((tick) => <span key={tick.t} style={{ left: pct(tick.t) }}>{tick.label}</span>)}
          </div>
        </div>
      </div>

      <div className="wamAg__tl">
        {rows.slice(0, limit).map((row, index) => {
          const head = row.hops[0];
          const tail = row.hops[row.hops.length - 1];
          const start = timeOf(head);
          const end = timeOf(tail);
          const day = dayOf(start);
          const markers: React.ReactNode[] = [];
          if (prevDay && day !== prevDay) {
            markers.push(<div className="wamAg__gap" key={`d-${index}`}><span>{day}</span></div>);
          } else if (prevEnd != null && (start - prevEnd) / 1000 > GAP_SECONDS) {
            markers.push(<div className="wamAg__gap" key={`g-${index}`}><span>{duration((start - prevEnd) / 1000)} later</span></div>);
          }
          prevEnd = end;
          prevDay = day;
          const color = TONE_HEX[storyTone(head.level)];
          const isSel = Boolean(selected && row.hops.some((h) => selected.ids.has(h.alertId)));
          const users = Array.from(new Set(row.hops.flatMap((h) => h.users)));
          const sources = Array.from(new Set(row.hops.flatMap((h) => h.sources || [])));
          const tactics = Array.from(new Set(row.hops.flatMap((h) => h.tactics)));
          const techniques = Array.from(new Set(row.hops.flatMap((h) => h.techniques)));
          const level = Math.max(...row.hops.map((h) => h.level || 0));
          return (
            <React.Fragment key={`${head.alertId}-${index}`}>
              {markers}
              <div className={`wamAg__tr${isSel ? ' wamAg__tr--sel' : ''}`} ref={(el) => { rowRefs.current[index] = el; }}>
                <div className="wamAg__tt">{clockOf(start)}</div>
                <div><div className="wamAg__rd" style={{ '--c': color } as React.CSSProperties} /></div>
                <div
                  className="wamAg__tcard"
                  onClick={(ev) => { if (!(ev.target as HTMLElement).closest('.wamAg__oa')) selectRow(row); }}
                >
                  {/* The heading line is the keyboard/AT target, so the card's own "Open" button isn't nested inside a button. */}
                  <div
                    className="wamAg__thd"
                    role="button"
                    tabIndex={0}
                    aria-pressed={isSel}
                    onKeyDown={(ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); selectRow(row); } }}
                  >
                    <SeverityBadge level={level} />
                    <b>{head.ruleDescription || 'Alert'}</b>
                    {row.hops.length > 1 && (
                      <>
                        <EuiBadge color="primary">×{row.hops.length.toLocaleString()}</EuiBadge>
                        <span className="wamAg__span">{clockOf(start)} → {clockOf(end)} · over {duration((end - start) / 1000)}</span>
                      </>
                    )}
                  </div>
                  <div className="wamAg__tmeta">
                    <EuiBadge color="hollow" className="wamAg__ch">{hostOf(head)}</EuiBadge>
                    {sources.map((ip) => <EuiBadge color="hollow" className="wamAg__ch" key={`s-${ip}`}>Source: {ip}</EuiBadge>)}
                    {users.map((u) => <EuiBadge color="hollow" className="wamAg__ch" key={`u-${u}`}>User: {u}</EuiBadge>)}
                    {head.ruleId && <EuiBadge color="hollow" className="wamAg__ch" title="Wazuh rule ID">Rule {head.ruleId}</EuiBadge>}
                    {tactics.map((t) => <EuiBadge color="hollow" className="wamAg__ch wamAg__ch--tac" key={`t-${t}`}>{t}</EuiBadge>)}
                    {techniques.map((t) => <EuiBadge color="hollow" className="wamAg__ch wamAg__ch--tec" key={`q-${t}`}>{t}</EuiBadge>)}
                    {onOpenLinked && (
                      <EuiButtonEmpty size="xs" className="wamAg__oa" onClick={() => openRow(row)}>
                        Open {row.hops.length > 1 ? `${row.hops.length.toLocaleString()} alerts` : 'alert'}
                      </EuiButtonEmpty>
                    )}
                  </div>
                  {row.hops.length > 1 && isSel && (
                    <div className="wamAg__reps">
                      {row.hops.map((h) => (
                        <span key={h.alertId} className={selected?.single === h.alertId ? 'wamAg__on' : ''}>{clockOf(timeOf(h))}</span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </React.Fragment>
          );
        })}
      </div>
      {rows.length > limit && (
        <EuiButtonEmpty size="s" className="wamAg__more" onClick={() => setLimit((n) => n + ROW_PAGE)}>
          Show {Math.min(ROW_PAGE, rows.length - limit).toLocaleString()} more of {(rows.length - limit).toLocaleString()} remaining
        </EuiButtonEmpty>
      )}
    </div>
  );
};
