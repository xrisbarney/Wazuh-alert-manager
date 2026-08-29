import React, { useEffect, useState } from 'react';
import {
  Chart,
  Settings,
  Axis,
  BarSeries,
  AreaSeries,
  Position,
  ScaleType,
} from '@elastic/charts';
import { EUI_CHARTS_THEME_LIGHT, EUI_CHARTS_THEME_DARK } from '@elastic/eui/dist/eui_charts_theme';
import { EuiEmptyPrompt } from '@elastic/eui';

// @elastic/charts is bundled by the OSD monorepo we compile inside (a root
// dependency), so it is available without adding a plugin dependency. All chart
// usage is isolated in this one file so the rest of Reports still renders if a
// charts API ever shifts across the supported OSD versions.

function isDark(): boolean {
  try {
    if (typeof document !== 'undefined') {
      const root = document.documentElement;
      const body = document.body;
      if (
        root.classList.contains('euiTheme-dark') ||
        body.classList.contains('euiTheme-dark') ||
        root.classList.contains('ouiTheme-dark') ||
        body.classList.contains('ouiTheme-dark')
      ) return true;
      if (root.getAttribute('data-theme') === 'dark' || body.getAttribute('data-theme') === 'dark') return true;
      if (
        root.classList.contains('euiTheme-light') ||
        body.classList.contains('euiTheme-light') ||
        root.classList.contains('ouiTheme-light') ||
        body.classList.contains('ouiTheme-light') ||
        root.getAttribute('data-theme') === 'light' ||
        body.getAttribute('data-theme') === 'light'
      ) return false;
    }
    return typeof window !== 'undefined' && Boolean(window.matchMedia?.('(prefers-color-scheme: dark)').matches);
  } catch (e) {
    return false;
  }
}

function useChartTheme() {
  const [dark, setDark] = useState(isDark);

  useEffect(() => {
    const update = () => setDark(isDark());
    const media = window.matchMedia?.('(prefers-color-scheme: dark)');
    const observer = new MutationObserver(update);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['class', 'data-theme'] });
    if (document.body) observer.observe(document.body, { attributes: true, attributeFilter: ['class', 'data-theme'] });
    if (media?.addEventListener) media.addEventListener('change', update);
    else media?.addListener(update);
    return () => {
      observer.disconnect();
      if (media?.removeEventListener) media.removeEventListener('change', update);
      else media?.removeListener(update);
    };
  }, []);

  return dark ? EUI_CHARTS_THEME_DARK.theme : EUI_CHARTS_THEME_LIGHT.theme;
}

function cssColor(names: string[], fallback: string): string {
  if (typeof document === 'undefined') return fallback;
  const styles = getComputedStyle(document.documentElement);
  for (const name of names) {
    const value = styles.getPropertyValue(name).trim();
    if (value) return value;
  }
  return fallback;
}

export const AlertTrendChart: React.FC<{ data: Array<{ date: string; count: number }> }> = ({ data }) => {
  const theme = useChartTheme();
  if (!data || data.length === 0) {
    return <EuiEmptyPrompt iconType="visAreaStacked" title={<h4>No alerts in this period</h4>} titleSize="xs" />;
  }
  const points = data.map((d) => ({ t: new Date(d.date).getTime(), c: d.count }));
  return (
    <Chart size={{ height: 230 }}>
      <Settings theme={theme} showLegend={false} />
      <Axis
        id="bottom"
        position={Position.Bottom}
        tickFormat={(v) => new Date(v).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
      />
      <Axis id="left" position={Position.Left} tickFormat={(v) => String(Math.round(v))} />
      <AreaSeries
        id="alerts-per-day"
        name="Alerts"
        xScaleType={ScaleType.Time}
        yScaleType={ScaleType.Linear}
        xAccessor="t"
        yAccessors={['c']}
        data={points}
      />
    </Chart>
  );
};

// Stacked status-over-time: each day's alerts split by current disposition.
export const StatusTrendChart: React.FC<{ data: Array<{ date: string; open: number; in_progress: number; closed: number }> }> = ({
  data,
}) => {
  const theme = useChartTheme();
  if (!data || data.length === 0) {
    return <EuiEmptyPrompt iconType="visAreaStacked" title={<h4>No alerts in this period</h4>} titleSize="xs" />;
  }
  const points = data.map((d) => ({ t: new Date(d.date).getTime(), open: d.open, in_progress: d.in_progress, closed: d.closed }));
  const series: Array<{ key: 'open' | 'in_progress' | 'closed'; name: string; color: string }> = [
    { key: 'open', name: 'Open', color: cssColor(['--euiColorPrimary', '--ouiColorPrimary'], '#0077CC') },
    { key: 'in_progress', name: 'In progress', color: cssColor(['--euiColorAccent', '--ouiColorAccent'], '#9170B8') },
    { key: 'closed', name: 'Closed', color: cssColor(['--euiColorMediumShade', '--ouiColorMediumShade'], '#98A2B3') },
  ];
  return (
    <Chart size={{ height: 230 }}>
      <Settings theme={theme} showLegend legendPosition={Position.Bottom} />
      <Axis
        id="bottom"
        position={Position.Bottom}
        tickFormat={(v) => new Date(v).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
      />
      <Axis id="left" position={Position.Left} tickFormat={(v) => String(Math.round(v))} />
      {series.map((s) => (
        <AreaSeries
          key={s.key}
          id={s.key}
          name={s.name}
          xScaleType={ScaleType.Time}
          yScaleType={ScaleType.Linear}
          xAccessor="t"
          yAccessors={[s.key]}
          stackAccessors={['t']}
          color={s.color}
          data={points}
        />
      ))}
    </Chart>
  );
};

export const StatusBarChart: React.FC<{ breakdown: { open: number; in_progress: number; closed: number } }> = ({
  breakdown,
}) => {
  const theme = useChartTheme();
  const data = [
    { label: 'Open', value: breakdown.open },
    { label: 'In progress', value: breakdown.in_progress },
    { label: 'Closed', value: breakdown.closed },
  ];
  return (
    <Chart size={{ height: 200 }}>
      <Settings theme={theme} showLegend={false} rotation={90} />
      <Axis id="left" position={Position.Left} />
      <Axis id="bottom" position={Position.Bottom} tickFormat={(v) => String(Math.round(v))} />
      <BarSeries
        id="status"
        name="Alerts"
        xScaleType={ScaleType.Ordinal}
        yScaleType={ScaleType.Linear}
        xAccessor="label"
        yAccessors={['value']}
        data={data}
      />
    </Chart>
  );
};

export const CaseSeverityBarChart: React.FC<{ breakdown: Record<string, number> }> = ({ breakdown }) => {
  const theme = useChartTheme();
  // Always render every band, including zeros, so the taxonomy is visible.
  const order = ['low', 'medium', 'high', 'critical'];
  const data = order.map((k) => ({ label: k.charAt(0).toUpperCase() + k.slice(1), value: breakdown[k] || 0 }));
  return (
    <Chart size={{ height: 200 }}>
      <Settings theme={theme} showLegend={false} />
      <Axis id="bottom" position={Position.Bottom} />
      <Axis id="left" position={Position.Left} tickFormat={(v) => String(Math.round(v))} />
      <BarSeries
        id="case-severity"
        name="Cases"
        xScaleType={ScaleType.Ordinal}
        yScaleType={ScaleType.Linear}
        xAccessor="label"
        yAccessors={['value']}
        data={data}
      />
    </Chart>
  );
};
