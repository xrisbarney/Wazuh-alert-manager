/**
 * @jest-environment jsdom
 */
import React from 'react';
import { render } from '@testing-library/react';
import { EUI_CHARTS_THEME_DARK, EUI_CHARTS_THEME_LIGHT } from '@elastic/eui/dist/eui_charts_theme';

// @elastic/charts draws on canvas, which jsdom has no layout for; the test only
// needs the theme the chart's <Settings> receives.
const mockSettingsSpy = jest.fn();
jest.mock('@elastic/charts', () => ({
  Chart: ({ children }: { children?: any }) => require('react').createElement('div', null, children),
  Settings: (props: any) => {
    mockSettingsSpy(props);
    return null;
  },
  Axis: () => null,
  BarSeries: () => null,
  AreaSeries: () => null,
  Position: { Bottom: 'bottom', Left: 'left' },
  ScaleType: { Time: 'time', Linear: 'linear' },
}));

import { AlertTrendChart } from './report_charts';

const data = [{ date: '2026-11-20T00:00:00.000Z', count: 3 }];

function receivedTheme(): any {
  expect(mockSettingsSpy).toHaveBeenCalled();
  return mockSettingsSpy.mock.calls[mockSettingsSpy.mock.calls.length - 1][0].theme;
}

describe('report chart theme detection', () => {
  afterEach(() => {
    document.body.style.color = '';
    document.body.className = '';
    document.documentElement.className = '';
  });

  // The 4.x dashboard sets no theme class or attribute, so the only signal is
  // the body text colour: light text means the dark theme.
  it('picks the dark chart theme from a light body text colour', () => {
    document.body.style.color = 'rgb(223, 229, 239)';
    render(<AlertTrendChart data={data} />);
    const theme = receivedTheme();
    expect(theme.background).toEqual(EUI_CHARTS_THEME_DARK.theme.background);
    expect(theme.axes.axisLine).toEqual(EUI_CHARTS_THEME_DARK.theme.axes.axisLine);
    expect(theme.background).not.toEqual(EUI_CHARTS_THEME_LIGHT.theme.background);
  });

  it('picks the light chart theme from a dark body text colour', () => {
    document.body.style.color = 'rgb(52, 55, 65)';
    render(<AlertTrendChart data={data} />);
    const theme = receivedTheme();
    expect(theme.background).toEqual(EUI_CHARTS_THEME_LIGHT.theme.background);
    expect(theme.axes.axisLine).toEqual(EUI_CHARTS_THEME_LIGHT.theme.axes.axisLine);
  });

  it('prefers an explicit euiTheme-dark class over the body text colour', () => {
    document.body.style.color = 'rgb(52, 55, 65)';
    document.documentElement.classList.add('euiTheme-dark');
    render(<AlertTrendChart data={data} />);
    expect(receivedTheme().background).toEqual(EUI_CHARTS_THEME_DARK.theme.background);
  });
});
