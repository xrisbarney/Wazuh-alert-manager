/**
 * @jest-environment jsdom
 */
import React from 'react';
import { configure, render, screen, waitFor } from '@testing-library/react';
import { DiscoverBridgeCard, discoverBridgeLinks } from './discover_bridge_card';
import { WAM_ALERT_SEVERITY_COLUMN } from '../../common';

configure({ testIdAttribute: 'data-test-subj' });

function apiServiceWith(status: any, options: { reject?: Error } = {}) {
  return {
    appUrl: (path: string) => `/base${path}`,
    fetchSavedObjectsBridgeStatus: jest.fn(async () => {
      if (options.reject) throw options.reject;
      return status;
    }),
  } as any;
}

describe('discoverBridgeLinks', () => {
  test('builds basePath-aware deep links for the 2.x Discover shape', () => {
    const links = discoverBridgeLinks({ appUrl: (p: string) => `/base${p}` }, '2.19.5');
    expect(links.discoverApp).toBe('/base/app/data-explorer/discover');
    expect(links.reportingApp).toBe('/base/app/reports-dashboards#/');
    expect(links.alertsPattern).toContain(`/base/app/data-explorer/discover#?_a=(discover:(columns:!('agent.name','rule.description','${WAM_ALERT_SEVERITY_COLUMN}','status','assigned_to')`);
    expect(links.alertsPattern).toContain("metadata:(indexPattern:'wam-alerts',view:discover)");
    expect(links.alertsPattern).toContain("time:(from:'now-24h',to:'now')");
    expect(links.casesPattern).toContain("sort:!(!('created_at',desc))");
    expect(links.casesPattern).toContain("indexPattern:'wam-cases'");
    expect(links.openAlertsSearch).toBe('/base/app/data-explorer/discover#/view/wam-open-alerts');
    expect(links.openCasesSearch).toBe('/base/app/data-explorer/discover#/view/wam-open-cases');
  });

  test('hides the deep links and keeps the app links on an unknown Discover shape (OSD 3.x)', () => {
    const links = discoverBridgeLinks({ appUrl: (p: string) => p }, '3.6.0');
    expect(links.discoverApp).toBe('/app/data-explorer/discover');
    expect(links.reportingApp).toBe('/app/reports-dashboards#/');
    expect(links.alertsPattern).toBeNull();
    expect(links.casesPattern).toBeNull();
    expect(links.openAlertsSearch).toBeNull();
    expect(links.openCasesSearch).toBeNull();
  });
});

describe('DiscoverBridgeCard', () => {
  test('shows the provisioned badge and the app links when the bridge is ok', async () => {
    const api = apiServiceWith({ indexPatterns: 'ok', message: 'provisioned', version: 15, checkedAt: '2026-11-20T10:00:00.000Z', objects: {} });
    render(<DiscoverBridgeCard apiService={api} />);
    await waitFor(() => expect(screen.getByTestId('wamDiscoverBridgeState').textContent).toBe('Provisioned'));
    expect(screen.queryByTestId('wamDiscoverBridgeMessage')).toBeNull();
    expect(screen.getByTestId('wamDiscoverBridgeReporting').getAttribute('href')).toBe('/base/app/reports-dashboards#/');
    expect(screen.getByTestId('wamDiscoverBridgeAlerts').getAttribute('href')).toContain('/base/app/data-explorer/discover');
    expect(api.fetchSavedObjectsBridgeStatus).toHaveBeenCalledTimes(1);
  });

  test('shows the server message when provisioning failed, and the links stay usable', async () => {
    const api = apiServiceWith({ indexPatterns: 'error', message: 'Discover/Reporting bridge failed (1 write(s)): index-pattern/wam-cases: forbidden.', version: null, checkedAt: null, objects: {} });
    render(<DiscoverBridgeCard apiService={api} />);
    await waitFor(() => expect(screen.getByTestId('wamDiscoverBridgeState').textContent).toBe('Provisioning failed'));
    expect(screen.getByTestId('wamDiscoverBridgeMessage').textContent).toContain('index-pattern/wam-cases: forbidden');
    expect(screen.getByTestId('wamDiscoverBridgeReporting').getAttribute('href')).toBe('/base/app/reports-dashboards#/');
  });

  test('shows a retryable warning when the status request itself fails', async () => {
    const api = apiServiceWith(null, { reject: Object.assign(new Error('boom'), { body: { message: 'version route unavailable' } }) });
    render(<DiscoverBridgeCard apiService={api} />);
    await waitFor(() => expect(screen.getByText('version route unavailable')).toBeTruthy());
    expect(screen.getByTestId('wamDiscoverBridgeState').textContent).toBe('Not provisioned');
  });
});
