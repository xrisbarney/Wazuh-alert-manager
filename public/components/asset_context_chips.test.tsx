/**
 * @jest-environment jsdom
 */
import React from 'react';
import { configure, render, screen, waitFor } from '@testing-library/react';
import {
  AssetContextChips,
  AssetContextCountBadges,
  EMPTY_ASSET_SUMMARY,
  aggregateAssetSummaries,
  familyStatusTooltip,
  summarizeAssetContext,
} from './asset_context_chips';

configure({ testIdAttribute: 'data-test-subj' });

function service(impl: () => Promise<any>) {
  return {
    fetchAssetContext: jest.fn(impl),
    appUrl: (path: string) => `/base${path}`,
  } as any;
}

const full = {
  agentId: '001',
  agentName: 'web-01',
  line: 4,
  fetchedAt: '2026-11-20T10:00:00.000Z',
  cached: false,
  families: {
    system: { status: 'ok', os: { name: 'Ubuntu', version: '22.04', platform: 'ubuntu' }, hostname: 'web-01' },
    networks: { status: 'ok', ips: ['10.0.0.5', '10.0.0.6', '10.0.0.7', '10.0.0.8'], total: 4 },
    ports: { status: 'ok', open: 12, listening: 7 },
    vulnerabilities: { status: 'ok', total: 3, critical: 1, high: 2, medium: 0, low: 0, topCves: [{ id: 'CVE-2024-3094', severity: 'Critical', score: 10 }] },
    sca: { status: 'not_available', reason: 'SCA results are not indexed on Wazuh 4.x (the SCA module reads them from the manager API); open Configuration Assessment for this agent' },
  },
  links: {
    itHygiene: '/app/it-hygiene#/overview/?tab=it-hygiene&tabView=dashboard&agentId=001',
    vulnerabilityDetection: '/app/vulnerability-detection#/overview/?tab=vuls&tabView=dashboard&agentId=001',
    configurationAssessment: '/app/configuration-assessment#/overview/?tab=sca&tabView=inventory&agentId=001',
  },
};

describe('AssetContextChips', () => {
  test('shows a spinner chip first, then one chip per family and the two deep links', async () => {
    let resolve!: (v: any) => void;
    const apiService = service(() => new Promise((r) => { resolve = r; }));
    render(<AssetContextChips apiService={apiService} agentId="001" agentName="web-01" />);
    expect(screen.getByTestId('wamAssetContextLoading')).toBeTruthy();
    expect(apiService.fetchAssetContext).toHaveBeenCalledWith({ agentId: '001', agentName: 'web-01' });
    resolve(full);
    await waitFor(() => expect(screen.queryByTestId('wamAssetContextLoading')).toBeNull());
    expect(screen.getByTestId('wamAssetContextChip-os').textContent).toContain('Ubuntu 22.04');
    expect(screen.getByTestId('wamAssetContextChip-ips').textContent).toContain('10.0.0.5, 10.0.0.6, 10.0.0.7 +1');
    expect(screen.getByTestId('wamAssetContextChip-ports').textContent).toContain('12 open, 7 listening');
    const cves = screen.getByTestId('wamAssetContextChip-cves');
    expect(cves.textContent).toContain('1 critical / 2 high');
    expect(cves.getAttribute('data-status')).toBe('ok');
    const sca = screen.getByTestId('wamAssetContextChip-sca');
    expect(sca.textContent).toContain('not indexed on 4.x');
    expect(sca.getAttribute('data-status')).toBe('not_available');
    expect(screen.getByTestId('wamAssetContextLinkSca').getAttribute('href')).toBe(`/base${full.links.configurationAssessment}`);
    expect(screen.getByTestId('wamAssetContextLinkHygiene').getAttribute('href')).toBe(`/base${full.links.itHygiene}`);
    expect(screen.getByTestId('wamAssetContextLinkVuln').getAttribute('href')).toBe(`/base${full.links.vulnerabilityDetection}`);
  });

  test('renders no access and no data states per chip', async () => {
    const apiService = service(async () => ({
      ...full,
      families: {
        system: { status: 'ok', os: null, hostname: null },
        networks: { status: 'no_access' },
        ports: { status: 'error', reason: 'timeout' },
        vulnerabilities: { status: 'ok', total: 0, critical: 0, high: 0, medium: 0, low: 0, topCves: [] },
        sca: { status: 'ok', total: 10, failed: 4, passed: 6 },
      },
    }));
    render(<AssetContextChips apiService={apiService} agentId="001" />);
    await waitFor(() => expect(screen.queryByTestId('wamAssetContextLoading')).toBeNull());
    expect(screen.getByTestId('wamAssetContextChip-os').getAttribute('data-status')).toBe('no_data');
    expect(screen.getByTestId('wamAssetContextChip-os').textContent).toContain('no data');
    expect(screen.getByTestId('wamAssetContextChip-ips').textContent).toContain('no access');
    expect(screen.getByTestId('wamAssetContextChip-ports').textContent).toContain('unavailable');
    expect(screen.getByTestId('wamAssetContextChip-cves').getAttribute('data-status')).toBe('no_data');
    expect(screen.getByTestId('wamAssetContextChip-sca').textContent).toContain('4 failed');
  });

  test('a failed request becomes a single unavailable chip and renders nothing without an agent', async () => {
    const apiService = service(async () => { throw Object.assign(new Error('boom'), { body: { message: 'Internal Server Error' } }); });
    render(<AssetContextChips apiService={apiService} agentId="001" />);
    await waitFor(() => expect(screen.getByTestId('wamAssetContextFailed')).toBeTruthy());
    expect(screen.queryByTestId('wamAssetContextChip-os')).toBeNull();

    const idle = service(async () => full);
    const { container } = render(<AssetContextChips apiService={idle} agentId={null} agentName={null} />);
    expect(container.innerHTML).toBe('');
    expect(idle.fetchAssetContext).not.toHaveBeenCalled();
  });

  test('skips the IT Hygiene link when the build has no such app (null link)', async () => {
    const apiService = service(async () => ({ ...full, links: { ...full.links, itHygiene: null } }));
    render(<AssetContextChips apiService={apiService} agentId="001" />);
    await waitFor(() => expect(screen.queryByTestId('wamAssetContextLoading')).toBeNull());
    expect(screen.queryByTestId('wamAssetContextLinkHygiene')).toBeNull();
    expect(screen.getByTestId('wamAssetContextLinkVuln')).toBeTruthy();
  });

  test('on 5.0 (no Configuration Assessment link) an unavailable SCA family falls back to the plain n/a label and no link', async () => {
    const apiService = service(async () => ({ ...full, links: { ...full.links, configurationAssessment: null } }));
    render(<AssetContextChips apiService={apiService} agentId="001" />);
    await waitFor(() => expect(screen.queryByTestId('wamAssetContextLoading')).toBeNull());
    expect(screen.getByTestId('wamAssetContextChip-sca').textContent).toContain('n/a');
    expect(screen.queryByTestId('wamAssetContextLinkSca')).toBeNull();
  });

  test('onLoaded reports the compact counts once (step 11.4): vulnerabilities and SCA when their families answered, a failed read as unloaded', async () => {
    const onLoaded = jest.fn();
    const apiService = service(async () => ({ ...full, families: { ...full.families, sca: { status: 'ok', total: 10, failed: 4, passed: 6 } } }));
    render(<AssetContextChips apiService={apiService} agentId="001" agentName="web-01" onLoaded={onLoaded} />);
    await waitFor(() => expect(onLoaded).toHaveBeenCalledTimes(1));
    expect(onLoaded).toHaveBeenCalledWith({ loaded: true, vulnKnown: true, vulnCritical: 1, vulnHigh: 2, scaKnown: true, scaFailed: 4, scaPassed: 6 });

    // 4.x: SCA is not indexed, so the summary carries no SCA counts; a no-access vulnerabilities family is unknown, not zero.
    expect(summarizeAssetContext(full as any)).toEqual({ loaded: true, vulnKnown: true, vulnCritical: 1, vulnHigh: 2, scaKnown: false, scaFailed: 0, scaPassed: 0 });
    expect(summarizeAssetContext({ ...full, families: { ...full.families, vulnerabilities: { status: 'no_access' } } } as any)).toMatchObject({ loaded: true, vulnKnown: false, vulnCritical: 0 });
    expect(summarizeAssetContext(null)).toEqual(EMPTY_ASSET_SUMMARY);

    const failing = jest.fn();
    const broken = service(async () => { throw new Error('boom'); });
    render(<AssetContextChips apiService={broken} agentId="002" onLoaded={failing} />);
    await waitFor(() => expect(failing).toHaveBeenCalledTimes(1));
    expect(failing).toHaveBeenCalledWith(EMPTY_ASSET_SUMMARY);
  });

  test('a controlled `source` renders the host-held state and never fetches (step 11.4)', async () => {
    const apiService = service(async () => full);
    const { rerender } = render(<AssetContextChips apiService={apiService} agentId="001" agentName="web-01" source={{ status: 'loading' }} />);
    expect(screen.getByTestId('wamAssetContextLoading')).toBeTruthy();
    rerender(<AssetContextChips apiService={apiService} agentId="001" agentName="web-01" source={{ status: 'ready', context: full as any }} />);
    expect(screen.queryByTestId('wamAssetContextLoading')).toBeNull();
    expect(screen.getByTestId('wamAssetContextChip-os').textContent).toContain('Ubuntu 22.04');
    expect(screen.getByTestId('wamAssetContextLinkVuln')).toBeTruthy();
    rerender(<AssetContextChips apiService={apiService} agentId="001" agentName="web-01" source={{ status: 'failed', error: 'boom' }} />);
    expect(screen.getByTestId('wamAssetContextFailed')).toBeTruthy();
    expect(screen.queryByTestId('wamAssetContextChip-os')).toBeNull();
    expect(apiService.fetchAssetContext).not.toHaveBeenCalled();
  });

  test('aggregateAssetSummaries sums loaded rows only and the count badges render per known family', () => {
    const a = { loaded: true, vulnKnown: true, vulnCritical: 1, vulnHigh: 2, scaKnown: false, scaFailed: 0, scaPassed: 0 };
    const b = { loaded: true, vulnKnown: true, vulnCritical: 0, vulnHigh: 3, scaKnown: true, scaFailed: 4, scaPassed: 6 };
    expect(aggregateAssetSummaries([a, EMPTY_ASSET_SUMMARY, b])).toEqual({ loaded: true, vulnKnown: true, vulnCritical: 1, vulnHigh: 5, scaKnown: true, scaFailed: 4, scaPassed: 6 });
    expect(aggregateAssetSummaries([EMPTY_ASSET_SUMMARY])).toEqual(EMPTY_ASSET_SUMMARY);
    expect(aggregateAssetSummaries([])).toEqual(EMPTY_ASSET_SUMMARY);

    const { container, rerender } = render(<AssetContextCountBadges summary={EMPTY_ASSET_SUMMARY} testSubj="counts" />);
    expect(container.innerHTML).toBe('');
    rerender(<AssetContextCountBadges summary={a} testSubj="counts" />);
    expect(screen.getByTestId('counts-vuln').textContent).toBe('1 critical / 2 high');
    expect(screen.queryByTestId('counts-sca')).toBeNull();
    rerender(<AssetContextCountBadges summary={b} testSubj="counts" />);
    expect(screen.getByTestId('counts-sca').textContent).toBe('4 SCA failed');
  });

  test('status tooltips explain the role grant and the timeout', () => {
    expect(familyStatusTooltip({ status: 'no_access' }, 'IP addresses')).toMatch(/wazuh_alert_manager_native_read/);
    expect(familyStatusTooltip({ status: 'error', reason: 'timeout' }, 'Open ports')).toMatch(/timed out/);
    expect(familyStatusTooltip({ status: 'not_available', reason: full.families.sca.reason }, 'SCA checks')).toMatch(/not indexed on Wazuh 4\.x.*Configuration Assessment/);
  });
});
