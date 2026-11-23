/**
 * @jest-environment jsdom
 */
import React from 'react';
import { configure, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { EnrichmentSettingsView, ctiExplorerUrl, toPayload } from './enrichment_settings_view';

configure({ testIdAttribute: 'data-test-subj' });

function apiServiceWith(isPluginAdmin: boolean, settings: any) {
  return {
    fetchSystemCapabilities: jest.fn(async () => ({ isPluginAdmin })),
    fetchEnrichmentSettings: jest.fn(async () => settings),
    saveEnrichmentSettings: jest.fn(),
    testEnrichmentSource: jest.fn(),
    appUrl: jest.fn((path: string) => `/base${path}`),
  } as any;
}

const settings = {
  encryptionConfigured: true,
  egressAllowedHosts: ['misp.example.org'],
  sources: [
    { id: 'wazuh_cti_local', name: 'Wazuh CTI catalog (local)', kind: 'wazuh_cti_local', enabled: false, supports: ['ip', 'domain', 'url', 'hash'], cacheTtlSeconds: 3600, timeoutMs: 8000, builtIn: true },
    { id: 'misp-1', name: 'Corp MISP', kind: 'misp', enabled: true, supports: ['ip', 'hash'], cacheTtlSeconds: 600, timeoutMs: 8000, baseUrl: 'https://misp.example.org', apiKeyConfigured: true },
  ],
};

describe('EnrichmentSettingsView', () => {
  test('locks the tab for non-administrators without loading the settings form', async () => {
    const api = apiServiceWith(false, settings);
    render(<EnrichmentSettingsView apiService={api} onToast={jest.fn()} />);
    await waitFor(() => expect(screen.getByText(/administered by Wazuh administrators/)).toBeTruthy());
    expect(screen.queryByTestId('wamEnrichmentSave')).toBeNull();
  });

  test('lists the sources with masked credentials, the built-in marker and the egress allowlist', async () => {
    const api = apiServiceWith(true, settings);
    render(<EnrichmentSettingsView apiService={api} onToast={jest.fn()} />);
    await waitFor(() => expect(screen.getByTestId('wamEnrichmentSource-misp-1')).toBeTruthy());
    expect(screen.getByTestId('wamEnrichmentSource-wazuh_cti_local').textContent).toContain('built in');
    expect(screen.getByTestId('wamEnrichmentSource-misp-1').textContent).toContain('Configured');
    expect(screen.getByTestId('wamEnrichmentSource-misp-1').textContent).not.toContain('k3y');
    // Step 10.5d: name above the id (queue primary / secondary pattern), never beside it.
    const nameCell = screen.getByTestId('wamEnrichmentSource-misp-1').querySelector('[data-test-subj="wamEnrichmentSourceName"]')!;
    expect(nameCell.className).toContain('wamTablePrimary');
    // The 180px content floor only widens the column under auto layout.
    expect(screen.getByTestId('wamEnrichmentSource-misp-1').closest('table')!.className).toContain('euiTable--auto');
    expect(nameCell.querySelector('strong')!.textContent).toBe('Corp MISP');
    expect(nameCell.querySelector('.wamTableSecondary code')!.textContent).toBe('misp-1');
    expect(screen.getByTestId('wamEnrichmentSource-wazuh_cti_local').querySelector('strong .euiBadge')!.textContent).toBe('built in');
    expect(screen.getByText('misp.example.org')).toBeTruthy();
    expect(screen.getByText(/WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS/)).toBeTruthy();
    expect(screen.getByText(/private, loopback or link-local/)).toBeTruthy();
    expect((screen.getByTestId('wamEnrichmentSave') as HTMLButtonElement).disabled).toBe(true);
  });

  test('an administrator whose settings load fails sees a load error with retry, not the permission lock', async () => {
    const api = apiServiceWith(true, settings);
    api.fetchEnrichmentSettings.mockRejectedValueOnce(Object.assign(new Error('boom'), { body: { message: 'meta index unavailable' } }));
    render(<EnrichmentSettingsView apiService={api} onToast={jest.fn()} />);
    await waitFor(() => expect(screen.getByTestId('wamEnrichmentLoadError')).toBeTruthy());
    expect(screen.getByText('meta index unavailable')).toBeTruthy();
    expect(screen.queryByText(/administered by Wazuh administrators/)).toBeNull();
    fireEvent.click(screen.getByTestId('wamEnrichmentRetry'));
    await waitFor(() => expect(screen.getByTestId('wamEnrichmentSource-misp-1')).toBeTruthy());
    expect(api.fetchEnrichmentSettings).toHaveBeenCalledTimes(2);
  });

  test('"Clear saved key" sends apiKey: null so the stored key is removed', async () => {
    const api = apiServiceWith(true, settings);
    api.saveEnrichmentSettings.mockResolvedValue({ ...settings, sources: settings.sources.map((s: any) => (s.id === 'misp-1' ? { ...s, apiKeyConfigured: false } : s)) });
    render(<EnrichmentSettingsView apiService={api} onToast={jest.fn()} />);
    await waitFor(() => expect(screen.getByTestId('wamEnrichmentSource-misp-1')).toBeTruthy());
    fireEvent.click(screen.getByLabelText('Edit Corp MISP'));
    fireEvent.click(screen.getByTestId('wamEnrichmentClearKey'));
    expect(screen.getByText('Will be cleared')).toBeTruthy();
    fireEvent.click(screen.getByTestId('wamEnrichmentApply'));
    expect(screen.getByTestId('wamEnrichmentSource-misp-1').textContent).toContain('Key cleared');
    fireEvent.click(screen.getByTestId('wamEnrichmentSave'));
    await waitFor(() => expect(api.saveEnrichmentSettings).toHaveBeenCalledTimes(1));
    const sent = api.saveEnrichmentSettings.mock.calls[0][0].sources.find((s: any) => s.id === 'misp-1');
    expect(sent.apiKey).toBeNull();
    expect(sent.apiKeyConfigured).toBeUndefined();
  });

  test('toPayload keeps the apiKey contract and the CTI Explorer link honours basePath on 5.0 builds only', () => {
    const base: any = { id: 'x', name: 'x', kind: 'misp', enabled: true, baseUrl: 'https://misp.example.org', apiKeyConfigured: true, builtIn: false };
    expect(toPayload({ ...base, apiKey: '' })).not.toHaveProperty('apiKey');
    expect(toPayload({ ...base, apiKey: undefined })).not.toHaveProperty('apiKey');
    expect(toPayload({ ...base, apiKey: 'new' }).apiKey).toBe('new');
    expect(toPayload({ ...base, apiKey: null }).apiKey).toBeNull();
    expect(toPayload(base)).not.toHaveProperty('apiKeyConfigured');
    const api = apiServiceWith(true, settings);
    const url = ctiExplorerUrl(api);
    // The checked-in build target is 4.x; a 5.0 build prepends the basePath.
    expect(url === null || url === '/base/app/cti-explorer').toBe(true);
  });
});
