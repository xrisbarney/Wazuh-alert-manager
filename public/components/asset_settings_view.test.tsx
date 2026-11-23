/**
 * @jest-environment jsdom
 */
import React from 'react';
import { configure, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { AssetSettingsView, suggestId } from './asset_settings_view';
import { AssetBadge } from './asset_badge';

configure({ testIdAttribute: 'data-test-subj' });

const settings = {
  assets: [
    { id: 'web', match: { kind: 'glob', value: 'web-*' }, criticality: 'high', tags: ['pci'] },
    { id: 'dmz', match: { kind: 'group', value: 'dmz' }, criticality: 'critical', tags: [] },
  ],
  updated_by: 'admin',
};

function apiServiceWith(isPluginAdmin: boolean) {
  return {
    fetchSystemCapabilities: jest.fn(async () => ({ isPluginAdmin })),
    fetchAssetSettings: jest.fn(async () => settings),
    saveAssetSettings: jest.fn(async (payload: any) => ({ ...payload, updated_by: 'admin' })),
    resolveAsset: jest.fn(async () => ({ criticality: 'high', tags: ['pci'], matchedId: 'web', matchedBy: 'glob' })),
  } as any;
}

describe('AssetSettingsView', () => {
  test('locks the tab for non-administrators', async () => {
    render(<AssetSettingsView apiService={apiServiceWith(false)} onToast={jest.fn()} />);
    await waitFor(() => expect(screen.getByText(/administered by Wazuh administrators/)).toBeTruthy());
    expect(screen.queryByTestId('wamAssetSave')).toBeNull();
  });

  test('lists entries, removes one and saves the whole list', async () => {
    const api = apiServiceWith(true);
    render(<AssetSettingsView apiService={api} onToast={jest.fn()} />);
    await waitFor(() => expect(screen.getByTestId('wamAsset-web')).toBeTruthy());
    expect(screen.getByTestId('wamAsset-dmz')).toBeTruthy();
    fireEvent.click(screen.getByTestId('wamAssetRemove-dmz'));
    expect(screen.getByTestId('wamAssetDirty')).toBeTruthy();
    fireEvent.click(screen.getByTestId('wamAssetSave'));
    await waitFor(() => expect(api.saveAssetSettings).toHaveBeenCalledWith({ assets: [settings.assets[0]] }));
  });

  test('adds an entry through the editor with comma separated tags', async () => {
    const api = apiServiceWith(true);
    render(<AssetSettingsView apiService={api} onToast={jest.fn()} />);
    await waitFor(() => expect(screen.getByTestId('wamAssetAdd')).toBeTruthy());
    fireEvent.click(screen.getByTestId('wamAssetAdd'));
    fireEvent.change(screen.getByTestId('wamAssetEditorKind'), { target: { value: 'name' } });
    fireEvent.change(screen.getByTestId('wamAssetEditorValue'), { target: { value: 'DB-Prod-01' } });
    fireEvent.change(screen.getByTestId('wamAssetEditorCriticality'), { target: { value: 'critical' } });
    fireEvent.change(screen.getByTestId('wamAssetEditorTags'), { target: { value: 'crown-jewel, pci, pci' } });
    fireEvent.click(screen.getByTestId('wamAssetEditorApply'));
    await waitFor(() => expect(screen.getByTestId('wamAsset-db-prod-01')).toBeTruthy());
    fireEvent.click(screen.getByTestId('wamAssetSave'));
    await waitFor(() => expect(api.saveAssetSettings).toHaveBeenCalled());
    expect(api.saveAssetSettings.mock.calls[0][0].assets[2]).toEqual({
      id: 'db-prod-01',
      match: { kind: 'name', value: 'DB-Prod-01' },
      criticality: 'critical',
      tags: ['crown-jewel', 'pci'],
    });
  });

  test('an id typed deliberately is kept when the value changes afterwards', async () => {
    const api = apiServiceWith(true);
    render(<AssetSettingsView apiService={api} onToast={jest.fn()} />);
    await waitFor(() => expect(screen.getByTestId('wamAssetAdd')).toBeTruthy());
    fireEvent.click(screen.getByTestId('wamAssetAdd'));
    // Untouched id follows the value...
    fireEvent.change(screen.getByTestId('wamAssetEditorValue'), { target: { value: 'mail-*' } });
    expect((screen.getByTestId('wamAssetEditorId') as HTMLInputElement).value).toBe('mail');
    // ...until the user edits it; an id starting with "asset" must survive too.
    fireEvent.change(screen.getByTestId('wamAssetEditorId'), { target: { value: 'asset-db-01' } });
    fireEvent.change(screen.getByTestId('wamAssetEditorValue'), { target: { value: 'db-*' } });
    expect((screen.getByTestId('wamAssetEditorId') as HTMLInputElement).value).toBe('asset-db-01');
  });

  test('Test match calls the resolve route and shows the resolved criticality', async () => {
    const api = apiServiceWith(true);
    render(<AssetSettingsView apiService={api} onToast={jest.fn()} />);
    await waitFor(() => expect(screen.getByTestId('wamAssetTestRun')).toBeTruthy());
    fireEvent.change(screen.getByTestId('wamAssetTestName'), { target: { value: 'web-07' } });
    fireEvent.change(screen.getByTestId('wamAssetTestGroups'), { target: { value: 'default, dmz' } });
    fireEvent.click(screen.getByTestId('wamAssetTestRun'));
    await waitFor(() => expect(screen.getByTestId('wamAssetTestResult')).toBeTruthy());
    expect(api.resolveAsset).toHaveBeenCalledWith({ agentName: 'web-07', groups: ['default', 'dmz'], labels: [] });
    expect(screen.getByTestId('wamAssetTestCriticality').textContent).toBe('High');
  });

  test('suggestId derives a unique lower-case id', () => {
    expect(suggestId('Web Prod*', [])).toBe('web-prod');
    expect(suggestId('web', [{ id: 'web' } as any])).toBe('web-2');
  });
});

describe('AssetBadge', () => {
  test('renders nothing without a stamped criticality and the label with one', () => {
    const { container } = render(<AssetBadge asset={{ criticality: null, tags: [], groups: [], labels: null, matched_id: null, matched_by: null }} />);
    expect(container.innerHTML).toBe('');
    render(<AssetBadge compact testSubj="badge" asset={{ criticality: 'critical', tags: ['pci'], groups: ['dmz'], labels: null, matched_id: 'dmz', matched_by: 'group' }} />);
    expect(screen.getByTestId('badge').textContent).toBe('Critical');
  });
});
