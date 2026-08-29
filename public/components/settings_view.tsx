import React, { useState } from 'react';
import { EuiTabbedContent } from '@elastic/eui';
import { AlertsApiService } from '../services/api';
import { AiSettingsView } from './ai_settings_view';
import { RulesView } from './rules_view';
import { StorageHealthView } from './storage_health_view';
import { AboutView } from './about_view';
import { SyncSettingsView } from './sync_settings_view';

interface Props {
  apiService: AlertsApiService;
  onToast: (title: string, color: 'success' | 'danger' | 'primary', text?: string) => void;
}

export const SettingsView: React.FC<Props> = ({ apiService, onToast }) => {
  const requested = new URLSearchParams(window.location.search).get('settingsTab');
  const initial = ['automation', 'ai', 'sync', 'storage', 'about'].includes(requested || '') ? requested! : 'automation';
  const [selected, setSelected] = useState(initial);
  const selectTab = (id: string) => {
    setSelected(id);
    const url = new URL(window.location.href);
    url.searchParams.set('settingsTab', id);
    window.history.replaceState({}, '', url.toString());
  };
  const tabs = [
    {
      id: 'automation',
      name: 'Automation rules',
      content: <RulesView apiService={apiService} onToast={onToast} />,
    },
    {
      id: 'ai',
      name: 'AI analysis',
      content: <AiSettingsView apiService={apiService} onToast={onToast} />,
    },
    {
      id: 'sync',
      name: 'Background sync',
      content: <SyncSettingsView apiService={apiService} onToast={onToast} />,
    },
    {
      id: 'storage',
      name: 'Storage & lifecycle',
      content: <StorageHealthView apiService={apiService} onToast={onToast} />,
    },
    {
      id: 'about',
      name: 'About',
      content: <AboutView apiService={apiService} />,
    },
  ];
  return (
    <EuiTabbedContent
      className="wamSettingsTabs"
      size="s"
      selectedTab={tabs.find((tab) => tab.id === selected)}
      onTabClick={(t) => selectTab(t.id)}
      tabs={tabs}
    />
  );
};
