import React, { useState } from 'react';
import { EuiFlexGroup, EuiFlexItem } from '@elastic/eui';
import { AlertsApiService } from '../services/api';
import { AiSettingsView } from './ai_settings_view';
import { RulesView } from './rules_view';
import { StorageHealthView } from './storage_health_view';
import { AboutView } from './about_view';
import { SyncSettingsView } from './sync_settings_view';
import { EnrichmentSettingsView } from './enrichment_settings_view';
import { AssetSettingsView } from './asset_settings_view';
import { ReportSchedulesView } from './report_schedules_view';
import { SlaSettingsView } from './sla_settings_view';
import { NotificationSettingsView } from './notification_settings_view';
import { TaskListsView } from './task_lists_view';
import {
  DEFAULT_SETTINGS_SECTION,
  SettingsNav,
  SettingsSectionId,
  isSettingsSectionId,
  useSettingsNavCollapsed,
} from './settings_nav';

interface Props {
  apiService: AlertsApiService;
  onToast: (title: string, color: 'success' | 'danger' | 'primary', text?: string) => void;
}

/** The `?settingsTab=` deep link, or the default section. */
export function initialSettingsSection(search: string): SettingsSectionId {
  const requested = new URLSearchParams(search).get('settingsTab');
  return isSettingsSectionId(requested) ? requested : DEFAULT_SETTINGS_SECTION;
}

export const SettingsView: React.FC<Props> = ({ apiService, onToast }) => {
  const [selected, setSelected] = useState<SettingsSectionId>(() => initialSettingsSection(window.location.search));
  // Collapsed-rail preference (step 11.2): persisted per browser, default expanded.
  const [navCollapsed, toggleNavCollapsed] = useSettingsNavCollapsed();
  const select = (id: SettingsSectionId) => {
    setSelected(id);
    const url = new URL(window.location.href);
    url.searchParams.set('settingsTab', id);
    window.history.replaceState({}, '', url.toString());
  };

  const page = (() => {
    switch (selected) {
      case 'automation':
        return <RulesView apiService={apiService} onToast={onToast} />;
      case 'task-lists':
        return <TaskListsView apiService={apiService} onToast={onToast} />;
      case 'sla':
        return <SlaSettingsView apiService={apiService} onToast={onToast} />;
      case 'notifications':
        return <NotificationSettingsView apiService={apiService} onToast={onToast} />;
      case 'ai':
        return <AiSettingsView apiService={apiService} onToast={onToast} />;
      case 'enrichment':
        return <EnrichmentSettingsView apiService={apiService} onToast={onToast} />;
      case 'assets':
        return <AssetSettingsView apiService={apiService} onToast={onToast} />;
      case 'reports':
        return <ReportSchedulesView apiService={apiService} onToast={onToast} />;
      case 'sync':
        return <SyncSettingsView apiService={apiService} onToast={onToast} />;
      case 'storage':
        return <StorageHealthView apiService={apiService} onToast={onToast} />;
      case 'about':
        return <AboutView apiService={apiService} />;
    }
  })();

  return (
    <EuiFlexGroup gutterSize="l" alignItems="flexStart" responsive={false} className="wamSettingsLayout" data-test-subj="wamSettings">
      <EuiFlexItem
        grow={false}
        className={`wamSettingsNavColumn${navCollapsed ? ' wamSettingsNavColumn--collapsed' : ''}`}
      >
        <SettingsNav activeId={selected} onSelect={select} collapsed={navCollapsed} onToggleCollapsed={toggleNavCollapsed} />
      </EuiFlexItem>
      <EuiFlexItem className="wamSettingsContent" data-test-subj={`wamSettingsPage-${selected}`}>
        {page}
      </EuiFlexItem>
    </EuiFlexGroup>
  );
};
