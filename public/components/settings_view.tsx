import React, { useState } from 'react';
import { EuiTabbedContent } from '@elastic/eui';
import { AlertsApiService } from '../services/api';
import { AiSettingsView } from './ai_settings_view';
import { RulesView } from './rules_view';

interface Props {
  apiService: AlertsApiService;
  onToast: (title: string, color: 'success' | 'danger' | 'primary', text?: string) => void;
}

export const SettingsView: React.FC<Props> = ({ apiService, onToast }) => {
  const [selected, setSelected] = useState('automation');
  return (
    <EuiTabbedContent
      size="s"
      selectedTab={undefined}
      initialSelectedTab={{ id: selected } as any}
      onTabClick={(t) => setSelected(t.id)}
      tabs={[
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
      ]}
    />
  );
};
