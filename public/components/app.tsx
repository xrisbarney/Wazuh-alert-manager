import React, { useState } from 'react';
import {
  EuiPage,
  EuiPageBody,
  EuiPageContent,
  EuiPageContentBody,
  EuiPageHeader,
  EuiTitle,
  EuiTabs,
  EuiTab,
  EuiGlobalToastList,
  EuiGlobalToastListToast,
} from '@elastic/eui';
import { CoreStart } from '../../../../src/core/public';
import { DataPublicPluginStart } from '../../../../src/plugins/data/public';
import { AlertsApiService } from '../services/api';
import { AlertsView } from './alerts_view';
import { CasesView } from './cases_view';
import { AiSettingsView } from './ai_settings_view';
import { ReportsView } from './reports_view';

interface AppProps {
  coreStart: CoreStart;
  dataStart: DataPublicPluginStart;
  basename: string;
}

type TabId = 'alerts' | 'cases' | 'reports' | 'ai-settings';

export const WazuhAlertManagerApp: React.FC<AppProps> = ({ coreStart }) => {
  const [activeTab, setActiveTab] = useState<TabId>('alerts');
  const [toasts, setToasts] = useState<EuiGlobalToastListToast[]>([]);
  const [jumpToCaseId, setJumpToCaseId] = useState<string | undefined>();
  const [openAlertId, setOpenAlertId] = useState<string | undefined>();

  const apiService = React.useMemo(() => new AlertsApiService(coreStart.http), [coreStart.http]);

  const addToast = (title: string, color: 'success' | 'danger' | 'primary', text?: string) => {
    setToasts((prev) => [...prev, { id: Math.random().toString(), title, color, text }]);
  };

  const removeToast = (toast: EuiGlobalToastListToast) => {
    setToasts((prev) => prev.filter((t) => t.id !== toast.id));
  };

  const openCase = (caseId: string) => {
    setJumpToCaseId(caseId);
    setActiveTab('cases');
  };

  const openAlert = (alertId: string) => {
    setOpenAlertId(alertId);
    setActiveTab('alerts');
  };

  return (
    <>
      <EuiPage paddingSize="l">
        <EuiPageBody>
          <EuiPageHeader>
            <EuiTitle size="l">
              <h1>Wazuh Alert Manager</h1>
            </EuiTitle>
          </EuiPageHeader>

          <EuiTabs>
            <EuiTab isSelected={activeTab === 'alerts'} onClick={() => setActiveTab('alerts')}>
              Alerts
            </EuiTab>
            <EuiTab isSelected={activeTab === 'cases'} onClick={() => setActiveTab('cases')}>
              Cases
            </EuiTab>
            <EuiTab isSelected={activeTab === 'reports'} onClick={() => setActiveTab('reports')}>
              Reports
            </EuiTab>
            <EuiTab isSelected={activeTab === 'ai-settings'} onClick={() => setActiveTab('ai-settings')}>
              AI Settings
            </EuiTab>
          </EuiTabs>

          <EuiPageContent>
            <EuiPageContentBody>
              {activeTab === 'alerts' && (
                <AlertsView
                  apiService={apiService}
                  onToast={addToast}
                  onOpenCase={openCase}
                  openAlertId={openAlertId}
                  onOpenAlertHandled={() => setOpenAlertId(undefined)}
                />
              )}
              {activeTab === 'cases' && (
                <CasesView
                  apiService={apiService}
                  onToast={addToast}
                  openCaseId={jumpToCaseId}
                  onOpenAlert={openAlert}
                  onCaseFlyoutClosed={() => setJumpToCaseId(undefined)}
                />
              )}
              {activeTab === 'reports' && <ReportsView apiService={apiService} onToast={addToast} />}
              {activeTab === 'ai-settings' && <AiSettingsView apiService={apiService} onToast={addToast} />}
            </EuiPageContentBody>
          </EuiPageContent>
        </EuiPageBody>
      </EuiPage>

      <EuiGlobalToastList toasts={toasts} dismissToast={removeToast} toastLifeTimeMs={6000} />
    </>
  );
};
