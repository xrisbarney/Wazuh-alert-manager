import React, { useState, useEffect } from 'react';
import {
  EuiPage,
  EuiPageBody,
  EuiPageContent,
  EuiPageContentBody,
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
import { SettingsView } from './settings_view';
import { ReportsView } from './reports_view';

export type AppSection = 'workbench' | 'reporting';

interface AppProps {
  coreStart: CoreStart;
  dataStart: DataPublicPluginStart;
  basename: string;
  // Which nav child this mount is - the plugin registers Workbench and Reporting
  // as two apps under one collapsible category, and each mounts this component
  // with the matching section.
  section?: AppSection;
}

type WorkbenchTab = 'alerts' | 'cases' | 'settings';

export const WazuhAlertManagerApp: React.FC<AppProps> = ({ coreStart, section = 'workbench' }) => {
  const [activeTab, setActiveTab] = useState<WorkbenchTab>('alerts');
  const [toasts, setToasts] = useState<EuiGlobalToastListToast[]>([]);
  const [jumpToCaseId, setJumpToCaseId] = useState<string | undefined>();
  const [openAlertId, setOpenAlertId] = useState<string | undefined>();

  const apiService = React.useMemo(() => new AlertsApiService(coreStart.http), [coreStart.http]);

  // Put the title in the dashboard's top breadcrumb bar (like the other Wazuh
  // modules) instead of a large in-page header, reclaiming the vertical space.
  useEffect(() => {
    coreStart.chrome.setBreadcrumbs([
      { text: 'Wazuh alert manager' },
      { text: section === 'reporting' ? 'Reporting' : 'Workbench' },
    ]);
  }, [coreStart.chrome, section]);

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
      <EuiPage paddingSize="m">
        <EuiPageBody>
          {section === 'reporting' ? (
            <EuiPageContent>
              <EuiPageContentBody>
                <ReportsView apiService={apiService} onToast={addToast} />
              </EuiPageContentBody>
            </EuiPageContent>
          ) : (
            <>
              <EuiTabs>
                <EuiTab isSelected={activeTab === 'alerts'} onClick={() => setActiveTab('alerts')}>
                  Alerts
                </EuiTab>
                <EuiTab isSelected={activeTab === 'cases'} onClick={() => setActiveTab('cases')}>
                  Cases
                </EuiTab>
                <EuiTab isSelected={activeTab === 'settings'} onClick={() => setActiveTab('settings')}>
                  Settings
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
                  {activeTab === 'settings' && <SettingsView apiService={apiService} onToast={addToast} />}
                </EuiPageContentBody>
              </EuiPageContent>
            </>
          )}
        </EuiPageBody>
      </EuiPage>

      <EuiGlobalToastList toasts={toasts} dismissToast={removeToast} toastLifeTimeMs={6000} />
    </>
  );
};
