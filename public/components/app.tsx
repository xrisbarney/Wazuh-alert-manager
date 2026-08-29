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
  EuiFlexGroup,
  EuiFlexItem,
  EuiIcon,
  EuiText,
  EuiTitle,
  EuiSpacer,
  EuiCallOut,
  EuiButtonEmpty,
} from '@elastic/eui';
import { CoreStart } from '../../../../src/core/public';
import { DataPublicPluginStart } from '../../../../src/plugins/data/public';
import { AlertsApiService } from '../services/api';
import { AlertsView } from './alerts_view';
import { CasesView } from './cases_view';
import { SettingsView } from './settings_view';
import { ReportsView } from './reports_view';
import { PLUGIN_BUILD_ID } from '../../common';
import { BuildInfo } from '../services/api';

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
  const initialParams = React.useMemo(() => new URLSearchParams(window.location.search), []);
  const requestedTab = initialParams.get('tab');
  const initialTab: WorkbenchTab = requestedTab === 'cases' || requestedTab === 'settings' ? requestedTab : 'alerts';
  const [activeTab, setActiveTab] = useState<WorkbenchTab>(initialTab);
  const [toasts, setToasts] = useState<EuiGlobalToastListToast[]>([]);
  const [jumpToCaseId, setJumpToCaseId] = useState<string | undefined>(initialParams.get('case') || undefined);
  const [openAlertId, setOpenAlertId] = useState<string | undefined>(initialParams.get('alert') || undefined);
  const [serverBuild, setServerBuild] = useState<BuildInfo | null>(null);

  const apiService = React.useMemo(() => new AlertsApiService(coreStart.http), [coreStart.http]);

  // Put the title in the dashboard's top breadcrumb bar (like the other Wazuh
  // modules) instead of a large in-page header, reclaiming the vertical space.
  useEffect(() => {
    coreStart.chrome.setBreadcrumbs([
      { text: 'Wazuh alert manager' },
      { text: section === 'reporting' ? 'Reporting' : 'Workbench' },
    ]);
  }, [coreStart.chrome, section]);

  useEffect(() => {
    apiService.fetchBuildInfo().then(setServerBuild).catch(() => undefined);
  }, [apiService]);

  const addToast = (title: string, color: 'success' | 'danger' | 'primary', text?: string) => {
    setToasts((prev) => [...prev, { id: Math.random().toString(), title, color, text }]);
  };

  const removeToast = (toast: EuiGlobalToastListToast) => {
    setToasts((prev) => prev.filter((t) => t.id !== toast.id));
  };

  const updateLocation = (tab: WorkbenchTab, values: { caseId?: string | null; alertId?: string | null } = {}) => {
    const url = new URL(window.location.href);
    url.searchParams.set('tab', tab);
    if (values.caseId) url.searchParams.set('case', values.caseId);
    else if (values.caseId === null) url.searchParams.delete('case');
    if (values.alertId) url.searchParams.set('alert', values.alertId);
    else if (values.alertId === null) url.searchParams.delete('alert');
    window.history.replaceState({}, '', url.toString());
  };

  const selectTab = (tab: WorkbenchTab) => {
    setActiveTab(tab);
    updateLocation(tab, { caseId: tab === 'cases' ? undefined : null, alertId: tab === 'alerts' ? undefined : null });
  };

  const openCase = (caseId: string) => {
    setJumpToCaseId(caseId);
    setActiveTab('cases');
    updateLocation('cases', { caseId, alertId: null });
  };

  const openAlert = (alertId: string) => {
    setOpenAlertId(alertId);
    setActiveTab('alerts');
    updateLocation('alerts', { alertId, caseId: null });
  };

  return (
    <>
      <EuiPage paddingSize="m" className="wamApp">
        <EuiPageBody>
          {serverBuild && serverBuild.buildId !== PLUGIN_BUILD_ID && (
            <>
              <EuiCallOut
                color="warning"
                iconType="refresh"
                title="Update available — reload Workbench"
              >
                <p>The server is running build <code>{serverBuild.buildId}</code>, but this browser has <code>{PLUGIN_BUILD_ID}</code>.</p>
                <EuiButtonEmpty size="s" iconType="refresh" onClick={() => window.location.reload()}>
                  Reload Workbench
                </EuiButtonEmpty>
              </EuiCallOut>
              <EuiSpacer size="m" />
            </>
          )}
          {section === 'reporting' ? (
            <EuiPageContent>
              <EuiPageContentBody>
                <ReportsView apiService={apiService} onToast={addToast} />
              </EuiPageContentBody>
            </EuiPageContent>
          ) : (
            <>
              <div className="wamWorkbenchHeader">
                <EuiFlexGroup alignItems="center" responsive={false} gutterSize="m" className="wamPageIntro">
                  <EuiFlexItem grow={false}>
                    <span className="wamPageIntro__icon"><EuiIcon type="securitySignal" size="l" /></span>
                  </EuiFlexItem>
                  <EuiFlexItem>
                    <EuiTitle size="s"><h1>Security operations workbench</h1></EuiTitle>
                    <EuiText size="s" color="subdued">Triage alerts, coordinate investigations, and automate repeatable decisions.</EuiText>
                  </EuiFlexItem>
                </EuiFlexGroup>
                <EuiSpacer size="m" />
                <EuiTabs className="wamWorkbenchTabs">
                  <EuiTab isSelected={activeTab === 'alerts'} onClick={() => selectTab('alerts')}>Alerts</EuiTab>
                  <EuiTab isSelected={activeTab === 'cases'} onClick={() => selectTab('cases')}>Cases</EuiTab>
                  <EuiTab isSelected={activeTab === 'settings'} onClick={() => selectTab('settings')}>Settings</EuiTab>
                </EuiTabs>
              </div>

              <EuiPageContent className="wamPageContent">
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
                      onCaseFlyoutClosed={() => {
                        setJumpToCaseId(undefined);
                        updateLocation('cases', { caseId: null });
                      }}
                    />
                  )}
                  {activeTab === 'settings' && <SettingsView apiService={apiService} onToast={addToast} />}
                </EuiPageContentBody>
              </EuiPageContent>
            </>
          )}
        </EuiPageBody>
      </EuiPage>

      <EuiGlobalToastList className="wamGlobalToasts" toasts={toasts} dismissToast={removeToast} toastLifeTimeMs={6000} />
    </>
  );
};
