import React from 'react';
import ReactDOM from 'react-dom';
import { AppMountParameters, CoreStart } from '../../../src/core/public';
import { DataPublicPluginStart } from '../../../src/plugins/data/public';
import { WazuhAlertManagerApp, AppSection } from './components/app';

export const renderApp = (
  coreStart: CoreStart,
  dataStart: DataPublicPluginStart,
  { appBasePath, element }: AppMountParameters,
  section: AppSection = 'workbench'
) => {
  ReactDOM.render(
    <WazuhAlertManagerApp
      coreStart={coreStart}
      dataStart={dataStart}
      basename={appBasePath}
      section={section}
    />,
    element
  );

  return () => ReactDOM.unmountComponentAtNode(element);
};
