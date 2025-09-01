import React from 'react';
import ReactDOM from 'react-dom';
import { AppMountParameters, CoreStart } from '../../../src/core/public';
import { DataPublicPluginStart } from '../../../src/plugins/data/public';
import { WazuhAlertManagerApp } from './components/app';

export const renderApp = (
  coreStart: CoreStart,
  dataStart: DataPublicPluginStart,
  { appBasePath, element }: AppMountParameters
) => {
  ReactDOM.render(
    <WazuhAlertManagerApp
      coreStart={coreStart}
      dataStart={dataStart}
      basename={appBasePath}
    />,
    element
  );

  return () => ReactDOM.unmountComponentAtNode(element);
};