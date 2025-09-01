import { CoreSetup, CoreStart, Plugin, AppMountParameters } from '../../../src/core/public';
import { DataPublicPluginSetup, DataPublicPluginStart } from '../../../src/plugins/data/public';
import { WazuhAlertManagerPluginSetup, WazuhAlertManagerPluginStart } from './types';
import { PLUGIN_NAME } from '../common';

interface WazuhAlertManagerPluginSetupDeps {
  data: DataPublicPluginSetup;
}

interface WazuhAlertManagerPluginStartDeps {
  data: DataPublicPluginStart;
}

export class WazuhAlertManagerPlugin
  implements Plugin<
    WazuhAlertManagerPluginSetup,
    WazuhAlertManagerPluginStart,
    WazuhAlertManagerPluginSetupDeps,
    WazuhAlertManagerPluginStartDeps
  > {
  public setup(
    core: CoreSetup<WazuhAlertManagerPluginStartDeps>,
    { data }: WazuhAlertManagerPluginSetupDeps
  ): WazuhAlertManagerPluginSetup {
    // Register an application into the side navigation menu
    core.application.register({
      id: PLUGIN_NAME,
      title: 'Wazuh Alert Manager',
      async mount(params: AppMountParameters) {
        // Load application bundle
        const { renderApp } = await import('./application');
        // Get start services as specified in opensearch_dashboards.json
        const [coreStart, pluginsStart] = await core.getStartServices();
        // Render the application
        return renderApp(coreStart, (pluginsStart as WazuhAlertManagerPluginStartDeps).data, params);
      },
    });

    return {};
  }

  public start(core: CoreStart, { data }: WazuhAlertManagerPluginStartDeps): WazuhAlertManagerPluginStart {
    return {};
  }

  public stop() { }
}