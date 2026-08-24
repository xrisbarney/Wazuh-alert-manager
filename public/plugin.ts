import { CoreSetup, CoreStart, Plugin, AppMountParameters } from '../../../src/core/public';
import { DataPublicPluginSetup, DataPublicPluginStart } from '../../../src/plugins/data/public';
import { WazuhAlertManagerPluginSetup, WazuhAlertManagerPluginStart } from './types';
import { PLUGIN_NAME } from '../common';

// Inlined as a data URI (matching public/assets/logo.svg) rather than an
// http.basePath.prepend()'d asset URL - Wazuh's custom side nav renders app
// icons as a plain <img src>, and that failed to load the asset route in
// practice (broken-image placeholder in the nav) even though the route
// itself served the file correctly. A data URI needs no network round trip,
// so it can't be affected by whatever that nav does with the src.
const NAV_ICON =
  'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMzIiIGhlaWdodD0iMzIiIHZpZXdCb3g9IjAgMCAzMiAzMiIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KICA8cGF0aCBkPSJNMTYgMiBMMjggNi41IFYxNSBDMjggMjIuNSAyMi44IDI3LjggMTYgMzAgQzkuMiAyNy44IDQgMjIuNSA0IDE1IFY2LjUgWiIKICAgICAgICBmaWxsPSIjMEI2NEREIi8+CiAgPHBhdGggZD0iTTE2IDIgTDI4IDYuNSBWMTUgQzI4IDIyLjUgMjIuOCAyNy44IDE2IDMwIFoiCiAgICAgICAgZmlsbD0iIzA3NEZCMyIvPgogIDxwYXRoIGQ9Ik0xNiA4LjUgTDE2IDE4IiBzdHJva2U9IiNGRkZGRkYiIHN0cm9rZS13aWR0aD0iMi42IiBzdHJva2UtbGluZWNhcD0icm91bmQiLz4KICA8Y2lyY2xlIGN4PSIxNiIgY3k9IjIyLjUiIHI9IjEuOCIgZmlsbD0iI0ZGRkZGRiIvPgogIDxjaXJjbGUgY3g9IjI0IiBjeT0iOS41IiByPSIzLjIiIGZpbGw9IiNGNUE2MjMiLz4KPC9zdmc+Cg==';

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
      icon: NAV_ICON,
      order: 9010,
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