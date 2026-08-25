import { CoreSetup, CoreStart, Plugin, AppMountParameters } from '../../../src/core/public';
import { DataPublicPluginSetup, DataPublicPluginStart } from '../../../src/plugins/data/public';
import { WazuhAlertManagerPluginSetup, WazuhAlertManagerPluginStart } from './types';
import { PLUGIN_NAME } from '../common';

// The side nav renders `icon` (a URL) as a plain <img> but `euiIconType` as a
// first-class EUI glyph. Both an asset URL and an inlined data URI showed a
// broken-image placeholder there, so the nav entry uses euiIconType below -
// a named glyph can't fail to load. Verified present in the EUI fork that
// OSD 2.19.x ships (securityApp/watchesApp/reportingApp are NOT in it).
const NAV_EUI_ICON = 'securitySignal';

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
    // Register two apps under one collapsible category so the side nav shows
    // "Wazuh Alert Manager" as a group with "Workbench" and "Reporting" children.
    const category = {
      // Sentence case to match the other dashboard plugins' nav entries.
      id: 'wazuhAlertManager',
      label: 'Wazuh alert manager',
      order: 9010,
      euiIconType: NAV_EUI_ICON,
    };

    core.application.register({
      // Keep the original id for the workbench so existing links still resolve.
      id: PLUGIN_NAME,
      title: 'Workbench',
      category,
      euiIconType: NAV_EUI_ICON,
      order: 10,
      async mount(params: AppMountParameters) {
        const { renderApp } = await import('./application');
        const [coreStart, pluginsStart] = await core.getStartServices();
        return renderApp(coreStart, (pluginsStart as WazuhAlertManagerPluginStartDeps).data, params, 'workbench');
      },
    });

    core.application.register({
      id: 'wazuhAlertManagerReporting',
      title: 'Reporting',
      category,
      euiIconType: 'visBarVerticalStacked',
      order: 20,
      async mount(params: AppMountParameters) {
        const { renderApp } = await import('./application');
        const [coreStart, pluginsStart] = await core.getStartServices();
        return renderApp(coreStart, (pluginsStart as WazuhAlertManagerPluginStartDeps).data, params, 'reporting');
      },
    });

    return {};
  }

  public start(core: CoreStart, { data }: WazuhAlertManagerPluginStartDeps): WazuhAlertManagerPluginStart {
    return {};
  }

  public stop() { }
}