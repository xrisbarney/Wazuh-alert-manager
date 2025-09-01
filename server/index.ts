import { PluginInitializerContext } from '......srccoreserver';
import { WazuhAlertManagerPlugin } from './plugin';

// This exports static code and TypeScript types,
// as well as, OpenSearch Dashboards Platform `plugin()` initializer.

export function plugin(initializerContext: PluginInitializerContext) {
  return new WazuhAlertManagerPlugin(initializerContext);
}

export { WazuhAlertManagerPluginSetup, WazuhAlertManagerPluginStart } from './types';
