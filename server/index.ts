import { PluginInitializerContext } from '../../../src/core/server';
import { WazuhAlertManagerPlugin } from './plugin';
import { configSchema } from './config';

export const config = {
  schema: configSchema,
};

export function plugin(initializerContext: PluginInitializerContext) {
  return new WazuhAlertManagerPlugin(initializerContext);
}

export { WazuhAlertManagerPluginSetup, WazuhAlertManagerPluginStart } from './types';
