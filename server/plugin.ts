import {
  PluginInitializerContext,
  CoreSetup,
  CoreStart,
  Plugin,
  Logger,
} from '......srccoreserver';

import { WazuhAlertManagerPluginSetup, WazuhAlertManagerPluginStart } from './types';
import { defineRoutes } from './routes';

export class WazuhAlertManagerPlugin
  implements Plugin<WazuhAlertManagerPluginSetup, WazuhAlertManagerPluginStart> {
  private readonly logger: Logger;

  constructor(initializerContext: PluginInitializerContext) {
    this.logger = initializerContext.logger.get();
  }

  public setup(core: CoreSetup) {
    this.logger.debug('wazuhAlertManager: Setup');
    const router = core.http.createRouter();

    // Register server side APIs
    defineRoutes(router);

    return {};
  }

  public start(core: CoreStart) {
    this.logger.debug('wazuhAlertManager: Started');
    return {};
  }

  public stop() {}
}
