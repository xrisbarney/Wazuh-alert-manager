import { take } from 'rxjs/operators';
import {
  PluginInitializerContext,
  CoreSetup,
  CoreStart,
  Plugin,
  Logger,
} from '../../../src/core/server';

import { WazuhAlertManagerPluginSetup, WazuhAlertManagerPluginStart } from './types';
import { defineRoutes } from './routes';
import { AlertManagerConfigType } from './config';
import { ensureIndices } from './lib/provision';
import { startSyncJob } from './lib/sync_job';

export class WazuhAlertManagerPlugin
  implements Plugin<WazuhAlertManagerPluginSetup, WazuhAlertManagerPluginStart> {
  private readonly logger: Logger;
  private stopSyncJob: () => void = () => {};

  constructor(private readonly initializerContext: PluginInitializerContext) {
    this.logger = initializerContext.logger.get();
  }

  public setup(core: CoreSetup) {
    this.logger.debug('wazuhAlertManager: Setup');
    const router = core.http.createRouter();
    defineRoutes(router);
    return {};
  }

  public start(core: CoreStart) {
    this.logger.debug('wazuhAlertManager: Started');

    const client = core.opensearch.client.asInternalUser;

    this.initializerContext.config
      .create<AlertManagerConfigType>()
      .pipe(take(1))
      .toPromise()
      .then(async (config) => {
        await ensureIndices(client, this.logger);
        this.stopSyncJob = startSyncJob(client, config, this.logger);
      })
      .catch((e) => {
        this.logger.error(`wazuhAlertManager: failed to provision indices: ${e.message}`);
      });

    return {};
  }

  public stop() {
    this.stopSyncJob();
  }
}
