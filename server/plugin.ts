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
import { migrateLegacyData } from './lib/legacy_migration';
import { migrateSavedRuleSchemas } from './lib/rule_schema_migration';
import { ensureLifecycleSettings, startLifecycleJob } from './lib/lifecycle';
import { ensureAutomationSettings, startAutomationWorker } from './lib/automation_queue';
import { backfillCaseUids } from './lib/case_uid_migration';
import { migrateCaseAliases } from './lib/case_alias_migration';
import { recoverPreparingAlertRetirements, startRetirementRecoveryJob } from './lib/alert_retirement';
import { runReportingBackfill } from './lib/reporting_backfill';

export class WazuhAlertManagerPlugin
  implements Plugin<WazuhAlertManagerPluginSetup, WazuhAlertManagerPluginStart> {
  private readonly logger: Logger;
  private stopSyncJob: () => void = () => {};
  private stopLifecycleJob: () => void = () => {};
  private stopAutomationWorker: () => void = () => {};
  private stopRetirementRecoveryJob: () => void = () => {};
  private initializationPromise: Promise<void> | null = null;
  private stopped = false;

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

    this.stopped = false;
    this.initializationPromise = this.initializerContext.config
      .create<AlertManagerConfigType>()
      .pipe(take(1))
      .toPromise()
      .then(async (config) => {
        await ensureIndices(client, this.logger);
        if (this.stopped) return;
        await migrateCaseAliases(client, this.logger);
        if (this.stopped) return;
        await ensureLifecycleSettings(client, config);
        if (this.stopped) return;
        await ensureAutomationSettings(client);
        if (this.stopped) return;
        await migrateLegacyData(client, config, this.logger);
        if (this.stopped) return;
        await backfillCaseUids(client);
        if (this.stopped) return;
        await migrateSavedRuleSchemas(client, this.logger);
        if (this.stopped) return;
        await recoverPreparingAlertRetirements(client, this.logger);
        if (this.stopped) return;
        this.stopRetirementRecoveryJob = startRetirementRecoveryJob(client, this.logger);
        if (this.stopped) {
          this.stopRetirementRecoveryJob();
          this.stopRetirementRecoveryJob = () => {};
          return;
        }
        this.stopLifecycleJob = startLifecycleJob(client, config, this.logger);
        if (this.stopped) {
          this.stopLifecycleJob();
          this.stopLifecycleJob = () => {};
          this.stopRetirementRecoveryJob();
          this.stopRetirementRecoveryJob = () => {};
          return;
        }
        this.stopAutomationWorker = startAutomationWorker(client, this.logger);
        if (this.stopped) {
          this.stopAutomationWorker();
          this.stopAutomationWorker = () => {};
          this.stopLifecycleJob();
          this.stopLifecycleJob = () => {};
          this.stopRetirementRecoveryJob();
          this.stopRetirementRecoveryJob = () => {};
          return;
        }
        this.stopSyncJob = startSyncJob(client, config, this.logger);
        // Historical reporting materialization is resumable and must never
        // delay live sync, lifecycle checks, or automation on startup.
        runReportingBackfill(client, this.logger).catch((e) => {
          this.logger.error(`wazuhAlertManager: reporting backfill will retry on next start: ${e.message}`);
        });
      })
      .catch((e) => {
        this.stopSyncJob();
        this.stopSyncJob = () => {};
        this.stopAutomationWorker();
        this.stopAutomationWorker = () => {};
        this.stopLifecycleJob();
        this.stopLifecycleJob = () => {};
        this.stopRetirementRecoveryJob();
        this.stopRetirementRecoveryJob = () => {};
        this.logger.error(`wazuhAlertManager: failed to provision indices: ${e.message}`);
      });

    return {};
  }

  public async stop() {
    this.stopped = true;
    this.stopSyncJob();
    this.stopAutomationWorker();
    this.stopLifecycleJob();
    this.stopRetirementRecoveryJob();
    await this.initializationPromise;
    this.initializationPromise = null;
  }
}
