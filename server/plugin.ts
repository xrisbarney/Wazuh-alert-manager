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
import { startReportScheduler } from './lib/report_schedules/scheduler';
import { setSlaEscalationRuntime, startSlaEscalationScanner } from './lib/sla/escalation';
import { setNotificationRuntime } from './lib/notifications/render';
import { setNotificationDispatcherRuntime, startNotificationDispatcher } from './lib/notifications/dispatcher';
import { createNotificationEmitter, registerNotificationEmitter } from './lib/notifications/emitters';
import { registerActivityEmitter } from './lib/activity';
import { runSavedObjectsBridge } from './lib/saved_objects_bridge';

export class WazuhAlertManagerPlugin
  implements Plugin<WazuhAlertManagerPluginSetup, WazuhAlertManagerPluginStart> {
  private readonly logger: Logger;
  private stopSyncJob: () => void = () => {};
  private stopLifecycleJob: () => void = () => {};
  private stopAutomationWorker: () => void = () => {};
  private stopRetirementRecoveryJob: () => void = () => {};
  private stopReportScheduler: () => void = () => {};
  private stopSlaEscalation: () => void = () => {};
  private stopNotificationDispatcher: () => void = () => {};
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

  public async start(core: CoreStart, plugins: { wazuhCore?: unknown } = {}) {
    this.logger.debug('wazuhAlertManager: Started');
    // Optional dependency (opensearch_dashboards.json optionalPlugins): only
    // the sync job uses it, for 4.x agent groups (step 6.4a).
    const wazuhCore = (plugins && (plugins as any).wazuhCore) || null;

    const client = core.opensearch.client.asInternalUser;

    this.stopped = false;
    const readinessPromise = this.initializerContext.config
      .create<AlertManagerConfigType>()
      .pipe(take(1))
      .toPromise()
      .then(async (config) => {
        await ensureIndices(client, this.logger);
        return config;
      });

    this.initializationPromise = readinessPromise
      .then(async (config) => {
        if (this.stopped) return;
        // Discover/Reporting bridge (step 5.6): index patterns + saved
        // searches through the internal saved-objects repository. Runs after
        // provisioning (its version record lives in the meta index) and is
        // never fatal; the outcome is reported by GET /system/version.
        await runSavedObjectsBridge(core, client, this.logger);
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
        this.stopSyncJob = startSyncJob(client, config, this.logger, { wazuhCore });
        // Notifications (step 1.1): deep-link base for rendered payloads.
        setNotificationRuntime(config);
        // Notification emitters (step 1.3): one instance on the internal
        // client feeds the outbox from the case activity hook, the routes
        // (severity raise, report run-now), the SLA scanner and the report
        // scheduler. Registered before the producers start.
        const emitter = createNotificationEmitter(() => client, this.logger);
        registerNotificationEmitter(emitter);
        registerActivityEmitter(emitter.activityHook);
        // Scheduled summaries (step 5.4): lease-based, so every replica may
        // start it; only the lease holder renders.
        if (config.reports?.scheduler?.enabled) {
          this.stopReportScheduler = startReportScheduler(client, config, this.logger, { emitter });
          if (this.stopped) {
            this.stopReportScheduler();
            this.stopReportScheduler = () => {};
          }
        }
        // SLA escalation scanner (step 3.3): same lease pattern; the runtime
        // record lets GET /sla/escalation/status report enabled/tickSeconds.
        setSlaEscalationRuntime(config);
        if (config.sla?.escalation?.enabled) {
          this.stopSlaEscalation = startSlaEscalationScanner(client, config, this.logger, { emitter });
          if (this.stopped) {
            this.stopSlaEscalation();
            this.stopSlaEscalation = () => {};
          }
        }
        // Notification outbox dispatcher (step 1.2): lease-based like the SLA
        // scanner; one replica delivers the queued notifications.
        setNotificationDispatcherRuntime(config);
        if (config.notifications?.dispatcher?.enabled) {
          this.stopNotificationDispatcher = startNotificationDispatcher(client, config, this.logger);
          if (this.stopped) {
            this.stopNotificationDispatcher();
            this.stopNotificationDispatcher = () => {};
          }
        }
        // Historical reporting materialization is resumable and must never
        // delay live sync, lifecycle checks, or automation on startup.
        runReportingBackfill(client, this.logger).catch((e) => {
          this.logger.error(`wazuhAlertManager: reporting backfill will retry on next start: ${e.message}`);
        });
      })
      .catch((e) => {
        this.stopNotificationDispatcher();
        this.stopNotificationDispatcher = () => {};
        this.stopSlaEscalation();
        this.stopSlaEscalation = () => {};
        this.stopReportScheduler();
        this.stopReportScheduler = () => {};
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

    // OpenSearch Dashboards may advertise HTTP readiness as soon as plugin
    // start returns. Hold that boundary until the plugin-owned aliases and
    // mappings exist so a first page load cannot race provisioning. Lengthy,
    // resumable migrations and worker startup continue through the tracked
    // initialization promise above.
    await readinessPromise.catch(() => undefined);
    return {};
  }

  public async stop() {
    this.stopped = true;
    registerActivityEmitter(null);
    registerNotificationEmitter(null);
    this.stopNotificationDispatcher();
    this.stopSlaEscalation();
    this.stopReportScheduler();
    this.stopSyncJob();
    this.stopAutomationWorker();
    this.stopLifecycleJob();
    this.stopRetirementRecoveryJob();
    await this.initializationPromise;
    this.initializationPromise = null;
  }
}
