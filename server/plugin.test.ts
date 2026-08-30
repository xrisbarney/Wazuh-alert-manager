jest.mock('./routes', () => ({ defineRoutes: jest.fn() }));
jest.mock('./lib/provision', () => ({ ensureIndices: jest.fn() }));
jest.mock('./lib/legacy_migration', () => ({ migrateLegacyData: jest.fn() }));
jest.mock('./lib/rule_schema_migration', () => ({ migrateSavedRuleSchemas: jest.fn() }));
jest.mock('./lib/lifecycle', () => ({
  ensureLifecycleSettings: jest.fn(),
  startLifecycleJob: jest.fn(),
}));
jest.mock('./lib/automation_queue', () => ({ ensureAutomationSettings: jest.fn(), startAutomationWorker: jest.fn() }));
jest.mock('./lib/sync_job', () => ({ startSyncJob: jest.fn() }));
jest.mock('./lib/case_uid_migration', () => ({ backfillCaseUids: jest.fn() }));
jest.mock('./lib/case_alias_migration', () => ({ migrateCaseAliases: jest.fn() }));
jest.mock('./lib/alert_retirement', () => ({
  recoverPreparingAlertRetirements: jest.fn(),
  startRetirementRecoveryJob: jest.fn(),
}));

import { ensureAutomationSettings, startAutomationWorker } from './lib/automation_queue';
import { migrateLegacyData } from './lib/legacy_migration';
import { migrateSavedRuleSchemas } from './lib/rule_schema_migration';
import { ensureLifecycleSettings, startLifecycleJob } from './lib/lifecycle';
import { ensureIndices } from './lib/provision';
import { startSyncJob } from './lib/sync_job';
import { backfillCaseUids } from './lib/case_uid_migration';
import { migrateCaseAliases } from './lib/case_alias_migration';
import { recoverPreparingAlertRetirements, startRetirementRecoveryJob } from './lib/alert_retirement';
import { WazuhAlertManagerPlugin } from './plugin';

const logger: any = { debug: jest.fn(), info: jest.fn(), warn: jest.fn(), error: jest.fn() };
const config: any = { sync: {}, lifecycle: {}, migration: {} };
const core: any = { opensearch: { client: { asInternalUser: {} } } };

function pluginWithConfig(configPromise = Promise.resolve(config)) {
  const initializerContext: any = {
    logger: { get: () => logger },
    config: {
      create: () => ({ pipe: () => ({ toPromise: () => configPromise }) }),
    },
  };
  return new WazuhAlertManagerPlugin(initializerContext);
}

describe('plugin initialization lifecycle', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (ensureIndices as jest.Mock).mockResolvedValue(undefined);
    (ensureLifecycleSettings as jest.Mock).mockResolvedValue(undefined);
    (ensureAutomationSettings as jest.Mock).mockResolvedValue(undefined);
    (migrateLegacyData as jest.Mock).mockResolvedValue(undefined);
    (backfillCaseUids as jest.Mock).mockResolvedValue(undefined);
    (migrateCaseAliases as jest.Mock).mockResolvedValue(0);
    (migrateSavedRuleSchemas as jest.Mock).mockResolvedValue(undefined);
    (recoverPreparingAlertRetirements as jest.Mock).mockResolvedValue(0);
    (startRetirementRecoveryJob as jest.Mock).mockReturnValue(jest.fn());
    (startLifecycleJob as jest.Mock).mockReturnValue(jest.fn());
    (startAutomationWorker as jest.Mock).mockReturnValue(jest.fn());
    (startSyncJob as jest.Mock).mockReturnValue(jest.fn());
  });

  test('does not start workers after stop races initialization', async () => {
    let finishProvision!: () => void;
    (ensureIndices as jest.Mock).mockReturnValue(new Promise<void>((resolve) => (finishProvision = resolve)));
    const plugin = pluginWithConfig();

    const started = plugin.start(core);
    await Promise.resolve();
    const stopped = plugin.stop();
    finishProvision();
    await Promise.all([started, stopped]);

    expect(startLifecycleJob).not.toHaveBeenCalled();
    expect(startAutomationWorker).not.toHaveBeenCalled();
    expect(startSyncJob).not.toHaveBeenCalled();
  });

  test('does not report plugin start complete before owned indices are provisioned', async () => {
    let finishProvision!: () => void;
    (ensureIndices as jest.Mock).mockReturnValue(new Promise<void>((resolve) => (finishProvision = resolve)));
    const plugin = pluginWithConfig();
    let started = false;

    const startPromise = plugin.start(core).then(() => { started = true; });
    await Promise.resolve();
    await Promise.resolve();

    expect(ensureIndices).toHaveBeenCalledTimes(1);
    expect(started).toBe(false);

    finishProvision();
    await startPromise;

    expect(started).toBe(true);
  });

  test('cleans workers already started when a later startup stage fails', async () => {
    const stopLifecycle = jest.fn();
    const stopRecovery = jest.fn();
    (startLifecycleJob as jest.Mock).mockReturnValue(stopLifecycle);
    (startRetirementRecoveryJob as jest.Mock).mockReturnValue(stopRecovery);
    (startAutomationWorker as jest.Mock).mockImplementation(() => {
      throw new Error('worker failed');
    });
    const plugin = pluginWithConfig();

    plugin.start(core);
    await (plugin as any).initializationPromise;

    expect(stopLifecycle).toHaveBeenCalledTimes(1);
    expect(stopRecovery).toHaveBeenCalledTimes(1);
    expect(startSyncJob).not.toHaveBeenCalled();
    expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('worker failed'));
  });

  test('canonicalizes saved rules after legacy import and before workers start', async () => {
    const order: string[] = [];
    (migrateCaseAliases as jest.Mock).mockImplementation(async () => { order.push('case-aliases'); });
    (migrateLegacyData as jest.Mock).mockImplementation(async () => { order.push('legacy'); });
    (backfillCaseUids as jest.Mock).mockImplementation(async () => { order.push('case-uids'); });
    (migrateSavedRuleSchemas as jest.Mock).mockImplementation(async () => { order.push('rules'); });
    (recoverPreparingAlertRetirements as jest.Mock).mockImplementation(async () => { order.push('retirement-recovery'); });
    (startRetirementRecoveryJob as jest.Mock).mockImplementation(() => {
      order.push('retirement-recovery-job'); return jest.fn();
    });
    (startLifecycleJob as jest.Mock).mockImplementation(() => { order.push('lifecycle'); return jest.fn(); });
    (startAutomationWorker as jest.Mock).mockImplementation(() => { order.push('automation'); return jest.fn(); });
    (startSyncJob as jest.Mock).mockImplementation(() => { order.push('sync'); return jest.fn(); });

    const plugin = pluginWithConfig();
    plugin.start(core);
    await (plugin as any).initializationPromise;

    expect(order).toEqual([
      'case-aliases', 'legacy', 'case-uids', 'rules', 'retirement-recovery', 'retirement-recovery-job',
      'lifecycle', 'automation', 'sync',
    ]);
  });

  test('does not start workers when retirement recovery fails closed', async () => {
    (recoverPreparingAlertRetirements as jest.Mock).mockRejectedValue(new Error('unsafe preparing record'));
    const plugin = pluginWithConfig();

    plugin.start(core);
    await (plugin as any).initializationPromise;

    expect(startLifecycleJob).not.toHaveBeenCalled();
    expect(startAutomationWorker).not.toHaveBeenCalled();
    expect(startSyncJob).not.toHaveBeenCalled();
    expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('unsafe preparing record'));
    expect(startRetirementRecoveryJob).not.toHaveBeenCalled();
  });

  test('stops the periodic retirement recovery job on plugin stop', async () => {
    const stopRecovery = jest.fn();
    (startRetirementRecoveryJob as jest.Mock).mockReturnValue(stopRecovery);
    const plugin = pluginWithConfig();

    plugin.start(core);
    await (plugin as any).initializationPromise;
    await plugin.stop();

    expect(stopRecovery).toHaveBeenCalledTimes(1);
  });
});
