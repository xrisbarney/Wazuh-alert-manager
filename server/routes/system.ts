import { schema } from '@osd/config-schema';
import { IRouter } from '../../../../src/core/server';
import {
  ACTIVITY_READ_ALIAS,
  ACTIVITY_WRITE_ALIAS,
  ALERTS_READ_ALIAS,
  ALERTS_WRITE_ALIAS,
  API_ROOT,
  LEGACY_ALERT_STATUS_INDEX,
  META_INDEX,
  MIGRATION_INDEX,
  SYNC_DLQ_INDEX,
  CASES_INDEX,
  CASES_READ_ALIAS,
  CASES_WRITE_ALIAS,
  EVIDENCE_READ_ALIAS,
  EVIDENCE_WRITE_ALIAS,
  PLUGIN_BUILD_ID,
  PLUGIN_BUILT_AT,
  PLUGIN_VERSION,
  TARGET_OSD_VERSION,
} from '../../common';
import { canManageLifecycle, isPluginAdmin, requireLifecycleManager, requirePluginAdmin } from '../lib/authorization';
import { trustedIdentity } from '../lib/identity';
import { LIFECYCLE_SETTINGS_ID, lifecycleStatus, loadLifecycleSettings } from '../lib/lifecycle';
import {
  executeAlertRetirement,
  planAlertRetirement,
  purgeRetiredAlertIndex,
  restoreRetiredAlertIndex,
} from '../lib/alert_retirement';
import { activityMapping, alertStatusMapping, casesMapping, evidenceMapping } from '../lib/mappings';
import { assertManagedWriteTarget } from '../lib/index_namespace';
import { purgeRetiredActivityIndex, retireActivityIndex } from '../lib/activity_retirement';
import { purgeRetiredEvidenceIndex, retireEvidenceIndex } from '../lib/evidence_retirement';
import {
  executeCaseRetirement,
  listArchivedCaseGenerations,
  planCaseRetirement,
  reopenArchivedCase,
  purgeArchivedCaseGeneration,
} from '../lib/case_retirement';
import { loadSyncSettings, saveSyncSettings } from '../lib/sync_settings';
import {
  automationQueueHealth,
  listAutomationDlq,
  loadAutomationSettings,
  resolveAutomationDlqEvent,
  retryAutomationDlqEvent,
  saveAutomationSettings,
} from '../lib/automation_queue';
import { isEvidenceHeld, scanArchiveEvidence } from '../lib/evidence';
import { reportingBackfillStatus } from '../lib/reporting_backfill';

async function safeCount(client: any, index: string): Promise<number | null> {
  try {
    const res: any = await client.count({ index, body: { query: { match_all: {} } } });
    return res.body.count ?? 0;
  } catch (e) {
    return null;
  }
}

async function safeQueryCount(client: any, index: string, query: any): Promise<number | null> {
  try {
    const res: any = await client.count({ index, body: { query } });
    return res.body.count ?? 0;
  } catch (e) {
    return null;
  }
}

async function safeGet(client: any, index: string, id: string): Promise<any | null> {
  try {
    const res: any = await client.get({ index, id });
    return res.body._source || null;
  } catch (e) {
    return null;
  }
}

async function safeAutomationHealth(client: any): Promise<any | null> {
  try {
    return await automationQueueHealth(client);
  } catch (e) {
    return null;
  }
}

async function archiveReferenceHealth(client: any, index: string): Promise<any | null> {
  try {
    let references = 0;
    let heldReferences = 0;
    const caseIds = new Set<string>();
    await scanArchiveEvidence(client, index, async (hits) => {
      references += hits.length;
      for (const hit of hits) {
        if (isEvidenceHeld(hit._source)) heldReferences += 1;
        if (hit._source?.case_id) caseIds.add(hit._source.case_id);
      }
    });
    let activeCaseReferences = 0;
    for (const caseId of caseIds) {
      const caseDoc = await safeGet(client, CASES_INDEX, caseId);
      if (!caseDoc || caseDoc.status !== 'closed') activeCaseReferences += 1;
    }
    return { references, heldReferences, activeCaseReferences };
  } catch (e) {
    return null;
  }
}

async function alertGenerations(client: any): Promise<any[]> {
  try {
    const [readResult, writeResult, settings]: any[] = await Promise.all([
      client.indices.getAlias({ name: ALERTS_READ_ALIAS }),
      client.indices.getAlias({ name: ALERTS_WRITE_ALIAS }),
      loadLifecycleSettings(client),
    ]);
    const read = readResult?.body || {};
    const write = writeResult?.body || {};
    return Promise.all(
      Object.keys(read)
        .sort()
        .map(async (index) => {
          const [total, active, indexSettings]: any[] = await Promise.all([
            safeCount(client, index),
            (async () => {
              try {
                const result: any = await client.count({
                  index,
                  body: { query: { terms: { status: ['open', 'in_progress'] } } },
                });
                return result.body.count ?? 0;
              } catch (e) {
                return null;
              }
            })(),
            client.indices.getSettings({ index }),
          ]);
          const createdAtMs = Number(indexSettings?.body?.[index]?.settings?.index?.creation_date || 0);
          const ageDays = createdAtMs ? (Date.now() - createdAtMs) / 86400000 : 0;
          const isWriteIndex = write[index]?.aliases?.[ALERTS_WRITE_ALIAS]?.is_write_index === true;
          return {
            index,
            total,
            active,
            isWriteIndex,
            createdAt: createdAtMs ? new Date(createdAtMs).toISOString() : null,
            ageDays: Math.floor(ageDays),
            retentionEligible:
              !isWriteIndex && Boolean(settings) && ageDays >= settings.operationalRetentionDays,
          };
        })
    );
  } catch (e) {
    return [];
  }
}

async function archivedAlertGenerations(client: any): Promise<any[]> {
  try {
    const [allResult, readResult, writeResult]: any[] = await Promise.all([
      client.indices.get({ index: 'wazuh-alert-status-v2-*' }),
      client.indices.getAlias({ name: ALERTS_READ_ALIAS }),
      client.indices.getAlias({ name: ALERTS_WRITE_ALIAS }),
    ]);
    const live = new Set([
      ...Object.keys(readResult?.body || {}),
      ...Object.keys(writeResult?.body || {}),
    ]);
    return Promise.all(
      Object.keys(allResult?.body || {})
        .filter((index) => !live.has(index))
        .sort()
        .map(async (index) => {
          const [total, record, referenceHealth, lifecycleSettings] = await Promise.all([
            safeCount(client, index),
            safeGet(client, META_INDEX, `retirement:${index}`),
            archiveReferenceHealth(client, index),
            loadLifecycleSettings(client),
          ]);
          const tracked = ['completed', 'restored'].includes(record?.status);
          const blockedReasons: string[] = [];
          let heldReferences: number | null = null;
          let activeCaseReferences: number | null = null;
          let evidenceRetentionEligible: boolean | null = null;
          if (referenceHealth == null) {
            blockedReasons.push('Evidence references unavailable');
          } else {
            heldReferences = referenceHealth.heldReferences;
            if (heldReferences) blockedReasons.push(`${heldReferences} evidence hold(s)`);
            activeCaseReferences = referenceHealth.activeCaseReferences;
            if (activeCaseReferences) blockedReasons.push(`${activeCaseReferences} active/unavailable case(s)`);
            if (referenceHealth.references) {
              const completedAt = Date.parse(record?.completed_at || '');
              evidenceRetentionEligible = Boolean(
                lifecycleSettings && Number.isFinite(completedAt) &&
                (Date.now() - completedAt) / 86400000 >= lifecycleSettings.evidenceRetentionDays
              );
              if (!evidenceRetentionEligible) blockedReasons.push('Full-evidence retention not met');
            } else {
              evidenceRetentionEligible = true;
            }
          }
          return {
            index,
            total,
            status: record?.status || 'untracked',
            restoreEligible: tracked,
            purgeEligible: tracked && blockedReasons.length === 0,
            evidenceReferences: referenceHealth?.references ?? null,
            heldReferences,
            activeCaseReferences,
            evidenceRetentionEligible,
            purgeBlockedReasons: blockedReasons,
            restoredDocuments: record?.restored_documents ?? null,
            restoredAt: record?.restored_at ?? null,
          };
        })
    );
  } catch (e) {
    return [];
  }
}

async function activityGenerations(client: any): Promise<{ live: any[]; archived: any[] }> {
  try {
    const [allResult, readResult, writeResult, settings]: any[] = await Promise.all([
      client.indices.get({ index: 'wazuh-alert-manager-v2-activity-*' }),
      client.indices.getAlias({ name: ACTIVITY_READ_ALIAS }),
      client.indices.getAlias({ name: ACTIVITY_WRITE_ALIAS }),
      loadLifecycleSettings(client),
    ]);
    const read = readResult?.body || {};
    const write = writeResult?.body || {};
    const all = allResult?.body || {};
    const live = await Promise.all(
      Object.keys(read).sort().map(async (index) => {
        const [total, indexSettings]: any[] = await Promise.all([
          safeCount(client, index),
          client.indices.getSettings({ index }),
        ]);
        const createdAtMs = Number(indexSettings?.body?.[index]?.settings?.index?.creation_date || 0);
        const ageDays = createdAtMs ? (Date.now() - createdAtMs) / 86400000 : 0;
        const isWriteIndex = write[index]?.aliases?.[ACTIVITY_WRITE_ALIAS]?.is_write_index === true;
        return {
          index,
          total,
          ageDays: Math.floor(ageDays),
          isWriteIndex,
          retentionEligible: !isWriteIndex && Boolean(settings) && ageDays >= settings.activityRetentionDays,
        };
      })
    );
    const attached = new Set([
      ...Object.keys(read),
      ...Object.keys(write),
    ]);
    const archived = await Promise.all(
      Object.keys(all).filter((index) => !attached.has(index)).sort().map(async (index) => {
        const [total, record] = await Promise.all([
          safeCount(client, index),
          safeGet(client, META_INDEX, `activity-retirement:${index}`),
        ]);
        return { index, total, status: record?.status || 'untracked', purgeEligible: record?.status === 'completed' };
      })
    );
    return { live, archived };
  } catch (e) {
    return { live: [], archived: [] };
  }
}

async function evidenceGenerations(client: any): Promise<{ live: any[]; archived: any[] }> {
  try {
    const [allResult, readResult, writeResult]: any[] = await Promise.all([
      client.indices.get({ index: 'wazuh-alert-manager-v2-evidence-*' }),
      client.indices.getAlias({ name: EVIDENCE_READ_ALIAS }),
      client.indices.getAlias({ name: EVIDENCE_WRITE_ALIAS }),
    ]);
    const all = allResult?.body || {};
    const read = readResult?.body || {};
    const write = writeResult?.body || {};
    const live = await Promise.all(Object.keys(read).sort().map(async (index) => ({
      index,
      total: await safeCount(client, index),
      isWriteIndex: write[index]?.aliases?.[EVIDENCE_WRITE_ALIAS]?.is_write_index === true,
    })));
    const attached = new Set([...Object.keys(read), ...Object.keys(write)]);
    const archived = await Promise.all(Object.keys(all).filter((index) => !attached.has(index)).sort().map(async (index) => {
      const [total, record] = await Promise.all([
        safeCount(client, index), safeGet(client, META_INDEX, `evidence-retirement:${index}`),
      ]);
      return { index, total, status: record?.status || 'untracked', purgeEligible: record?.status === 'completed' };
    }));
    return { live, archived };
  } catch (e) {
    return { live: [], archived: [] };
  }
}

async function caseGenerations(client: any): Promise<any[]> {
  try {
    const [readResult, writeResult, settings]: any[] = await Promise.all([
      client.indices.getAlias({ name: CASES_READ_ALIAS }),
      client.indices.getAlias({ name: CASES_WRITE_ALIAS }),
      loadLifecycleSettings(client),
    ]);
    const read = readResult?.body || {};
    const write = writeResult?.body || {};
    return Promise.all(Object.keys(read).sort().map(async (index) => {
      const [total, indexSettings]: any[] = await Promise.all([
        safeCount(client, index),
        client.indices.getSettings({ index }),
      ]);
      const createdAtMs = Number(indexSettings?.body?.[index]?.settings?.index?.creation_date || 0);
      const ageDays = createdAtMs ? (Date.now() - createdAtMs) / 86400000 : 0;
      const isWriteIndex = write[index]?.aliases?.[CASES_WRITE_ALIAS]?.is_write_index === true;
      return {
        index,
        total,
        ageDays: Math.floor(ageDays),
        isWriteIndex,
        retentionEligible: !isWriteIndex && Boolean(settings) && ageDays >= (settings.caseRetentionDays ?? 365),
      };
    }));
  } catch (e) {
    return [];
  }
}

export function defineSystemRoutes(router: IRouter) {
  router.get(
    { path: `${API_ROOT}/system/version`, validate: false },
    async (context, request, response) =>
      response.ok({
        headers: {
          'cache-control': 'no-store, no-cache, max-age=0, must-revalidate',
          pragma: 'no-cache',
          expires: '0',
        },
        body: {
          pluginVersion: PLUGIN_VERSION,
          buildId: PLUGIN_BUILD_ID,
          builtAt: PLUGIN_BUILT_AT,
          targetOsdVersion: TARGET_OSD_VERSION,
        },
      })
  );

  router.get(
    { path: `${API_ROOT}/system/sync/settings`, validate: false },
    async (context, request, response) => {
      try {
        const settings = await loadSyncSettings(context.core.opensearch.client.asCurrentUser);
        return response.ok({ body: settings });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );

  router.put(
    {
      path: `${API_ROOT}/system/sync/settings`,
      validate: { body: schema.object({ enabled: schema.boolean(), intervalSeconds: schema.number({ min: 15, max: 3600 }) }) },
    },
    async (context, request, response) => {
      try {
        const identity = await requireLifecycleManager(context, request);
        const settings = await saveSyncSettings(
          context.core.opensearch.client.asCurrentUser,
          request.body as any,
          identity.name
        );
        return response.ok({ body: settings });
      } catch (e: any) {
        return response.customError({ statusCode: e?.statusCode || e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );

  router.get(
    { path: `${API_ROOT}/system/capabilities`, validate: false },
    async (context, request, response) => {
      const identity = await trustedIdentity(context, request);
      return response.ok({
        body: {
          canManageLifecycle: canManageLifecycle(identity),
          isPluginAdmin: isPluginAdmin(identity),
          authorizationSource: identity.source,
        },
      });
    }
  );

  router.get(
    { path: `${API_ROOT}/system/lifecycle/settings`, validate: false },
    async (context, request, response) => {
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const settings = await loadLifecycleSettings(client);
        if (!settings) return response.notFound({ body: { message: 'Lifecycle settings are not provisioned yet.' } });
        return response.ok({ body: settings });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );

  router.put(
    {
      path: `${API_ROOT}/system/lifecycle/settings`,
      validate: {
        body: schema.object({
          enabled: schema.boolean(),
          rolloverAge: schema.string(),
          rolloverSize: schema.string(),
          operationalRetentionDays: schema.number({ min: 7, max: 3650 }),
          activityRetentionDays: schema.number({ min: 30, max: 3650 }),
          caseRetentionDays: schema.number({ min: 30, max: 3650 }),
          evidenceRetentionDays: schema.number({ min: 30, max: 3650 }),
        }),
      },
    },
    async (context, request, response) => {
      try {
        const identity = await requireLifecycleManager(context, request);
        const body: any = request.body;
        if (!/^[1-9]\d*(s|m|h|d)$/i.test(body.rolloverAge)) {
          return response.badRequest({ body: { message: 'Rollover age must look like 12h, 7d, or 30d.' } });
        }
        if (!/^[1-9]\d*(kb|mb|gb|tb)$/i.test(body.rolloverSize)) {
          return response.badRequest({ body: { message: 'Rollover size must look like 500mb, 20gb, or 1tb.' } });
        }
        const settings = {
          enabled: body.enabled,
          rolloverAge: body.rolloverAge.toLowerCase(),
          rolloverSize: body.rolloverSize.toLowerCase(),
          operationalRetentionDays: Math.round(body.operationalRetentionDays),
          activityRetentionDays: Math.round(body.activityRetentionDays),
          caseRetentionDays: Math.round(body.caseRetentionDays),
          evidenceRetentionDays: Math.round(body.evidenceRetentionDays),
        };
        const client = context.core.opensearch.client.asCurrentUser;
        await client.index({
          index: assertManagedWriteTarget(META_INDEX),
          id: LIFECYCLE_SETTINGS_ID,
          body: { ...settings, updated_at: new Date().toISOString(), updated_by: identity.name, source: 'workbench' },
          refresh: 'wait_for',
        });
        return response.ok({ body: settings });
      } catch (e: any) {
        const statusCode = e?.statusCode || e?.meta?.statusCode || 500;
        return response.customError({ statusCode, body: { message: e.message } });
      }
    }
  );

  router.get({ path: `${API_ROOT}/system/health`, validate: false }, async (context, request, response) => {
    const client = context.core.opensearch.client.asCurrentUser;
    try {
      const [
        alerts, activity, cases, evidence, heldEvidence, archivedEvidence, purgedEvidence,
        legacyAlerts, dlq, migration, sync, generations, archived, activityStorage, evidenceStorage, caseGenerationsList, archivedCases, automation,
      ] = await Promise.all([
        safeCount(client, ALERTS_READ_ALIAS),
        safeCount(client, ACTIVITY_READ_ALIAS),
        safeCount(client, CASES_INDEX),
        safeCount(client, EVIDENCE_READ_ALIAS),
        safeQueryCount(client, EVIDENCE_READ_ALIAS, { exists: { field: 'hold_since' } }),
        safeQueryCount(client, EVIDENCE_READ_ALIAS, { term: { relationship_state: 'archived' } }),
        safeQueryCount(client, EVIDENCE_READ_ALIAS, { term: { relationship_state: 'purged' } }),
        safeCount(client, LEGACY_ALERT_STATUS_INDEX),
        safeCount(client, SYNC_DLQ_INDEX),
        safeGet(client, MIGRATION_INDEX, 'legacy-v1-to-v2'),
        safeGet(client, META_INDEX, 'sync_state'),
        alertGenerations(client),
        archivedAlertGenerations(client),
        activityGenerations(client),
        evidenceGenerations(client),
        caseGenerations(client),
        listArchivedCaseGenerations(client),
        safeAutomationHealth(client),
      ]);
      let lifecycle: any = null;
      try {
        lifecycle = await lifecycleStatus(client);
      } catch (e) {
        // ISM may be unavailable to a read-only analyst. Counts remain useful.
      }
      return response.ok({
        body: {
          namespace: 'wazuh-alert-status-v2-* / wazuh-alert-manager-v2-*',
          sourcePattern: 'wazuh-alerts-* (read only)',
          counts: { alerts, activity, cases, evidence, heldEvidence, archivedEvidence, purgedEvidence, legacyAlerts, dlq },
          migration,
          sync,
          automation,
          lifecycle,
          generations: {
            alerts: generations,
            archivedAlerts: archived,
            activity: activityStorage.live,
            archivedActivity: activityStorage.archived,
            evidence: evidenceStorage.live,
            archivedEvidenceRelationships: evidenceStorage.archived,
            cases: caseGenerationsList,
            archivedCases,
          },
        },
      });
    } catch (e: any) {
      return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
    }
  });

  router.get(
    {
      path: `${API_ROOT}/system/reporting-backfill`,
      validate: false,
    },
    async (context, request, response) => {
      try {
        return response.ok({
          body: await reportingBackfillStatus(context.core.opensearch.client.asCurrentUser),
        });
      } catch (e: any) {
        return response.customError({
          statusCode: e?.statusCode || e?.meta?.statusCode || 500,
          body: { message: e.message },
        });
      }
    }
  );

  router.post(
    {
      path: `${API_ROOT}/system/automation/dlq/retry`,
      validate: { body: schema.object({ eventId: schema.string({ minLength: 1, maxLength: 512 }) }) },
    },
    async (context, request, response) => {
      try {
        await requirePluginAdmin(context, request);
        const result = await retryAutomationDlqEvent(
          context.core.opensearch.client.asCurrentUser,
          (request.body as any).eventId
        );
        return response.ok({ body: result });
      } catch (e: any) {
        return response.customError({
          statusCode: e?.statusCode || e?.meta?.statusCode || 500,
          body: { message: e.message },
        });
      }
    }
  );

  router.get(
    {
      path: `${API_ROOT}/system/automation/dlq`,
      validate: {
        query: schema.object({
          limit: schema.maybe(schema.number({ min: 1, max: 200 })),
          cursor: schema.maybe(schema.string({ maxLength: 4096 })),
        }),
      },
    },
    async (context, request, response) => {
      try {
        const query: any = request.query;
        return response.ok({
          body: await listAutomationDlq(
            context.core.opensearch.client.asCurrentUser,
            query.limit || 50,
            query.cursor
          ),
        });
      } catch (e: any) {
        return response.customError({
          statusCode: e?.statusCode || e?.meta?.statusCode || 500,
          body: { message: e.message },
        });
      }
    }
  );

  router.post(
    {
      path: `${API_ROOT}/system/automation/dlq/resolve`,
      validate: { body: schema.object({ id: schema.string({ minLength: 1, maxLength: 1024 }) }) },
    },
    async (context, request, response) => {
      try {
        await requirePluginAdmin(context, request);
        return response.ok({
          body: await resolveAutomationDlqEvent(
            context.core.opensearch.client.asCurrentUser,
            (request.body as any).id
          ),
        });
      } catch (e: any) {
        return response.customError({
          statusCode: e?.statusCode || e?.meta?.statusCode || 500,
          body: { message: e.message },
        });
      }
    }
  );

  router.get(
    { path: `${API_ROOT}/system/automation/queue`, validate: false },
    async (context, request, response) => {
      try {
        return response.ok({ body: await automationQueueHealth(context.core.opensearch.client.asCurrentUser) });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );

  router.get(
    { path: `${API_ROOT}/system/automation/queue/settings`, validate: false },
    async (context, request, response) => {
      try {
        return response.ok({ body: await loadAutomationSettings(context.core.opensearch.client.asCurrentUser) });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );

  router.put(
    {
      path: `${API_ROOT}/system/automation/queue/settings`,
      validate: { body: schema.object({
        paused: schema.boolean(),
        maxBacklog: schema.number({ min: 1, max: 1000000 }),
        maxDeferred: schema.number({ min: 1, max: 5000000 }),
      }) },
    },
    async (context, request, response) => {
      try {
        const identity = await requirePluginAdmin(context, request);
        return response.ok({
          body: await saveAutomationSettings(
            context.core.opensearch.client.asCurrentUser,
            request.body as any,
            identity.name
          ),
        });
      } catch (e: any) {
        return response.customError({
          statusCode: e?.statusCode || e?.meta?.statusCode || 500,
          body: { message: e.message },
        });
      }
    }
  );

  router.post(
    {
      path: `${API_ROOT}/system/rollover`,
      validate: {
        body: schema.object({ family: schema.oneOf([
          schema.literal('alerts'), schema.literal('activity'), schema.literal('cases'), schema.literal('evidence'),
        ]) }),
      },
    },
    async (context, request, response) => {
      try {
        await requireLifecycleManager(context, request);
      } catch (e: any) {
        return response.forbidden({ body: { message: e.message } });
      }
      const client = context.core.opensearch.client.asCurrentUser;
      const family = (request.body as any).family;
      const alias = family === 'alerts' ? ALERTS_WRITE_ALIAS
        : family === 'activity' ? ACTIVITY_WRITE_ALIAS
        : family === 'cases' ? CASES_WRITE_ALIAS : EVIDENCE_WRITE_ALIAS;
      const readAlias = family === 'alerts' ? ALERTS_READ_ALIAS
        : family === 'activity' ? ACTIVITY_READ_ALIAS
        : family === 'cases' ? CASES_READ_ALIAS : EVIDENCE_READ_ALIAS;
      const mappings = family === 'alerts' ? alertStatusMapping
        : family === 'activity' ? activityMapping
        : family === 'cases' ? casesMapping : evidenceMapping;
      try {
        const result: any = await client.indices.rollover({
          alias,
          body: { mappings, aliases: { [readAlias]: {} } },
        });
        return response.ok({ body: result.body });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );


  router.post(
    {
      path: `${API_ROOT}/system/retirement/plan`,
      validate: { body: schema.object({ retiringIndex: schema.string() }) },
    },
    async (context, request, response) => {
      try {
        await requireLifecycleManager(context, request);
        const client = context.core.opensearch.client.asCurrentUser;
        return response.ok({ body: await planAlertRetirement(client, (request.body as any).retiringIndex) });
      } catch (e: any) {
        const statusCode = e?.statusCode || e?.meta?.statusCode || 400;
        return response.customError({ statusCode, body: { message: e.message } });
      }
    }
  );

  router.post(
    {
      path: `${API_ROOT}/system/retirement/execute`,
      validate: {
        body: schema.object({ retiringIndex: schema.string(), confirmation: schema.string() }),
      },
    },
    async (context, request, response) => {
      try {
        const identity = await requireLifecycleManager(context, request);
        const body: any = request.body;
        if (body.confirmation !== body.retiringIndex) {
          return response.badRequest({ body: { message: 'Confirmation must exactly match the retiring index.' } });
        }
        const client = context.core.opensearch.client.asCurrentUser;
        const logger: any = (context as any).wazuhAlertManager?.logger || console;
        return response.ok({
          body: await executeAlertRetirement(client, body.retiringIndex, identity.name, logger),
        });
      } catch (e: any) {
        const statusCode = e?.statusCode || e?.meta?.statusCode || 400;
        return response.customError({ statusCode, body: { message: e.message } });
      }
    }
  );

  router.post(
    {
      path: `${API_ROOT}/system/retirement/restore`,
      validate: { body: schema.object({ index: schema.string(), confirmation: schema.string() }) },
    },
    async (context, request, response) => {
      try {
        const identity = await requireLifecycleManager(context, request);
        const body: any = request.body;
        if (body.confirmation !== `RESTORE ${body.index}`) {
          return response.badRequest({ body: { message: `Confirmation must exactly match RESTORE ${body.index}` } });
        }
        const client = context.core.opensearch.client.asCurrentUser;
        return response.ok({ body: await restoreRetiredAlertIndex(client, body.index, identity.name) });
      } catch (e: any) {
        const statusCode = e?.statusCode || e?.meta?.statusCode || 400;
        return response.customError({ statusCode, body: { message: e.message } });
      }
    }
  );

  router.post(
    {
      path: `${API_ROOT}/system/retirement/purge`,
      validate: { body: schema.object({ index: schema.string(), confirmation: schema.string() }) },
    },
    async (context, request, response) => {
      try {
        const identity = await requireLifecycleManager(context, request);
        const body: any = request.body;
        if (body.confirmation !== `PURGE ${body.index}`) {
          return response.badRequest({ body: { message: `Confirmation must exactly match PURGE ${body.index}` } });
        }
        const client = context.core.opensearch.client.asCurrentUser;
        return response.ok({ body: await purgeRetiredAlertIndex(client, body.index, identity.name) });
      } catch (e: any) {
        const statusCode = e?.statusCode || e?.meta?.statusCode || 400;
        return response.customError({ statusCode, body: { message: e.message } });
      }
    }
  );

  router.post(
    {
      path: `${API_ROOT}/system/activity-retirement/execute`,
      validate: { body: schema.object({ index: schema.string(), confirmation: schema.string() }) },
    },
    async (context, request, response) => {
      try {
        const identity = await requireLifecycleManager(context, request);
        const body: any = request.body;
        if (body.confirmation !== body.index) {
          return response.badRequest({ body: { message: 'Confirmation must exactly match the activity index.' } });
        }
        const client = context.core.opensearch.client.asCurrentUser;
        const settings = await loadLifecycleSettings(client);
        return response.ok({
          body: await retireActivityIndex(client, body.index, identity.name, settings.activityRetentionDays),
        });
      } catch (e: any) {
        return response.customError({ statusCode: e?.statusCode || e?.meta?.statusCode || 400, body: { message: e.message } });
      }
    }
  );

  router.post(
    {
      path: `${API_ROOT}/system/activity-retirement/purge`,
      validate: { body: schema.object({ index: schema.string(), confirmation: schema.string() }) },
    },
    async (context, request, response) => {
      try {
        const identity = await requireLifecycleManager(context, request);
        const body: any = request.body;
        if (body.confirmation !== `PURGE ${body.index}`) {
          return response.badRequest({ body: { message: `Confirmation must exactly match PURGE ${body.index}` } });
        }
        const client = context.core.opensearch.client.asCurrentUser;
        return response.ok({ body: await purgeRetiredActivityIndex(client, body.index, identity.name) });
      } catch (e: any) {
        return response.customError({ statusCode: e?.statusCode || e?.meta?.statusCode || 400, body: { message: e.message } });
      }
    }
  );

  router.post(
    {
      path: `${API_ROOT}/system/evidence-retirement/execute`,
      validate: { body: schema.object({ index: schema.string(), confirmation: schema.string() }) },
    },
    async (context, request, response) => {
      try {
        const identity = await requireLifecycleManager(context, request);
        const body: any = request.body;
        if (body.confirmation !== body.index) {
          return response.badRequest({ body: { message: 'Confirmation must exactly match the evidence index.' } });
        }
        return response.ok({ body: await retireEvidenceIndex(
          context.core.opensearch.client.asCurrentUser, body.index, identity.name
        ) });
      } catch (e: any) {
        return response.customError({ statusCode: e?.statusCode || e?.meta?.statusCode || 400, body: { message: e.message } });
      }
    }
  );

  router.post(
    {
      path: `${API_ROOT}/system/evidence-retirement/purge`,
      validate: { body: schema.object({ index: schema.string(), confirmation: schema.string() }) },
    },
    async (context, request, response) => {
      try {
        const identity = await requireLifecycleManager(context, request);
        const body: any = request.body;
        if (body.confirmation !== `PURGE ${body.index}`) {
          return response.badRequest({ body: { message: `Confirmation must exactly match PURGE ${body.index}` } });
        }
        return response.ok({ body: await purgeRetiredEvidenceIndex(
          context.core.opensearch.client.asCurrentUser, body.index, identity.name
        ) });
      } catch (e: any) {
        return response.customError({ statusCode: e?.statusCode || e?.meta?.statusCode || 400, body: { message: e.message } });
      }
    }
  );

  router.post(
    {
      path: `${API_ROOT}/system/cases/retirement/plan`,
      validate: { body: schema.object({ retiringIndex: schema.string() }) },
    },
    async (context, request, response) => {
      try {
        await requireLifecycleManager(context, request);
        const client = context.core.opensearch.client.asCurrentUser;
        const settings = await loadLifecycleSettings(client);
        return response.ok({
          body: await planCaseRetirement(client, (request.body as any).retiringIndex, settings.caseRetentionDays),
        });
      } catch (e: any) {
        const statusCode = e?.statusCode || e?.meta?.statusCode || 400;
        return response.customError({ statusCode, body: { message: e.message } });
      }
    }
  );

  router.post(
    {
      path: `${API_ROOT}/system/cases/retirement/execute`,
      validate: { body: schema.object({ retiringIndex: schema.string(), confirmation: schema.string() }) },
    },
    async (context, request, response) => {
      try {
        const identity = await requireLifecycleManager(context, request);
        const body: any = request.body;
        if (body.confirmation !== body.retiringIndex) {
          return response.badRequest({ body: { message: 'Confirmation must exactly match the retiring index.' } });
        }
        const client = context.core.opensearch.client.asCurrentUser;
        const settings = await loadLifecycleSettings(client);
        return response.ok({
          body: await executeCaseRetirement(
            client, body.retiringIndex, identity.name, settings.caseRetentionDays
          ),
        });
      } catch (e: any) {
        const statusCode = e?.statusCode || e?.meta?.statusCode || 400;
        return response.customError({ statusCode, body: { message: e.message } });
      }
    }
  );

  router.get(
    {
      path: `${API_ROOT}/system/cases/archived`,
      validate: false,
    },
    async (context, request, response) => {
      try {
        await requireLifecycleManager(context, request);
        const client = context.core.opensearch.client.asCurrentUser;
        return response.ok({ body: await listArchivedCaseGenerations(client) });
      } catch (e: any) {
        const statusCode = e?.statusCode || e?.meta?.statusCode || 400;
        return response.customError({ statusCode, body: { message: e.message } });
      }
    }
  );

  router.post(
    {
      path: `${API_ROOT}/system/cases/archived/{caseId}/reopen`,
      validate: { params: schema.object({ caseId: schema.string() }) },
    },
    async (context, request, response) => {
      try {
        const identity = await requireLifecycleManager(context, request);
        const client = context.core.opensearch.client.asCurrentUser;
        return response.ok({
          body: await reopenArchivedCase(client, (request.params as any).caseId, identity.name),
        });
      } catch (e: any) {
        const statusCode = e?.statusCode || e?.meta?.statusCode || 404;
        return response.customError({ statusCode, body: { message: e.message } });
      }
    }
  );

  router.post(
    {
      path: `${API_ROOT}/system/cases/archived/purge`,
      validate: { body: schema.object({ index: schema.string(), confirmation: schema.string() }) },
    },
    async (context, request, response) => {
      try {
        const identity = await requireLifecycleManager(context, request);
        const body: any = request.body;
        if (body.confirmation !== `PURGE ${body.index}`) {
          return response.badRequest({ body: { message: `Confirmation must exactly match PURGE ${body.index}` } });
        }
        const client = context.core.opensearch.client.asCurrentUser;
        await purgeArchivedCaseGeneration(client, body.index, identity.name);
        return response.ok({ body: { purged: body.index } });
      } catch (e: any) {
        const statusCode = e?.statusCode || e?.meta?.statusCode || 400;
        return response.customError({ statusCode, body: { message: e.message } });
      }
    }
  );
}
