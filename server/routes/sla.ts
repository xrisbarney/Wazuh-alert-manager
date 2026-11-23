import { schema } from '@osd/config-schema';
import { IRouter } from '../../../../src/core/server';
import {
  API_ROOT,
  SLA_ESCALATION_CONDITIONS,
  SLA_ESCALATION_MAX_NOTIFY,
  SLA_ESCALATION_TARGETS,
  SLA_MAX_ESCALATIONS,
  SLA_MINUTES_MAX,
  SLA_MINUTES_MIN,
  SLA_POLICY_DOC_ID,
  SLA_POLICY_UPDATED_ACTION,
} from '../../common';
import type { SlaDueBackfillStatus, SlaEscalationStatusPublic, SlaEscalationStatusResponse, SlaPolicyResponse } from '../../common';
import { isPluginAdmin, requirePluginAdmin } from '../lib/authorization';
import { trustedIdentity } from '../lib/identity';
import { appendActivity } from '../lib/activity';
import { DEFAULT_SLA_POLICY, LoadedSlaPolicy, loadSlaPolicy, saveSlaPolicy } from '../lib/sla/policy';
import { beginSlaDueBackfill, readSlaDueBackfillStatus, scheduleSlaDueBackfill } from '../lib/sla/due_backfill';
import { getSlaEscalationRuntime, readSlaEscalationStatus } from '../lib/sla/escalation';

/**
 * SLA policy routes (step 3.1).
 *
 *   GET /sla/policy   any signed-in user (the queue and the Reports page show the targets)
 *   PUT /sla/policy   administrator only: full replace of `targets` + `escalations`,
 *                     audit event `sla_policy_updated` on `system/sla_policy`,
 *                     local policy cache invalidated (other replicas: within 60 s)
 *
 * PUT validates shape here and semantics inside the settings doc write
 * (`normaliseSlaPolicy`, which answers 400). After the write, when the
 * `targets` differ from the stored ones (or the stored document was
 * unreadable), it schedules the due-date backfill of step 3.2
 * (fire-and-forget; the response never waits). An escalation-only edit or a
 * no-op save schedules nothing.
 *
 *   GET  /sla/backfill  any signed-in user: last / current backfill run (`{ status: null }` when it never ran);
 *                       `error` is a sanitised string (no index names), the full message is in the server log
 *   POST /sla/backfill  administrator only: start the backfill now under the stored policy; 202 with the
 *                       `running` status (progress through GET), or 200 `skipped` when a run holds the lease
 *
 *   GET /sla/escalation/status  any signed-in user: the escalation scanner's last tick (meta doc
 *                               `sla_escalation_status`, `status: null` before the first tick) plus this
 *                               replica's `enabled` / `tickSeconds` (step 3.3). The stored `errors` are
 *                               already sanitised by the scanner (type + HTTP status, no index names; the
 *                               full text is in the server log); the lease `holder` (hostname + pid) is
 *                               answered only to plugin administrators.
 */

const minutesSchema = schema.number({ min: SLA_MINUTES_MIN, max: SLA_MINUTES_MAX });

const targetSchema = schema.object(
  { resolveMinutes: minutesSchema, assignMinutes: minutesSchema },
  { unknowns: 'forbid' }
);

const escalationSchema = schema.object(
  {
    id: schema.string({ minLength: 1, maxLength: 64 }),
    name: schema.string({ minLength: 1, maxLength: 120 }),
    target: schema.oneOf(SLA_ESCALATION_TARGETS.map((value) => schema.literal(value)) as any),
    thresholdPercent: schema.number({ min: 1, max: 100 }),
    condition: schema.oneOf(SLA_ESCALATION_CONDITIONS.map((value) => schema.literal(value)) as any),
    actions: schema.object(
      {
        assignTo: schema.maybe(schema.string({ maxLength: 256 })),
        raiseSeverity: schema.maybe(schema.boolean()),
        comment: schema.maybe(schema.string({ maxLength: 2000 })),
        notify: schema.maybe(schema.arrayOf(schema.string({ maxLength: 128 }), { maxSize: SLA_ESCALATION_MAX_NOTIFY })),
      },
      { unknowns: 'forbid' }
    ),
    enabled: schema.boolean({ defaultValue: true }),
  },
  { unknowns: 'forbid' }
);

export const slaPolicyBodySchema = schema.object(
  {
    targets: schema.object(
      { critical: targetSchema, high: targetSchema, medium: targetSchema, low: targetSchema },
      { unknowns: 'forbid' }
    ),
    escalations: schema.arrayOf(escalationSchema, { maxSize: SLA_MAX_ESCALATIONS, defaultValue: [] }),
  },
  { unknowns: 'forbid' }
);

function failure(response: any, e: any) {
  const statusCode = e?.statusCode || e?.meta?.statusCode || 500;
  if (statusCode === 400) return response.badRequest({ body: { message: e.message } });
  if (statusCode === 403) return response.forbidden({ body: { message: e.message } });
  if (statusCode === 404) return response.notFound({ body: { message: e.message } });
  return response.customError({ statusCode, body: { message: e.message } });
}

export function policyBody(loaded: LoadedSlaPolicy, storedInvalid = false): SlaPolicyResponse {
  const body: SlaPolicyResponse = {
    policy: { targets: loaded.targets, escalations: loaded.escalations },
    updated_at: loaded.updated_at,
    updated_by: loaded.updated_by,
    defaults: DEFAULT_SLA_POLICY,
  };
  if (storedInvalid) body.storedInvalid = true;
  return body;
}

/**
 * The stored policy, or `null` when the document exists but no longer
 * validates (hand-edited, or written by a newer schema). A storage failure
 * (anything but the 400 of `normaliseSlaPolicy`) is rethrown.
 */
async function loadStoredOrNull(client: any, logger?: { warn?(message: string): void }): Promise<LoadedSlaPolicy | null> {
  try {
    return await loadSlaPolicy(client);
  } catch (e: any) {
    if ((e?.statusCode || e?.meta?.statusCode) !== 400) throw e;
    logger?.warn?.(`wazuh-alert-manager sla: stored ${SLA_POLICY_DOC_ID} is invalid, answering the defaults: ${e.message}`);
    return null;
  }
}

/** True when both target tables agree band by band (the backfill is only worth running when they differ). */
export function sameTargets(a: LoadedSlaPolicy['targets'] | null | undefined, b: LoadedSlaPolicy['targets'] | null | undefined): boolean {
  if (!a || !b) return false;
  return (['critical', 'high', 'medium', 'low'] as const).every(
    (band) => a[band]?.resolveMinutes === b[band]?.resolveMinutes && a[band]?.assignMinutes === b[band]?.assignMinutes
  );
}

/** Short audit summary of the resolve targets, e.g. `critical=60,high=240,medium=1440,low=4320;escalations=2`. */
export function policyAuditSummary(policy: LoadedSlaPolicy): string {
  const targets = (['critical', 'high', 'medium', 'low'] as const)
    .map((band) => `${band}=${policy.targets[band].resolveMinutes}/${policy.targets[band].assignMinutes}`)
    .join(',');
  return `${targets};escalations=${policy.escalations.length}`;
}

export function defineSlaRoutes(router: IRouter) {
  router.get({ path: `${API_ROOT}/sla/policy`, validate: false }, async (context, request, response) => {
    try {
      const client = context.core.opensearch.client.asCurrentUser;
      const stored = await loadStoredOrNull(client, (context as any).wazuhAlertManager?.logger || console);
      // An unreadable stored document answers the defaults flagged `storedInvalid`
      // so an administrator can repair it from the Settings tab instead of a 400.
      return response.ok({ body: stored ? policyBody(stored) : policyBody({ ...DEFAULT_SLA_POLICY }, true) });
    } catch (e: any) {
      return failure(response, e);
    }
  });

  router.put(
    { path: `${API_ROOT}/sla/policy`, validate: { body: slaPolicyBodySchema } },
    async (context, request, response) => {
      try {
        const identity = await requirePluginAdmin(context, request);
        const client = context.core.opensearch.client.asCurrentUser;
        const logger = (context as any).wazuhAlertManager?.logger || console;
        const before = await loadStoredOrNull(client, logger);
        const { targets, escalations } = request.body as any;
        const saved = await saveSlaPolicy(client, { targets, escalations }, { updatedBy: identity.name });
        await appendActivity(client, {
          targetType: 'system',
          targetId: SLA_POLICY_DOC_ID,
          user: identity.name,
          action: SLA_POLICY_UPDATED_ACTION,
          from: before ? policyAuditSummary(before) : 'unreadable',
          to: policyAuditSummary(saved),
        });
        if (!before || !sameTargets(before.targets, saved.targets)) {
          scheduleSlaDueBackfill(client, logger, saved, { policyVersion: saved.updated_at ?? null });
        }
        return response.ok({ body: policyBody(saved) });
      } catch (e: any) {
        return failure(response, e);
      }
    }
  );

  router.get({ path: `${API_ROOT}/sla/backfill`, validate: false }, async (context, request, response) => {
    try {
      const client = context.core.opensearch.client.asCurrentUser;
      const status: SlaDueBackfillStatus | null = await readSlaDueBackfillStatus(client);
      return response.ok({ body: { status } });
    } catch (e: any) {
      return failure(response, e);
    }
  });

  router.get({ path: `${API_ROOT}/sla/escalation/status`, validate: false }, async (context, request, response) => {
    try {
      const client = context.core.opensearch.client.asCurrentUser;
      const runtime = getSlaEscalationRuntime();
      const stored = await readSlaEscalationStatus(client);
      let status: SlaEscalationStatusPublic | null = stored;
      if (stored && !isPluginAdmin(await trustedIdentity(context, request))) {
        const { holder, ...rest } = stored;
        status = rest;
      }
      const body: SlaEscalationStatusResponse = {
        enabled: runtime.enabled,
        tickSeconds: runtime.tickSeconds,
        status,
      };
      return response.ok({ body });
    } catch (e: any) {
      return failure(response, e);
    }
  });

  router.post({ path: `${API_ROOT}/sla/backfill`, validate: false }, async (context, request, response) => {
    try {
      await requirePluginAdmin(context, request);
      const client = context.core.opensearch.client.asCurrentUser;
      const logger = (context as any).wazuhAlertManager?.logger || console;
      const stored = await loadStoredOrNull(client, logger);
      const policy = stored || { ...DEFAULT_SLA_POLICY };
      const started = await beginSlaDueBackfill(client, logger, policy, { policyVersion: stored?.updated_at ?? null });
      started.completion.catch((e: any) => logger?.error?.(`wazuh-alert-manager sla: run-now due-date backfill crashed: ${e?.message || e}`));
      if (started.status.status === 'skipped') return response.ok({ body: { status: started.status } });
      return response.accepted({ body: { status: started.status } });
    } catch (e: any) {
      return failure(response, e);
    }
  });
}
