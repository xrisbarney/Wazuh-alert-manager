import { schema } from '@osd/config-schema';
import { IRouter } from '../../../../src/core/server';
import {
  API_ROOT,
  ENRICHMENT_LOOKUP_TYPES,
  ENRICHMENT_MAX_SOURCES,
  ENRICHMENT_SETTINGS_DOC_ID,
  ENRICHMENT_SOURCE_KINDS,
  ENRICHMENT_VERDICTS,
} from '../../common';
import type { AlertEnrichment, AlertEnrichmentLookupResponse, EnrichmentLookupType, EnrichmentSettingsResponse } from '../../common';
import { extractIndicators, mergeAlertEnrichment } from '../../common';
import { requirePluginAdmin } from '../lib/authorization';
import { appendActivity } from '../lib/activity';
import { readEgressAllowedHosts } from '../lib/egress/url_policy';
import { assertManagedWriteTarget } from '../lib/index_namespace';
import { resolveAlerts } from '../lib/index_resolution';
import { getCurrentUsername } from '../lib/opensearch';
import { getEncryptionKey } from '../lib/secrets_config';
import { canonicalLookupValue, enrichmentSettings, runEnrichmentLookup, testEnrichmentSource, withBuiltInSources } from '../lib/enrichment';
import { buildSiblingVerdicts } from './indicators';

const lookupTypeSchema = schema.oneOf(ENRICHMENT_LOOKUP_TYPES.map((type) => schema.literal(type)) as any);

/**
 * PUT body: the whole source list. Shape only; `normaliseEnrichmentSettings`
 * (run inside the settings doc write) does the semantic checks (kind
 * capabilities, egress policy on URLs, bounds) and answers 400.
 */
const sourceSchema = schema.object(
  {
    id: schema.string({ minLength: 1, maxLength: 64 }),
    name: schema.string({ minLength: 1, maxLength: 120 }),
    kind: schema.oneOf(ENRICHMENT_SOURCE_KINDS.map((kind) => schema.literal(kind)) as any),
    enabled: schema.boolean({ defaultValue: false }),
    supports: schema.maybe(schema.arrayOf(lookupTypeSchema, { maxSize: ENRICHMENT_LOOKUP_TYPES.length })),
    cacheTtlSeconds: schema.maybe(schema.number()),
    timeoutMs: schema.maybe(schema.number()),
    baseUrl: schema.maybe(schema.string({ maxLength: 2048 })),
    urlTemplate: schema.maybe(schema.string({ maxLength: 2048 })),
    headers: schema.maybe(schema.recordOf(schema.string({ maxLength: 128 }), schema.string({ maxLength: 2048 }))),
    verdictPath: schema.maybe(schema.string({ maxLength: 512 })),
    scorePath: schema.maybe(schema.string({ maxLength: 512 })),
    tagsPath: schema.maybe(schema.string({ maxLength: 512 })),
    linkPath: schema.maybe(schema.string({ maxLength: 512 })),
    allowInsecure: schema.maybe(schema.boolean()),
    verdictMap: schema.maybe(
      schema.recordOf(schema.string({ maxLength: 256 }), schema.oneOf(ENRICHMENT_VERDICTS.map((v) => schema.literal(v)) as any))
    ),
    /** New plaintext key; '' or absent keeps the stored one, null clears it. */
    apiKey: schema.maybe(schema.nullable(schema.string({ maxLength: 4096 }))),
    /** Echoed read-only flags are accepted and ignored. */
    apiKeyConfigured: schema.maybe(schema.boolean()),
    builtIn: schema.maybe(schema.boolean()),
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

function settingsBody(masked: any): EnrichmentSettingsResponse {
  return {
    sources: withBuiltInSources(masked.sources || []) as any,
    encryptionConfigured: Boolean(getEncryptionKey()),
    egressAllowedHosts: readEgressAllowedHosts(),
    updated_at: masked.updated_at,
    updated_by: masked.updated_by,
  };
}

/**
 * Run a lookup for one indicator of an alert and store the bounded result on
 * the alert record (`enrichment`, plugin-owned). The value must be an
 * indicator the record (or its 4.x VirusTotal / Maltiverse siblings) carries,
 * so the stored object only ever describes the alert it hangs off. Writes go
 * through the resolved physical index behind the write alias, guarded by
 * `assertManagedWriteTarget`, as a partial update so concurrent status /
 * comment / sync writes are never clobbered, and under `if_seq_no` /
 * `if_primary_term` so concurrent lookups never drop each other's items.
 * When no enabled source supports the type nothing is written or audited.
 */
export async function lookupAndStoreAlertEnrichment(
  client: any,
  input: { alertId: string; type: EnrichmentLookupType; value: string; sourceIds?: string[]; refresh?: boolean; user: string },
  options: { now?: Date; logger?: { warn(message: string): void } } = {}
): Promise<AlertEnrichmentLookupResponse> {
  const { alertId, type, value, sourceIds, refresh, user } = input;
  const locations = await resolveAlerts(client, [alertId], true, true);
  const found = locations.get(alertId);
  if (!found) throw Object.assign(new Error('Alert not found'), { statusCode: 404 });

  const canonical = canonicalLookupValue(type, value);
  let siblingMatches: any[] = [];
  if (found.source?.threat?.integration == null) {
    try {
      siblingMatches = (await buildSiblingVerdicts(client, alertId)).matches;
    } catch (e) {
      // Sibling verdicts only widen the accepted set; the record's own indicators still count.
    }
  }
  const known = extractIndicators(found.source, { siblingMatches }).some((item) => item.type === type && item.value === canonical);
  if (!known) {
    throw Object.assign(new Error(`"${canonical.slice(0, 128)}" is not a ${type} indicator of alert ${alertId}.`), { statusCode: 400 });
  }

  const now = options.now || new Date();
  const lookup = await runEnrichmentLookup(client, { type, value: canonical, sourceIds, refresh }, { now, logger: options.logger });
  if (!lookup.results.length) {
    // No enabled source supports this type (or none of the requested ids do):
    // nothing was looked up, so the record and the audit trail stay untouched.
    const existing = found.source?.enrichment;
    return { ...lookup, alertId, enrichment: existing && typeof existing === 'object' ? existing : null };
  }

  const enrichment = await storeAlertEnrichment(client, alertId, found, lookup, now);
  await appendActivity(client, {
    targetType: 'alert',
    targetId: alertId,
    user,
    action: 'enrichment_lookup',
    to: `${type}:${canonical}`,
  });
  return { ...lookup, alertId, enrichment };
}

/** Bounded retries for the optimistic-concurrency write of `enrichment`. */
export const ENRICHMENT_WRITE_ATTEMPTS = 5;

/**
 * Merge `lookup` into the alert's stored `enrichment` and write it with
 * `if_seq_no` / `if_primary_term`. Concurrent lookups on the same alert (the
 * flyout's "Lookup all", two analysts) each read the record, merge and write;
 * a 409 means another writer landed first, so the record is re-resolved and
 * the merge redone on the fresh object instead of replacing it with a stale
 * one. The lookup itself is never repeated.
 */
async function storeAlertEnrichment(
  client: any,
  alertId: string,
  initial: { index: string; source?: any; seqNo?: number; primaryTerm?: number },
  lookup: Awaited<ReturnType<typeof runEnrichmentLookup>>,
  now: Date
): Promise<AlertEnrichment> {
  let current = initial;
  for (let attempt = 1; ; attempt++) {
    const enrichment: AlertEnrichment = mergeAlertEnrichment(current.source?.enrichment, lookup, now);
    const guarded = typeof current.seqNo === 'number' && typeof current.primaryTerm === 'number';
    try {
      // wait_for: the flyout re-reads the alert (and the queue re-searches for
      // the badge / filter) right after this call; see routes/alerts.ts bulk-update.
      await client.update({
        index: assertManagedWriteTarget(current.index),
        id: alertId,
        body: { doc: { enrichment } },
        refresh: 'wait_for',
        ...(guarded ? { if_seq_no: current.seqNo, if_primary_term: current.primaryTerm } : {}),
      });
      return enrichment;
    } catch (e: any) {
      const status = e?.meta?.statusCode || e?.statusCode;
      if (status !== 409 || attempt >= ENRICHMENT_WRITE_ATTEMPTS) throw e;
    }
    const fresh = (await resolveAlerts(client, [alertId], true, true)).get(alertId);
    if (!fresh) throw Object.assign(new Error('Alert not found'), { statusCode: 404 });
    current = fresh;
  }
}

export function defineEnrichmentRoutes(router: IRouter) {
  router.get({ path: `${API_ROOT}/enrichment/settings`, validate: false }, async (context, request, response) => {
    try {
      await requirePluginAdmin(context, request);
      const client = context.core.opensearch.client.asCurrentUser;
      return response.ok({ body: settingsBody(await enrichmentSettings.read(client)) });
    } catch (e: any) {
      return failure(response, e);
    }
  });

  router.put(
    {
      path: `${API_ROOT}/enrichment/settings`,
      validate: {
        body: schema.object({ sources: schema.arrayOf(sourceSchema, { maxSize: ENRICHMENT_MAX_SOURCES }) }),
      },
    },
    async (context, request, response) => {
      try {
        const identity = await requirePluginAdmin(context, request);
        const client = context.core.opensearch.client.asCurrentUser;
        const { sources } = request.body as any;
        const masked = await enrichmentSettings.write(client, { sources }, { actor: identity.name });
        await appendActivity(client, {
          targetType: 'system',
          targetId: ENRICHMENT_SETTINGS_DOC_ID,
          user: identity.name,
          action: 'enrichment_settings_updated',
          to: String((masked.sources || []).length),
        });
        return response.ok({ body: settingsBody(masked) });
      } catch (e: any) {
        return failure(response, e);
      }
    }
  );

  router.post(
    {
      path: `${API_ROOT}/enrichment/lookup`,
      validate: {
        query: schema.object({ refresh: schema.maybe(schema.boolean()) }),
        body: schema.object({
          type: lookupTypeSchema,
          value: schema.string({ minLength: 1, maxLength: 2048 }),
          sourceIds: schema.maybe(schema.arrayOf(schema.string({ minLength: 1, maxLength: 64 }), { maxSize: ENRICHMENT_MAX_SOURCES + 1 })),
        }),
      },
    },
    async (context, request, response) => {
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const { type, value, sourceIds } = request.body as any;
        const refresh = (request.query as any)?.refresh === true;
        return response.ok({ body: await runEnrichmentLookup(client, { type, value, sourceIds, refresh }) });
      } catch (e: any) {
        return failure(response, e);
      }
    }
  );

  router.post(
    {
      path: `${API_ROOT}/enrichment/alerts/{alertId}/lookup`,
      validate: {
        params: schema.object({ alertId: schema.string({ minLength: 1, maxLength: 256 }) }),
        query: schema.object({ refresh: schema.maybe(schema.boolean()) }),
        body: schema.object({
          type: lookupTypeSchema,
          value: schema.string({ minLength: 1, maxLength: 2048 }),
          sourceIds: schema.maybe(schema.arrayOf(schema.string({ minLength: 1, maxLength: 64 }), { maxSize: ENRICHMENT_MAX_SOURCES + 1 })),
        }),
      },
    },
    async (context, request, response) => {
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const user = await getCurrentUsername(context, request);
        const { alertId } = request.params as any;
        const { type, value, sourceIds } = request.body as any;
        const refresh = (request.query as any)?.refresh === true;
        return response.ok({ body: await lookupAndStoreAlertEnrichment(client, { alertId, type, value, sourceIds, refresh, user }) });
      } catch (e: any) {
        return failure(response, e);
      }
    }
  );

  router.post(
    {
      path: `${API_ROOT}/enrichment/test/{sourceId}`,
      validate: { params: schema.object({ sourceId: schema.string({ minLength: 1, maxLength: 64 }) }) },
    },
    async (context, request, response) => {
      try {
        await requirePluginAdmin(context, request);
        const client = context.core.opensearch.client.asCurrentUser;
        const { sourceId } = request.params as any;
        return response.ok({ body: await testEnrichmentSource(client, sourceId) });
      } catch (e: any) {
        return failure(response, e);
      }
    }
  );
}
