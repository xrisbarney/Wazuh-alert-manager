import { schema } from '@osd/config-schema';
import { IRouter } from '../../../../src/core/server';
import {
  API_ROOT,
  ASSET_CRITICALITIES,
  ASSET_MATCH_KINDS,
  ASSET_MAX_ENTRIES,
  ASSET_MAX_TAGS,
  ASSET_SETTINGS_DOC_ID,
} from '../../common';
import type { AssetContextResponse, AssetResolution, AssetSettingsResponse } from '../../common';
import { requirePluginAdmin } from '../lib/authorization';
import { trustedIdentity } from '../lib/identity';
import { getAssetContext } from '../lib/asset_context';
import { appendActivity } from '../lib/activity';
import { assetSettings, buildAssetMatcher } from '../lib/assets';

/**
 * Asset criticality routes (step 6.4a). All three are administrator-only:
 * the settings document names hosts and their business criticality.
 *
 *   GET  /assets/settings            the stored entries
 *   PUT  /assets/settings            replace the entries (whole list)
 *   GET  /assets/resolve?agentName=&groups=&labels=
 *                                    run the matcher once (settings tab "Test match")
 *
 * `GET /assets/context?agentId=&agentName=` (step 6.4b) is open to every
 * signed-in user: it only reads the native `wazuh-states-*` families as that
 * user, so the role grant (not this route) decides what comes back, and a
 * missing grant is a `no_access` chip rather than an error.
 *
 * PUT validates shape here and semantics inside the settings doc write
 * (`normaliseAssetSettings`, which answers 400).
 */

const entrySchema = schema.object(
  {
    id: schema.string({ minLength: 1, maxLength: 64 }),
    match: schema.object({
      kind: schema.oneOf(ASSET_MATCH_KINDS.map((kind) => schema.literal(kind)) as any),
      value: schema.string({ minLength: 1, maxLength: 256 }),
    }),
    criticality: schema.oneOf(ASSET_CRITICALITIES.map((value) => schema.literal(value)) as any),
    tags: schema.arrayOf(schema.string({ maxLength: 64 }), { maxSize: ASSET_MAX_TAGS, defaultValue: [] }),
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

function settingsBody(doc: any): AssetSettingsResponse {
  return {
    assets: Array.isArray(doc?.assets) ? doc.assets : [],
    updated_at: doc?.updated_at,
    updated_by: doc?.updated_by,
  };
}

function csv(value: unknown): string[] {
  return typeof value === 'string' ? value.split(',').map((v) => v.trim()).filter(Boolean) : [];
}

/** `key=value` pairs separated by commas, as typed into the Test match box. */
export function parseLabelsParam(value: unknown): Record<string, string> | null {
  const out: Record<string, string> = {};
  for (const pair of csv(value)) {
    const index = pair.indexOf('=');
    if (index <= 0) continue;
    out[pair.slice(0, index).trim()] = pair.slice(index + 1).trim();
  }
  return Object.keys(out).length ? out : null;
}

export function defineAssetRoutes(router: IRouter) {
  router.get({ path: `${API_ROOT}/assets/settings`, validate: false }, async (context, request, response) => {
    try {
      await requirePluginAdmin(context, request);
      const client = context.core.opensearch.client.asCurrentUser;
      return response.ok({ body: settingsBody(await assetSettings.read(client)) });
    } catch (e: any) {
      return failure(response, e);
    }
  });

  router.put(
    {
      path: `${API_ROOT}/assets/settings`,
      validate: {
        body: schema.object({ assets: schema.arrayOf(entrySchema, { maxSize: ASSET_MAX_ENTRIES }) }),
      },
    },
    async (context, request, response) => {
      try {
        const identity = await requirePluginAdmin(context, request);
        const client = context.core.opensearch.client.asCurrentUser;
        const { assets } = request.body as any;
        const saved = await assetSettings.write(client, { assets }, { actor: identity.name });
        await appendActivity(client, {
          targetType: 'system',
          targetId: ASSET_SETTINGS_DOC_ID,
          user: identity.name,
          action: 'asset_settings_updated',
          to: String((saved.assets || []).length),
        });
        return response.ok({ body: settingsBody(saved) });
      } catch (e: any) {
        return failure(response, e);
      }
    }
  );

  router.get(
    {
      path: `${API_ROOT}/assets/resolve`,
      validate: {
        query: schema.object({
          agentName: schema.maybe(schema.string({ maxLength: 256 })),
          /** csv of group names */
          groups: schema.maybe(schema.string({ maxLength: 4096 })),
          /** csv of key=value label pairs (4.x) */
          labels: schema.maybe(schema.string({ maxLength: 4096 })),
        }),
      },
    },
    async (context, request, response) => {
      try {
        await requirePluginAdmin(context, request);
        const client = context.core.opensearch.client.asCurrentUser;
        const query = request.query as any;
        const doc = await assetSettings.read(client);
        const matcher = buildAssetMatcher(doc.assets);
        const resolution: AssetResolution = matcher.resolve({
          agentName: query.agentName || null,
          groups: csv(query.groups),
          labels: parseLabelsParam(query.labels),
        });
        return response.ok({ body: resolution });
      } catch (e: any) {
        return failure(response, e);
      }
    }
  );

  router.get(
    {
      path: `${API_ROOT}/assets/context`,
      validate: {
        query: schema.object({
          agentId: schema.maybe(schema.string({ minLength: 1, maxLength: 64 })),
          agentName: schema.maybe(schema.string({ minLength: 1, maxLength: 256 })),
        }),
      },
    },
    async (context, request, response) => {
      try {
        const query = request.query as any;
        const agentId = typeof query.agentId === 'string' ? query.agentId.trim() : '';
        const agentName = typeof query.agentName === 'string' ? query.agentName.trim() : '';
        if (!agentId && !agentName) {
          return response.badRequest({ body: { message: 'agentId or agentName is required.' } });
        }
        const identity = await trustedIdentity(context, request);
        const client = context.core.opensearch.client.asCurrentUser;
        // Only a user the security plugin named gets a cache slot; the anonymous
        // fallback name would otherwise be shared between different real users.
        const body: AssetContextResponse = await getAssetContext(
          client,
          identity.name,
          { agentId: agentId || null, agentName: agentName || null },
          { cache: identity.source === 'security_plugin' }
        );
        return response.ok({ body });
      } catch (e: any) {
        return failure(response, e);
      }
    }
  );
}
