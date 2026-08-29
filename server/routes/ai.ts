import { schema } from '@osd/config-schema';
import { IRouter } from '../../../../src/core/server';
import {
  API_ROOT,
  COMMENTS_INDEX,
  META_INDEX,
  AI_PROVIDERS,
  AI_SETTINGS_DOC_ID,
} from '../../common';
import { getCurrentUsername } from '../lib/opensearch';
import { generateAiAnalysis } from '../lib/ai_providers';
import { projectAlert, projectCase, ProjectedAlert, ProjectedCase } from '../lib/egress/projection';
import { APPEND_HISTORY_SCRIPT_SOURCE, buildHistoryEntry } from '../lib/history';
import { encryptSecret, decryptSecret } from '../lib/crypto';
import { getEncryptionKey, ENCRYPTION_KEY_ENV_VAR } from '../lib/secrets_config';
import { resolveAlerts } from '../lib/index_resolution';
import { requirePluginAdmin } from '../lib/authorization';
import { validateAiBaseUrl } from '../lib/ai_url_policy';
import { appendActivity } from '../lib/activity';
import { resolveCase } from '../lib/case_index_resolution';

async function loadAiSettings(client: any): Promise<any | null> {
  try {
    const res: any = await client.get({ index: META_INDEX, id: AI_SETTINGS_DOC_ID });
    return res.body._source;
  } catch (e) {
    return null;
  }
}

export function defineAiRoutes(router: IRouter) {
  router.get({ path: `${API_ROOT}/ai/settings`, validate: false }, async (context, request, response) => {
    const client = context.core.opensearch.client.asCurrentUser;
    const settings = await loadAiSettings(client);
    return response.ok({
      body: {
        enabled: settings?.enabled ?? false,
        provider: settings?.provider ?? 'openai',
        model: settings?.model ?? '',
        baseUrl: settings?.baseUrl ?? '',
        configured: Boolean(settings?.apiKey),
        encryptionConfigured: Boolean(getEncryptionKey()),
      },
    });
  });

  router.post(
    {
      path: `${API_ROOT}/ai/settings`,
      validate: {
        body: schema.object({
          enabled: schema.boolean(),
          provider: schema.oneOf(AI_PROVIDERS.map((p) => schema.literal(p)) as any),
          apiKey: schema.maybe(schema.string()),
          model: schema.maybe(schema.string()),
          baseUrl: schema.maybe(schema.string()),
        }),
      },
    },
    async (context, request, response) => {
      try {
        await requirePluginAdmin(context, request);
      } catch (e: any) {
        return response.forbidden({ body: { message: e.message } });
      }
      const { enabled, provider, apiKey, model, baseUrl } = request.body as any;
      const trimmedKey = apiKey && apiKey.trim() ? apiKey.trim() : '';
      const encryptionKey = getEncryptionKey();

      if (trimmedKey && !encryptionKey) {
        return response.badRequest({
          body: {
            message:
              `Set the ${ENCRYPTION_KEY_ENV_VAR} environment variable (32+ characters) for the wazuh-dashboard ` +
              'service and restart it before storing an API key. This key is used to encrypt provider secrets at rest.',
          },
        });
      }

      const client = context.core.opensearch.client.asCurrentUser;
      const existing = await loadAiSettings(client);

      // A blank apiKey field means "keep the existing key" - it's never
      // sent back to the browser after being saved, so there's no other
      // way for the form to represent "leave it alone".
      const resolvedKey = trimmedKey ? encryptSecret(trimmedKey, encryptionKey!) : existing?.apiKey || '';

      let safeBaseUrl: string | null;
      try {
        safeBaseUrl = validateAiBaseUrl(provider, baseUrl);
      } catch (e: any) {
        return response.badRequest({ body: { message: e.message } });
      }

      const doc = {
        enabled,
        provider,
        model: model ?? '',
        baseUrl: safeBaseUrl ?? '',
        apiKey: resolvedKey,
        updated_at: new Date().toISOString(),
      };

      await client.index({ index: META_INDEX, id: AI_SETTINGS_DOC_ID, body: doc });
      return response.ok({
        body: { enabled: doc.enabled, provider: doc.provider, model: doc.model, baseUrl: doc.baseUrl, configured: Boolean(doc.apiKey) },
      });
    }
  );

  router.post(
    {
      path: `${API_ROOT}/ai/analyze`,
      validate: {
        body: schema.object({
          alertId: schema.maybe(schema.string()),
          caseId: schema.maybe(schema.string()),
        }),
      },
    },
    async (context, request, response) => {
      const { alertId, caseId } = request.body as any;
      if (!alertId && !caseId) {
        return response.badRequest({ body: { message: 'alertId or caseId is required' } });
      }

      const client = context.core.opensearch.client.asCurrentUser;
      const settings = await loadAiSettings(client);

      if (!settings?.enabled || !settings?.apiKey) {
        return response.badRequest({ body: { message: 'AI analysis is not configured. Set it up under AI Settings.' } });
      }
      const encryptionKey = getEncryptionKey();
      if (!encryptionKey) {
        return response.customError({
          statusCode: 500,
          body: { message: `${ENCRYPTION_KEY_ENV_VAR} is not set; cannot decrypt the stored API key.` },
        });
      }

      let apiKey: string;
      try {
        apiKey = decryptSecret(settings.apiKey, encryptionKey);
      } catch (e) {
        return response.customError({
          statusCode: 500,
          body: { message: `Failed to decrypt the stored API key - has ${ENCRYPTION_KEY_ENV_VAR} changed? Re-save it under AI Settings.` },
        });
      }

      const user = await getCurrentUsername(context, request);

      try {
        // The payload is allowlist-projected before it can be handed to a
        // provider - see server/lib/egress/projection.ts. Raw _source never
        // leaves the network.
        let payload: ProjectedAlert | ProjectedCase;
        let targetIndex: string;
        let targetId: string;

        if (alertId) {
          const locations = await resolveAlerts(client, [alertId], true);
          const alert = locations.get(alertId);
          if (!alert) return response.notFound({ body: { message: 'Alert not found' } });
          payload = projectAlert(alert.source);
          targetIndex = alert.index;
          targetId = alertId;
        } else {
          const caseRes = await resolveCase(client, caseId);
          const caseDoc = caseRes.source;
          const alertIds: string[] = caseDoc.alert_ids || [];
          // Bound the fan-out: a case's alert_ids can grow past any single
          // request's cap over repeated links, and projectCase caps how many
          // are actually sent, so only fetch what can be used.
          const boundedIds = alertIds.slice(0, 50);

          let alertSources: any[] = [];
          if (boundedIds.length) {
            const locations = await resolveAlerts(client, boundedIds, true);
            alertSources = boundedIds.map((id) => locations.get(id)?.source).filter(Boolean);
          }

          // Count comments without pulling their bodies across the boundary.
          const commentCountRes: any = await client.count({
            index: COMMENTS_INDEX,
            body: { query: { bool: { filter: [{ term: { event_type: 'comment' } }, { term: { case_id: caseId } }] } } },
          });
          const commentCount = commentCountRes.body.count ?? 0;

          payload = projectCase(caseDoc, alertSources, alertIds.length, commentCount);
          targetIndex = caseRes.index;
          targetId = caseId;
        }

        const text = await generateAiAnalysis(
          { provider: settings.provider, apiKey, model: settings.model, baseUrl: settings.baseUrl },
          payload,
          caseId ? 'case' : 'alert'
        );

        const analysis = {
          text,
          provider: settings.provider,
          model: settings.model || null,
          generated_at: new Date().toISOString(),
        };

        await client.update({
          index: targetIndex,
          id: targetId,
          body: {
            script: {
              lang: 'painless',
              source: APPEND_HISTORY_SCRIPT_SOURCE,
              params: {
                entry: buildHistoryEntry({ user, action: 'ai_analysis_generated' }),
                fields: { ai_analysis: analysis },
              },
            },
          },
        });
        await appendActivity(client, {
          targetType: caseId ? 'case' : 'alert',
          targetId,
          user,
          action: 'ai_analysis_generated',
        });

        return response.ok({ body: analysis });
      } catch (e: any) {
        return response.customError({ statusCode: 502, body: { message: e.message } });
      }
    }
  );
}
