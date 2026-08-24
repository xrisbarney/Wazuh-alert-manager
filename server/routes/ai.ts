import { schema } from '@osd/config-schema';
import { IRouter } from '../../../../src/core/server';
import { API_ROOT, ALERT_STATUS_INDEX, META_INDEX, AI_PROVIDERS, AI_SETTINGS_DOC_ID } from '../../common';
import { getCurrentUsername } from '../lib/opensearch';
import { generateAiAnalysis } from '../lib/ai_providers';
import { APPEND_HISTORY_SCRIPT_SOURCE, buildHistoryEntry } from '../lib/history';
import { encryptSecret, decryptSecret } from '../lib/crypto';
import { getEncryptionKey, ENCRYPTION_KEY_ENV_VAR } from '../lib/secrets_config';

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

      const doc = {
        enabled,
        provider,
        model: model ?? '',
        baseUrl: baseUrl ?? '',
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
      validate: { body: schema.object({ alertId: schema.string() }) },
    },
    async (context, request, response) => {
      const { alertId } = request.body as any;
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

      try {
        const alertRes: any = await client.get({ index: ALERT_STATUS_INDEX, id: alertId });
        const text = await generateAiAnalysis(
          { provider: settings.provider, apiKey, model: settings.model, baseUrl: settings.baseUrl },
          alertRes.body._source
        );

        const analysis = {
          text,
          provider: settings.provider,
          model: settings.model || null,
          generated_at: new Date().toISOString(),
        };

        const user = await getCurrentUsername(context, request);
        await client.update({
          index: ALERT_STATUS_INDEX,
          id: alertId,
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

        return response.ok({ body: analysis });
      } catch (e: any) {
        return response.customError({ statusCode: 502, body: { message: e.message } });
      }
    }
  );
}
