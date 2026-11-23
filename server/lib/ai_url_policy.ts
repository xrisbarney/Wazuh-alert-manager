import { AI_PROVIDERS, AiProvider } from '../../common';
import { EgressError, validateEgressUrl } from './egress/url_policy';

const DEFAULT_HOSTS: Record<AiProvider, string[]> = {
  openai: ['api.openai.com'],
  deepseek: ['api.deepseek.com'],
  gemini: ['generativelanguage.googleapis.com'],
  anthropic: ['api.anthropic.com'],
};

function configuredHosts(): Set<string> {
  return new Set(
    String(process.env.WAZUH_ALERT_MANAGER_AI_ALLOWED_HOSTS || '')
      .split(',')
      .map((host) => host.trim().toLowerCase())
      .filter(Boolean)
  );
}

/**
 * Validate custom AI endpoints before the dashboard server can make a request.
 * Delegates to the shared egress policy (server/lib/egress/url_policy.ts) with
 * the provider's default hosts plus WAZUH_ALERT_MANAGER_AI_ALLOWED_HOSTS as the
 * allowlist, keeping the error wording the AI settings UI has always shown.
 * Unlike enrichment sources and webhooks, a local-suffix name (`.internal`,
 * `.local`, `.home.arpa`) stays refused even when listed: the Q9 private
 * receiver escape hatch does not apply to AI endpoints.
 */
export function validateAiBaseUrl(provider: AiProvider, value?: string | null): string | null {
  if (!value || !value.trim()) return null;
  if (!(AI_PROVIDERS as readonly string[]).includes(provider)) throw new Error('Unsupported AI provider');
  let parsed: URL;
  try {
    parsed = validateEgressUrl(value, {
      purpose: 'AI base URL',
      allowedHosts: [...DEFAULT_HOSTS[provider], ...configuredHosts()],
      refuseLocalHostnames: true,
    }).url;
  } catch (e) {
    throw new Error(aiPolicyMessage(e));
  }
  return parsed.toString().replace(/\/$/, '');
}

function aiPolicyMessage(error: unknown): string {
  if (!(error instanceof EgressError)) return error instanceof Error ? error.message : String(error);
  switch (error.reason) {
    case 'invalid_url':
      return 'AI base URL must be a valid HTTPS URL.';
    case 'scheme':
    case 'credentials':
      return 'AI base URL must use HTTPS and must not contain embedded credentials.';
    case 'host':
      return 'AI base URL cannot target localhost, a local hostname, or an IP literal.';
    case 'allowlist': {
      const host = error.host || 'unknown';
      return `AI host ${host} is not allowed. Add it to WAZUH_ALERT_MANAGER_AI_ALLOWED_HOSTS on the dashboard service.`;
    }
    default:
      return error.message;
  }
}
