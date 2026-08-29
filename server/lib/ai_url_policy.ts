import { AI_PROVIDERS, AiProvider } from '../../common';

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

function isIpLiteral(hostname: string): boolean {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname) || hostname.includes(':');
}

/** Validate custom AI endpoints before the dashboard server can make a request. */
export function validateAiBaseUrl(provider: AiProvider, value?: string | null): string | null {
  if (!value || !value.trim()) return null;
  if (!(AI_PROVIDERS as readonly string[]).includes(provider)) throw new Error('Unsupported AI provider');
  let parsed: URL;
  try {
    parsed = new URL(value.trim());
  } catch (e) {
    throw new Error('AI base URL must be a valid HTTPS URL.');
  }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password) {
    throw new Error('AI base URL must use HTTPS and must not contain embedded credentials.');
  }
  const host = parsed.hostname.toLowerCase();
  if (host === 'localhost' || host.endsWith('.local') || isIpLiteral(host)) {
    throw new Error('AI base URL cannot target localhost, a local hostname, or an IP literal.');
  }
  const allowed = new Set([...DEFAULT_HOSTS[provider], ...configuredHosts()]);
  if (!allowed.has(host)) {
    throw new Error(
      `AI host ${host} is not allowed. Add it to WAZUH_ALERT_MANAGER_AI_ALLOWED_HOSTS on the dashboard service.`
    );
  }
  return parsed.toString().replace(/\/$/, '');
}
