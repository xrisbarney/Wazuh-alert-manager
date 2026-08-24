const ENV_VAR = 'WAZUH_ALERT_MANAGER_ENCRYPTION_KEY';

/**
 * The key used to encrypt AI provider API keys at rest, supplied as an
 * environment variable rather than through opensearch_dashboards.yml.
 *
 * This plugin's declarative config schema (server/config.ts) is honored
 * for defaults, but this dashboard build does not reliably recognize
 * third-party plugin config keys added to opensearch_dashboards.yml (they
 * get rejected at startup as "Unknown configuration key(s)") - see
 * README.md#ai-analysis-integration. An environment variable sidesteps
 * that entirely and is a perfectly standard way to hand a service a
 * secret, so it's used here instead of fighting the platform.
 */
export function getEncryptionKey(): string | undefined {
  const value = process.env[ENV_VAR];
  return value && value.length >= 32 ? value : undefined;
}

export const ENCRYPTION_KEY_ENV_VAR = ENV_VAR;
