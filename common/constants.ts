export const PLUGIN_ID = 'wazuhAlertManager';
export const PLUGIN_NAME = 'wazuh-alert-manager';

// Index names owned by this plugin.
export const ALERT_STATUS_INDEX = 'wazuh-alert-status';
export const COMMENTS_INDEX = 'wazuh-alert-manager-comments';
export const CASES_INDEX = 'wazuh-alert-manager-cases';
export const META_INDEX = 'wazuh-alert-manager-meta';
export const RULES_INDEX = 'wazuh-alert-manager-rules';

export const API_ROOT = '/api/wazuh_alert_manager';

export const ALERT_STATUSES = ['open', 'in_progress', 'closed'] as const;

export const CASE_SEVERITIES = ['low', 'medium', 'high', 'critical'] as const;

export const CASE_STATUSES = ['open', 'in_progress', 'closed'] as const;

export const AI_PROVIDERS = ['openai', 'deepseek', 'gemini', 'anthropic'] as const;

export const AI_SETTINGS_DOC_ID = 'ai_settings';

// Correlation rules: entity types an alert can be grouped by, and the ceiling
// on how many cases one evaluation pass may auto-create (blast-radius guard).
export const CORRELATION_ENTITIES = ['agent', 'srcip', 'dstip', 'user', 'dstuser', 'process'] as const;
export const MAX_AUTO_CASES_PER_RUN = 20;

