export const PLUGIN_ID = 'wazuhAlertManager';
export const PLUGIN_NAME = 'wazuh-alert-manager';

// Index names owned by this plugin.
export const ALERT_STATUS_INDEX = 'wazuh-alert-status';
export const COMMENTS_INDEX = 'wazuh-alert-manager-comments';
export const CASES_INDEX = 'wazuh-alert-manager-cases';
export const META_INDEX = 'wazuh-alert-manager-meta';

export const API_ROOT = '/api/wazuh_alert_manager';

export const ALERT_STATUSES = ['open', 'in_progress', 'closed'] as const;

export const CASE_SEVERITIES = ['low', 'medium', 'high', 'critical'] as const;

export const CASE_STATUSES = ['open', 'closed'] as const;

export const AI_PROVIDERS = ['openai', 'deepseek', 'gemini', 'anthropic'] as const;

export const AI_SETTINGS_DOC_ID = 'ai_settings';

