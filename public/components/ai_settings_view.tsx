import React, { useState, useEffect } from 'react';
import {
  EuiForm,
  EuiFormRow,
  EuiSwitch,
  EuiSelect,
  EuiFieldPassword,
  EuiFieldText,
  EuiButton,
  EuiSpacer,
  EuiBadge,
  EuiPanel,
  EuiAccordion,
  EuiLoadingSpinner,
  EuiCallOut,
  EuiCodeBlock,
  EuiTitle,
} from '@elastic/eui';
import { AiProvider } from '../../common';
import { AlertsApiService } from '../services/api';
import { SettingsFormActions, SettingsPageHeader } from './settings_page';

interface Props {
  apiService: AlertsApiService;
  onToast: (title: string, color: 'success' | 'danger' | 'primary', text?: string) => void;
}

const PROVIDER_OPTIONS: Array<{ value: AiProvider; text: string }> = [
  { value: 'openai', text: 'OpenAI' },
  { value: 'deepseek', text: 'DeepSeek' },
  { value: 'gemini', text: 'Google Gemini' },
  { value: 'anthropic', text: 'Anthropic Claude' },
];

export const AiSettingsView: React.FC<Props> = ({ apiService, onToast }) => {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [enabled, setEnabled] = useState(false);
  const [provider, setProvider] = useState<AiProvider>('openai');
  const [apiKey, setApiKey] = useState('');
  const [model, setModel] = useState('');
  const [baseUrl, setBaseUrl] = useState('');
  const [configured, setConfigured] = useState(false);
  const [encryptionConfigured, setEncryptionConfigured] = useState(true);

  useEffect(() => {
    apiService
      .fetchAiSettings()
      .then((res: any) => {
        setEnabled(res.enabled);
        setProvider(res.provider);
        setModel(res.model || '');
        setBaseUrl(res.baseUrl || '');
        setConfigured(res.configured);
        setEncryptionConfigured(res.encryptionConfigured);
      })
      .catch(() => onToast('Failed to load AI settings', 'danger'))
      .finally(() => setLoading(false));
  }, []);

  const save = async () => {
    try {
      setSaving(true);
      const res: any = await apiService.saveAiSettings({ enabled, provider, apiKey: apiKey || undefined, model: model || undefined, baseUrl: baseUrl || undefined });
      setConfigured(res.configured);
      setApiKey('');
      onToast('AI settings saved', 'success');
    } catch (e: any) {
      onToast('Failed to save AI settings', 'danger', e?.body?.message || e.message);
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <div className="wamSettingsLoading"><EuiLoadingSpinner size="xl" /></div>;

  return (
    <div className="wamSettingsPage wamAiSettings" data-test-subj="wamAiSettings">
      <SettingsPageHeader
        title="AI analysis integration"
        description="Connect an LLM provider so analysts can generate an AI-assisted summary and next-step suggestions when an alert is opened. The API key is encrypted before it is stored and is never sent back to the browser."
      />

      {!encryptionConfigured && (
        <>
          <EuiCallOut size="s" title="Encryption key not configured" color="danger" iconType="lock">
            <p>
              Set the <code>WAZUH_ALERT_MANAGER_ENCRYPTION_KEY</code> environment variable (32+ characters) for the
              wazuh-dashboard service and restart it before an API key can be saved. Generate one with:
            </p>
            <EuiCodeBlock isCopyable fontSize="s" paddingSize="s">
              openssl rand -base64 32
            </EuiCodeBlock>
          </EuiCallOut>
          <EuiSpacer size="m" />
        </>
      )}

      <EuiPanel hasBorder hasShadow={false} paddingSize="m">
        <EuiTitle size="xs"><h4>Provider</h4></EuiTitle>
        <EuiSpacer size="s" />
        <EuiForm>
          <EuiFormRow label="Enable AI analysis" fullWidth hasChildLabel={false}>
            <EuiSwitch label={enabled ? 'Enabled' : 'Disabled'} checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          </EuiFormRow>

          <EuiFormRow label="Provider" fullWidth>
            <EuiSelect fullWidth options={PROVIDER_OPTIONS} value={provider} onChange={(e) => setProvider(e.target.value as AiProvider)} />
          </EuiFormRow>

          <EuiFormRow
            label="API key"
            fullWidth
            labelAppend={configured ? <EuiBadge color="success">Configured</EuiBadge> : <EuiBadge color="hollow">Not set</EuiBadge>}
            helpText={configured ? 'Leave blank to keep the currently saved key.' : undefined}
          >
            <EuiFieldPassword
              fullWidth
              type="dual"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder={configured ? '••••••••••••' : 'Paste your API key'}
            />
          </EuiFormRow>

          <EuiAccordion id="ai-advanced" buttonContent="Advanced">
            <EuiSpacer size="s" />
            <EuiFormRow label="Model override" fullWidth helpText="Leave blank to use the provider's default model.">
              <EuiFieldText fullWidth value={model} onChange={(e) => setModel(e.target.value)} placeholder="e.g. gpt-4o-mini" />
            </EuiFormRow>
            <EuiFormRow label="API base URL override" fullWidth helpText="Only needed for self-hosted or proxied endpoints.">
              <EuiFieldText fullWidth value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder="https://..." />
            </EuiFormRow>
          </EuiAccordion>

          <EuiSpacer size="m" />
          <SettingsFormActions>
            <EuiButton size="s" fill iconType="save" onClick={save} isLoading={saving}>
              Save AI settings
            </EuiButton>
          </SettingsFormActions>
        </EuiForm>
      </EuiPanel>
    </div>
  );
};
