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
  EuiText,
  EuiBadge,
  EuiPanel,
  EuiAccordion,
  EuiLoadingSpinner,
  EuiCallOut,
  EuiCodeBlock,
} from '@elastic/eui';
import { AiProvider } from '../../common';
import { AlertsApiService } from '../services/api';

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

  if (loading) return <EuiLoadingSpinner size="xl" />;

  return (
    <EuiPanel paddingSize="l" style={{ maxWidth: 640 }}>
      <EuiText>
        <h2>AI Analysis Integration</h2>
      </EuiText>
      <EuiText size="s" color="subdued">
        Connect an LLM provider so analysts can generate an AI-assisted summary and next-step suggestions when an alert is opened.
        The API key is encrypted before it is stored and is never sent back to the browser.
      </EuiText>
      <EuiSpacer size="l" />

      {!encryptionConfigured && (
        <>
          <EuiCallOut title="Encryption key not configured" color="danger" iconType="lock">
            <p>
              Set the <code>WAZUH_ALERT_MANAGER_ENCRYPTION_KEY</code> environment variable (32+ characters) for the
              wazuh-dashboard service and restart it before an API key can be saved. Generate one with:
            </p>
            <EuiCodeBlock isCopyable fontSize="s" paddingSize="s">
              openssl rand -base64 32
            </EuiCodeBlock>
          </EuiCallOut>
          <EuiSpacer size="l" />
        </>
      )}

      <EuiForm>
        <EuiFormRow label="Enable AI analysis">
          <EuiSwitch label={enabled ? 'Enabled' : 'Disabled'} checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
        </EuiFormRow>

        <EuiFormRow label="Provider">
          <EuiSelect options={PROVIDER_OPTIONS} value={provider} onChange={(e) => setProvider(e.target.value as AiProvider)} />
        </EuiFormRow>

        <EuiFormRow
          label="API key"
          labelAppend={configured ? <EuiBadge color="success">Configured</EuiBadge> : <EuiBadge color="hollow">Not set</EuiBadge>}
          helpText={configured ? 'Leave blank to keep the currently saved key.' : undefined}
        >
          <EuiFieldPassword
            type="dual"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            placeholder={configured ? '••••••••••••' : 'Paste your API key'}
          />
        </EuiFormRow>

        <EuiAccordion id="ai-advanced" buttonContent="Advanced">
          <EuiSpacer size="s" />
          <EuiFormRow label="Model override" helpText="Leave blank to use the provider's default model.">
            <EuiFieldText value={model} onChange={(e) => setModel(e.target.value)} placeholder="e.g. gpt-4o-mini" />
          </EuiFormRow>
          <EuiFormRow label="API base URL override" helpText="Only needed for self-hosted or proxied endpoints.">
            <EuiFieldText value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder="https://..." />
          </EuiFormRow>
        </EuiAccordion>

        <EuiSpacer size="l" />
        <EuiButton fill onClick={save} isLoading={saving}>
          Save AI settings
        </EuiButton>
      </EuiForm>
    </EuiPanel>
  );
};
