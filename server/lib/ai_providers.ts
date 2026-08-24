import { AiProvider } from '../../common';

export interface AiCallSettings {
  provider: AiProvider;
  apiKey: string;
  model?: string | null;
  baseUrl?: string | null;
}

const DEFAULT_MODELS: Record<AiProvider, string> = {
  openai: 'gpt-4o-mini',
  deepseek: 'deepseek-chat',
  gemini: 'gemini-1.5-flash',
  anthropic: 'claude-3-5-haiku-latest',
};

const DEFAULT_BASE_URLS: Record<AiProvider, string> = {
  openai: 'https://api.openai.com/v1',
  deepseek: 'https://api.deepseek.com/v1',
  gemini: 'https://generativelanguage.googleapis.com/v1beta',
  anthropic: 'https://api.anthropic.com/v1',
};

const ALERT_SYSTEM_PROMPT =
  'You are a SOC analyst assistant. Given a single Wazuh security alert as JSON, respond with: ' +
  '1) a one-paragraph plain-English summary of what happened, ' +
  '2) an assessment of likely severity and false-positive risk, ' +
  '3) 2-4 concrete next investigative or remediation steps. ' +
  "Be concise and base your answer only on the alert's own field values - do not invent facts that are not present in the data.";

const CASE_SYSTEM_PROMPT =
  'You are a SOC analyst assistant. Given an incident case as JSON - its title/description/severity, every ' +
  'alert linked to it, and the analyst comments left on it - respond with: ' +
  '1) a short narrative of how the incident likely unfolded across the linked alerts, in chronological order, ' +
  '2) an overall severity/impact assessment for the case as a whole, ' +
  '3) 2-4 concrete next investigative or remediation steps for closing this case out. ' +
  'Be concise and base your answer only on the data provided - do not invent facts that are not present in it.';

/**
 * Calls the configured AI provider's text-generation API and returns the
 * raw analysis text. Provider APIs are intentionally isolated here so
 * adding a new provider only means adding one case to this switch plus one
 * entry to the AI_PROVIDERS constant / UI dropdown.
 */
export async function generateAiAnalysis(
  settings: AiCallSettings,
  payload: Record<string, any>,
  mode: 'alert' | 'case' = 'alert'
): Promise<string> {
  if (typeof fetch !== 'function') {
    throw new Error('The dashboard Node.js runtime does not have a global fetch available.');
  }

  const model = settings.model || DEFAULT_MODELS[settings.provider];
  const baseUrl = settings.baseUrl || DEFAULT_BASE_URLS[settings.provider];
  const SYSTEM_PROMPT = mode === 'case' ? CASE_SYSTEM_PROMPT : ALERT_SYSTEM_PROMPT;
  const userContent = `${mode === 'case' ? 'Case' : 'Alert'} JSON:\n${JSON.stringify(payload, null, 2)}`;

  switch (settings.provider) {
    case 'openai':
    case 'deepseek': {
      const res = await fetch(`${baseUrl}/chat/completions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${settings.apiKey}` },
        body: JSON.stringify({
          model,
          messages: [
            { role: 'system', content: SYSTEM_PROMPT },
            { role: 'user', content: userContent },
          ],
          temperature: 0.2,
        }),
      });
      if (!res.ok) {
        throw new Error(`${settings.provider} API error ${res.status}: ${await res.text()}`);
      }
      const data: any = await res.json();
      return data.choices?.[0]?.message?.content ?? '';
    }

    case 'anthropic': {
      const res = await fetch(`${baseUrl}/messages`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': settings.apiKey,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model,
          max_tokens: 1024,
          system: SYSTEM_PROMPT,
          messages: [{ role: 'user', content: userContent }],
        }),
      });
      if (!res.ok) {
        throw new Error(`anthropic API error ${res.status}: ${await res.text()}`);
      }
      const data: any = await res.json();
      return (data.content || []).map((block: any) => block.text).join('\n');
    }

    case 'gemini': {
      const res = await fetch(`${baseUrl}/models/${model}:generateContent?key=${settings.apiKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          systemInstruction: { parts: [{ text: SYSTEM_PROMPT }] },
          contents: [{ role: 'user', parts: [{ text: userContent }] }],
        }),
      });
      if (!res.ok) {
        throw new Error(`gemini API error ${res.status}: ${await res.text()}`);
      }
      const data: any = await res.json();
      return (data.candidates?.[0]?.content?.parts || []).map((p: any) => p.text).join('\n');
    }

    default:
      throw new Error(`Unsupported AI provider: ${settings.provider}`);
  }
}
