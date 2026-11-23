import { validateAiBaseUrl } from './ai_url_policy';

describe('AI base URL policy', () => {
  test('accepts provider defaults', () => {
    expect(validateAiBaseUrl('openai', 'https://api.openai.com/v1')).toBe('https://api.openai.com/v1');
  });

  test.each([
    'http://api.openai.com/v1',
    'https://127.0.0.1/v1',
    'https://localhost/v1',
    'https://169.254.169.254/latest/meta-data',
    'https://example.invalid/v1',
  ])('rejects unsafe or unapproved endpoint %s', (url) => {
    expect(() => validateAiBaseUrl('openai', url)).toThrow();
  });

  describe('with WAZUH_ALERT_MANAGER_AI_ALLOWED_HOSTS set', () => {
    const saved = process.env.WAZUH_ALERT_MANAGER_AI_ALLOWED_HOSTS;
    beforeEach(() => {
      process.env.WAZUH_ALERT_MANAGER_AI_ALLOWED_HOSTS = 'llm.corp.internal, gateway.example.com';
    });
    afterEach(() => {
      if (saved === undefined) delete process.env.WAZUH_ALERT_MANAGER_AI_ALLOWED_HOSTS;
      else process.env.WAZUH_ALERT_MANAGER_AI_ALLOWED_HOSTS = saved;
    });

    test('accepts a listed public host', () => {
      expect(validateAiBaseUrl('openai', 'https://gateway.example.com/v1/')).toBe('https://gateway.example.com/v1');
    });

    test('still refuses a listed local-suffix hostname (the private receiver escape hatch is not for AI)', () => {
      expect(() => validateAiBaseUrl('openai', 'https://llm.corp.internal/v1')).toThrow(/localhost, a local hostname, or an IP literal/);
    });
  });
});
