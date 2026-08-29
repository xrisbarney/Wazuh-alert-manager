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
});
