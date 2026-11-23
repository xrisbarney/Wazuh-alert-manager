import {
  EGRESS_ALLOWED_HOSTS_ENV_VAR,
  EgressError,
  isEgressError,
  isPrivateAddress,
  normaliseHosts,
  readEgressAllowedHosts,
  validateEgressUrl,
} from './url_policy';

const PURPOSE = { purpose: 'Webhook URL' };

function policyError(url: string, options: Parameters<typeof validateEgressUrl>[1] = PURPOSE): EgressError {
  try {
    validateEgressUrl(url, options);
  } catch (e) {
    expect(isEgressError(e)).toBe(true);
    return e as EgressError;
  }
  throw new Error(`expected ${url} to be refused`);
}

describe('egress URL policy', () => {
  const originalEnv = process.env[EGRESS_ALLOWED_HOSTS_ENV_VAR];

  beforeEach(() => {
    delete process.env[EGRESS_ALLOWED_HOSTS_ENV_VAR];
  });

  afterAll(() => {
    if (originalEnv === undefined) delete process.env[EGRESS_ALLOWED_HOSTS_ENV_VAR];
    else process.env[EGRESS_ALLOWED_HOSTS_ENV_VAR] = originalEnv;
  });

  test('accepts a public https URL and returns the parsed URL', () => {
    const result = validateEgressUrl(' https://hooks.example.com/path?x=1 ', PURPOSE);
    expect(result.ok).toBe(true);
    expect(result.url).toBeInstanceOf(URL);
    expect(result.url.hostname).toBe('hooks.example.com');
    expect(result.url.toString()).toBe('https://hooks.example.com/path?x=1');
  });

  test('accepts a URL instance', () => {
    expect(validateEgressUrl(new URL('https://api.example.org/v1'), PURPOSE).url.hostname).toBe('api.example.org');
  });

  test.each(['not a url', '', 'mailto:soc@example.com', 'https://'])('refuses unparsable input %j', (value) => {
    const error = policyError(value);
    expect(error.code).toBe('policy');
    expect(error.reason).toBe('invalid_url');
  });

  test('refuses non-https schemes by default', () => {
    const error = policyError('http://hooks.example.com/');
    expect(error.code).toBe('policy');
    expect(error.reason).toBe('scheme');
    expect(error.message).toBe('Webhook URL must use HTTPS.');
    expect(policyError('ftp://hooks.example.com/').reason).toBe('scheme');
  });

  test('refuses embedded credentials', () => {
    expect(policyError('https://user:secret@hooks.example.com/').reason).toBe('credentials');
    expect(policyError('https://user@hooks.example.com/').reason).toBe('credentials');
  });

  test.each([
    'https://localhost/',
    'https://LOCALHOST:5601/',
    'https://foo.localhost/',
    'https://printer.local/',
    'https://indexer.internal/',
    'https://nas.home.arpa/',
  ])('refuses local hostnames %s', (url) => {
    expect(policyError(url).reason).toBe('host');
  });

  test.each([
    'https://127.0.0.1/',
    'https://127.1/',
    'https://0x7f.0.0.1/',
    'https://2130706433/',
    'https://10.0.0.5/',
    'https://172.16.4.4:8443/',
    'https://192.168.56.21/',
    'https://100.64.1.1/',
    'https://169.254.169.254/latest/meta-data',
    'https://8.8.8.8/',
    'https://[::1]/',
    'https://[fe80::1]/',
    'https://[fd12:3456::1]/',
    'https://[fc00::1]/',
    'https://[::ffff:10.0.0.1]/',
    'https://[2606:4700::1111]/',
  ])('refuses IP literals and private ranges %s', (url) => {
    const error = policyError(url);
    expect(error.code).toBe('policy');
    expect(error.reason).toBe('host');
  });

  test('explicit allowlist is case-insensitive and exact', () => {
    const allowedHosts = ['Hooks.Example.COM'];
    expect(validateEgressUrl('https://hooks.example.com/a', { purpose: 'X', allowedHosts }).url.hostname).toBe(
      'hooks.example.com'
    );
    const error = policyError('https://evil.hooks.example.com/a', { purpose: 'X', allowedHosts });
    expect(error.reason).toBe('allowlist');
    expect(error.message).toContain(EGRESS_ALLOWED_HOSTS_ENV_VAR);
    expect(policyError('https://hooks.example.com.attacker.net/', { purpose: 'X', allowedHosts }).reason).toBe(
      'allowlist'
    );
  });

  test('env allowlist is read at call time', () => {
    expect(readEgressAllowedHosts()).toEqual([]);
    expect(validateEgressUrl('https://anything.example.net/', PURPOSE).ok).toBe(true);

    process.env[EGRESS_ALLOWED_HOSTS_ENV_VAR] = ' Hooks.Example.com , n8n.example.org,, ';
    expect(readEgressAllowedHosts()).toEqual(['hooks.example.com', 'n8n.example.org']);
    expect(validateEgressUrl('https://HOOKS.example.com/', PURPOSE).ok).toBe(true);
    expect(validateEgressUrl('https://n8n.example.org/', PURPOSE).ok).toBe(true);
    expect(policyError('https://anything.example.net/').reason).toBe('allowlist');

    delete process.env[EGRESS_ALLOWED_HOSTS_ENV_VAR];
    expect(validateEgressUrl('https://anything.example.net/', PURPOSE).ok).toBe(true);
  });

  test('explicit allowedHosts override the env allowlist', () => {
    process.env[EGRESS_ALLOWED_HOSTS_ENV_VAR] = 'env.example.com';
    expect(validateEgressUrl('https://api.example.com/', { purpose: 'X', allowedHosts: ['api.example.com'] }).ok).toBe(
      true
    );
    expect(policyError('https://env.example.com/', { purpose: 'X', allowedHosts: ['api.example.com'] }).reason).toBe(
      'allowlist'
    );
  });

  test('an empty or blank explicit allowedHosts keeps the env allowlist in force', () => {
    process.env[EGRESS_ALLOWED_HOSTS_ENV_VAR] = 'env.example.com';
    for (const allowedHosts of [[], [''], [' ', '']]) {
      expect(policyError('https://hooks.example.com/', { purpose: 'X', allowedHosts }).reason).toBe('allowlist');
      expect(validateEgressUrl('https://env.example.com/', { purpose: 'X', allowedHosts }).ok).toBe(true);
    }
    delete process.env[EGRESS_ALLOWED_HOSTS_ENV_VAR];
    expect(validateEgressUrl('https://hooks.example.com/', { purpose: 'X', allowedHosts: [] }).ok).toBe(true);
  });

  test('allowlist entries are normalised like URL hostnames (IDN, trailing dot, case)', () => {
    expect(normaliseHosts(['Bücher.Example', 'api.example.com.', ' ', 'not a host name', 'ok.example'])).toEqual([
      'xn--bcher-kva.example',
      'api.example.com',
      'ok.example',
    ]);
    const allowedHosts = ['bücher.example', 'api.example.com.'];
    expect(validateEgressUrl('https://xn--bcher-kva.example/', { purpose: 'X', allowedHosts }).ok).toBe(true);
    expect(validateEgressUrl('https://bücher.example/', { purpose: 'X', allowedHosts }).ok).toBe(true);
    expect(validateEgressUrl('https://api.example.com/', { purpose: 'X', allowedHosts }).ok).toBe(true);
    expect(validateEgressUrl('https://api.example.com./', { purpose: 'X', allowedHosts }).ok).toBe(true);
    expect(policyError('https://other.example.com./', { purpose: 'X', allowedHosts }).reason).toBe('allowlist');

    process.env[EGRESS_ALLOWED_HOSTS_ENV_VAR] = 'bücher.example';
    expect(validateEgressUrl('https://xn--bcher-kva.example/', PURPOSE).ok).toBe(true);
  });

  test('policy errors carry the refused host structurally', () => {
    expect(policyError('https://evil.example.com/', { purpose: 'X', allowedHosts: ['ok.example.com'] }).host).toBe(
      'evil.example.com'
    );
    expect(policyError('https://localhost/').host).toBe('localhost');
    expect(policyError('https://10.0.0.5/').host).toBe('10.0.0.5');
    expect(policyError('http://hooks.example.com/').host).toBeUndefined();
  });

  test.each([
    '127.0.0.1',
    '127.255.255.254',
    '0.0.0.0',
    '10.1.2.3',
    '100.64.0.1',
    '169.254.169.254',
    '172.16.0.1',
    '172.31.255.255',
    '192.168.56.21',
    '192.0.0.8',
    '198.18.0.1',
    '224.0.0.1',
    '255.255.255.255',
    '::',
    '::1',
    '::ffff:127.0.0.1',
    '::ffff:10.0.0.1',
    '::ffff:7f00:1',
    '::10.0.0.1',
    '64:ff9b::a00:1',
    'fc00::1',
    'fd12:3456::1',
    'fe80::1',
    'fe80::1%eth0',
    'fec0::1',
    'ff02::1',
    '2001:db8::1',
    'not-an-ip',
    '',
  ])('isPrivateAddress refuses %s', (address) => {
    expect(isPrivateAddress(address)).toBe(true);
  });

  test.each(['8.8.8.8', '1.1.1.1', '172.32.0.1', '172.15.255.255', '100.128.0.1', '2606:4700::1111', '::ffff:8.8.8.8', '64:ff9b::808:808'])(
    'isPrivateAddress accepts public %s',
    (address) => {
      expect(isPrivateAddress(address)).toBe(false);
    }
  );

  test('plain http is allowed only for allowlisted hosts with allowInsecure', () => {
    process.env[EGRESS_ALLOWED_HOSTS_ENV_VAR] = 'shuffle.example.com';
    expect(policyError('http://shuffle.example.com/hook').reason).toBe('scheme');
    expect(validateEgressUrl('http://shuffle.example.com/hook', { ...PURPOSE, allowInsecure: true }).url.protocol).toBe(
      'http:'
    );
    expect(policyError('http://other.example.com/hook', { ...PURPOSE, allowInsecure: true }).reason).toBe('allowlist');

    delete process.env[EGRESS_ALLOWED_HOSTS_ENV_VAR];
    // Without any allowlist nothing is "allowlisted", so http stays refused.
    expect(policyError('http://shuffle.example.com/hook', { ...PURPOSE, allowInsecure: true }).reason).toBe('scheme');
    // Local targets stay refused even when allowlisted and insecure is permitted.
    expect(
      policyError('http://10.0.0.5/hook', { purpose: 'X', allowedHosts: ['10.0.0.5'], allowInsecure: true }).reason
    ).toBe('host');
  });

  test('a local-suffix hostname is reachable only when allowlisted by name; loopback names never are', () => {
    expect(policyError('https://host.docker.internal/x').reason).toBe('host');
    expect(policyError('https://intel.corp.local/x').reason).toBe('host');
    process.env[EGRESS_ALLOWED_HOSTS_ENV_VAR] = 'host.docker.internal,app.localhost';
    expect(validateEgressUrl('https://host.docker.internal/x', PURPOSE).allowlisted).toBe(true);
    expect(validateEgressUrl('http://host.docker.internal:8080/x', { ...PURPOSE, allowInsecure: true }).url.port).toBe('8080');
    expect(policyError('https://intel.corp.local/x').reason).toBe('host');
    expect(policyError('https://other.example.com/x').reason).toBe('allowlist');
    expect(policyError('https://app.localhost/x').reason).toBe('host');
    expect(policyError('https://localhost/x', { purpose: 'X', allowedHosts: ['localhost'] }).reason).toBe('host');
    // A caller can opt out of the escape hatch (the AI base URL policy does).
    expect(policyError('https://host.docker.internal/x', { ...PURPOSE, refuseLocalHostnames: true }).reason).toBe('host');
    delete process.env[EGRESS_ALLOWED_HOSTS_ENV_VAR];
    expect(validateEgressUrl('https://hooks.example.com/x', PURPOSE).allowlisted).toBe(false);
  });

  test('EgressError carries code, reason and name', () => {
    const error = new EgressError('redirect', 'moved', { status: 302 });
    expect(error).toBeInstanceOf(Error);
    expect(error.name).toBe('EgressError');
    expect(error.code).toBe('redirect');
    expect(error.status).toBe(302);
    expect(error.reason).toBeUndefined();
  });
});
