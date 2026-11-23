import { Readable } from 'stream';
import { ReadableStream } from 'stream/web';

import {
  DEFAULT_EGRESS_TIMEOUT_MS,
  DEFAULT_MAX_RESPONSE_BYTES,
  EgressError,
  MAX_EGRESS_TIMEOUT_MS,
  boundedFetch,
  isEgressError,
} from './http';
import { EGRESS_ALLOWED_HOSTS_ENV_VAR } from './url_policy';

jest.mock('dns', () => ({ promises: { lookup: jest.fn() } }));
jest.mock('https', () => ({ request: jest.fn() }));
// eslint-disable-next-line @typescript-eslint/no-var-requires
const dnsLookup: jest.Mock = require('dns').promises.lookup;
// eslint-disable-next-line @typescript-eslint/no-var-requires
const httpsRequest: jest.Mock = require('https').request;

/** Fake `https.request` answer: a Node-style readable with status and headers. */
function fakeHttpsResponse(status: number, headers: Record<string, string>, body: string) {
  const res = Readable.from([Buffer.from(body, 'utf8')]) as any;
  res.statusCode = status;
  res.headers = headers;
  return res;
}

type FetchMock = jest.Mock<Promise<unknown>, [string, RequestInit]>;

function fakeHeaders(values: Record<string, string>) {
  const lower: Record<string, string> = {};
  for (const [key, value] of Object.entries(values)) lower[key.toLowerCase()] = value;
  return {
    get: (name: string) => (name.toLowerCase() in lower ? lower[name.toLowerCase()] : null),
    forEach: (cb: (value: string, key: string) => void) => {
      for (const [key, value] of Object.entries(lower)) cb(value, key);
    },
  };
}

function bytes(text: string): Uint8Array {
  return new Uint8Array(Buffer.from(text, 'utf8'));
}

function streamOf(chunks: Uint8Array[], onCancel?: () => void) {
  let index = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (index < chunks.length) controller.enqueue(chunks[index++]);
      else controller.close();
    },
    cancel() {
      if (onCancel) onCancel();
    },
  });
}

function fakeResponse(
  status: number,
  headers: Record<string, string>,
  body: ReadableStream<Uint8Array> | null
) {
  return { status, headers: fakeHeaders(headers), body };
}

async function expectEgressError(promise: Promise<unknown>): Promise<EgressError> {
  try {
    await promise;
  } catch (e) {
    expect(isEgressError(e)).toBe(true);
    return e as EgressError;
  }
  throw new Error('expected boundedFetch to reject');
}

describe('boundedFetch', () => {
  const realFetch = (global as any).fetch;
  let fetchMock: FetchMock;

  beforeEach(() => {
    delete process.env[EGRESS_ALLOWED_HOSTS_ENV_VAR];
    fetchMock = jest.fn();
    (global as any).fetch = fetchMock;
    httpsRequest.mockReset();
    dnsLookup.mockReset();
    dnsLookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }]);
  });

  afterAll(() => {
    (global as any).fetch = realFetch;
  });

  test('exposes the documented defaults', () => {
    expect(DEFAULT_EGRESS_TIMEOUT_MS).toBe(10000);
    expect(MAX_EGRESS_TIMEOUT_MS).toBe(60000);
    expect(DEFAULT_MAX_RESPONSE_BYTES).toBe(1024 * 1024);
  });

  test('returns status, lower-cased headers and the decoded body', async () => {
    fetchMock.mockResolvedValue(
      fakeResponse(201, { 'Content-Type': 'application/json', 'X-Request-Id': 'abc' }, streamOf([bytes('{"ok":'), bytes('true}')]))
    );

    const result = await boundedFetch('https://hooks.example.com/notify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{"hello":"world"}',
    });

    expect(result).toEqual({
      status: 201,
      headers: { 'content-type': 'application/json', 'x-request-id': 'abc' },
      bodyText: '{"ok":true}',
      truncated: false,
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://hooks.example.com/notify');
    expect(init.method).toBe('POST');
    expect(init.headers).toEqual({ 'content-type': 'application/json' });
    expect(init.body).toBe('{"hello":"world"}');
    expect(init.redirect).toBe('manual');
    expect(init.signal).toBeDefined();
    expect((init.signal as AbortSignal).aborted).toBe(false);
  });

  test('defaults to GET and tolerates a missing body', async () => {
    fetchMock.mockResolvedValue(fakeResponse(204, {}, null));
    const result = await boundedFetch('https://api.example.com/ping');
    expect(result.status).toBe(204);
    expect(result.bodyText).toBe('');
    expect(fetchMock.mock.calls[0][1].method).toBe('GET');
  });

  test('refuses policy violations before touching the network', async () => {
    for (const url of ['http://hooks.example.com/', 'https://127.0.0.1/', 'https://localhost:5601/', 'https://[::1]/']) {
      const error = await expectEgressError(boundedFetch(url, { purpose: 'Webhook URL' }));
      expect(error.code).toBe('policy');
    }
    process.env[EGRESS_ALLOWED_HOSTS_ENV_VAR] = 'allowed.example.com';
    const error = await expectEgressError(boundedFetch('https://other.example.com/'));
    expect(error.code).toBe('policy');
    expect(error.reason).toBe('allowlist');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test('resolves the hostname with the system lookup before connecting', async () => {
    fetchMock.mockResolvedValue(fakeResponse(200, {}, streamOf([bytes('ok')])));
    await boundedFetch('https://hooks.example.com/');
    expect(dnsLookup).toHaveBeenCalledWith('hooks.example.com', { all: true });
  });

  test.each([
    [['127.0.0.1']],
    [['10.0.0.5']],
    [['169.254.169.254']],
    [['::1']],
    [['::ffff:192.168.1.1']],
    [['fd00::1']],
    // one public and one private record: still refused
    [['93.184.216.34', '10.0.0.5']],
  ])('refuses a hostname that resolves to %j without touching the network', async (addresses) => {
    const resolve = jest.fn(async () => addresses);
    const error = await expectEgressError(boundedFetch('https://127.0.0.1.nip.io/', { purpose: 'Webhook URL', resolve }));
    expect(error.code).toBe('policy');
    expect(error.reason).toBe('host');
    expect(error.host).toBe('127.0.0.1.nip.io');
    expect(error.message).toContain('Webhook URL host 127.0.0.1.nip.io resolves to a private or local address');
    expect(resolve).toHaveBeenCalledWith('127.0.0.1.nip.io');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test('a hostname that resolves to public addresses is fetched', async () => {
    fetchMock.mockResolvedValue(fakeResponse(200, {}, streamOf([bytes('ok')])));
    const resolve = jest.fn(async () => ['93.184.216.34', '2606:2800:220:1:248:1893:25c8:1946']);
    const result = await boundedFetch('https://hooks.example.com/', { resolve });
    expect(result.bodyText).toBe('ok');
    expect(dnsLookup).not.toHaveBeenCalled();
  });

  test('the deadline also covers a hanging resolver', async () => {
    const resolve = jest.fn(() => new Promise<string[]>(() => undefined));
    const error = await expectEgressError(boundedFetch('https://slow.example.com/', { timeoutMs: 30, resolve }));
    expect(error.code).toBe('timeout');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test('a hostname that does not resolve is a network error', async () => {
    const resolve = jest.fn(async () => {
      throw new Error('getaddrinfo ENOTFOUND nope.example.com');
    });
    const error = await expectEgressError(boundedFetch('https://nope.example.com/', { resolve }));
    expect(error.code).toBe('network');
    expect(error.message).toContain('ENOTFOUND');
    expect(fetchMock).not.toHaveBeenCalled();

    const empty = await expectEgressError(boundedFetch('https://nope.example.com/', { resolve: async () => [] }));
    expect(empty.code).toBe('network');
  });

  test('an allowlisted local-suffix name skips the resolved-address check (operator opt-in for private receivers)', async () => {
    fetchMock.mockImplementation(async () => fakeResponse(200, {}, streamOf([bytes('ok')])));
    const resolve = jest.fn(async () => ['10.0.0.5']);
    const explicit = await boundedFetch('http://intel.corp.internal/', { allowedHosts: ['intel.corp.internal'], allowInsecure: true, resolve });
    expect(explicit.bodyText).toBe('ok');
    expect(resolve).not.toHaveBeenCalled();

    process.env[EGRESS_ALLOWED_HOSTS_ENV_VAR] = 'host.docker.internal';
    const viaEnv = await boundedFetch('https://host.docker.internal/', { resolve });
    expect(viaEnv.bodyText).toBe('ok');
    expect(resolve).not.toHaveBeenCalled();
    expect(dnsLookup).not.toHaveBeenCalled();
  });

  test('an allowlisted public name keeps the resolved-address check (the allowlist never widens the address policy)', async () => {
    fetchMock.mockImplementation(async () => fakeResponse(200, {}, streamOf([bytes('ok')])));
    const resolve = jest.fn(async () => ['10.0.0.5']);

    // Explicit caller allowlist, public-looking name resolving privately.
    const explicit = await expectEgressError(
      boundedFetch('http://intel.internal.example/', { allowedHosts: ['intel.internal.example'], allowInsecure: true, resolve })
    );
    expect(explicit.code).toBe('policy');
    expect(explicit.reason).toBe('host');
    expect(explicit.host).toBe('intel.internal.example');

    // Operator allowlist narrowed to a public source whose DNS record points at 10.x.
    process.env[EGRESS_ALLOWED_HOSTS_ENV_VAR] = 'api.abuseipdb.com,host.docker.internal';
    const viaEnv = await expectEgressError(boundedFetch('https://api.abuseipdb.com/api/v2/check', { resolve }));
    expect(viaEnv.reason).toBe('host');
    expect(viaEnv.message).toContain('api.abuseipdb.com resolves to a private or local address (10.0.0.5)');
    expect(fetchMock).not.toHaveBeenCalled();

    // The same listed public name is fetched once it resolves publicly.
    const publicResolve = jest.fn(async () => ['93.184.216.34']);
    const ok = await boundedFetch('https://api.abuseipdb.com/api/v2/check', { resolve: publicResolve });
    expect(ok.bodyText).toBe('ok');
    expect(publicResolve).toHaveBeenCalledWith('api.abuseipdb.com');
  });

  describe('allowInsecure over https', () => {
    function answerWith(status: number, headers: Record<string, string>, body: string) {
      httpsRequest.mockImplementation((options: any, cb: (res: any) => void) => {
        const req: any = { on: jest.fn(), write: jest.fn(), end: jest.fn(() => cb(fakeHttpsResponse(status, headers, body))) };
        return req;
      });
    }

    test('skips certificate verification for an allowlisted local-suffix name (lab MISP behind misp.internal)', async () => {
      answerWith(200, { 'content-type': 'application/json' }, '{"ok":true}');
      process.env[EGRESS_ALLOWED_HOSTS_ENV_VAR] = 'host.docker.internal,misp.internal';
      const result = await boundedFetch('https://misp.internal:8445/attributes/restSearch', {
        method: 'POST',
        headers: { Authorization: 'k' },
        body: '{}',
        allowInsecure: true,
      });
      expect(result.status).toBe(200);
      expect(result.bodyText).toBe('{"ok":true}');
      expect(result.headers['content-type']).toBe('application/json');
      expect(fetchMock).not.toHaveBeenCalled();
      expect(dnsLookup).not.toHaveBeenCalled();
      expect(httpsRequest).toHaveBeenCalledTimes(1);
      expect(httpsRequest.mock.calls[0][0]).toMatchObject({
        hostname: 'misp.internal',
        port: '8445',
        path: '/attributes/restSearch',
        method: 'POST',
        headers: { Authorization: 'k' },
        rejectUnauthorized: false,
      });
      const req = httpsRequest.mock.results[0].value;
      expect(req.write).toHaveBeenCalledWith('{}');
    });

    test('still refuses a redirect and caps the body on the unverified path', async () => {
      process.env[EGRESS_ALLOWED_HOSTS_ENV_VAR] = 'misp.internal';
      answerWith(302, { location: 'https://evil.example.net/' }, 'moved');
      const redirect = await expectEgressError(boundedFetch('https://misp.internal/', { allowInsecure: true }));
      expect(redirect.code).toBe('redirect');

      answerWith(200, {}, 'x'.repeat(64));
      const big = await expectEgressError(boundedFetch('https://misp.internal/', { allowInsecure: true, maxResponseBytes: 16 }));
      expect(big.code).toBe('too_large');
    });

    test('keeps verified TLS without the switch, for a public allowlisted host, and for an unlisted local name', async () => {
      fetchMock.mockImplementation(async () => fakeResponse(200, {}, streamOf([bytes('ok')])));
      process.env[EGRESS_ALLOWED_HOSTS_ENV_VAR] = 'misp.internal,api.abuseipdb.com';

      // Same receiver, switch off: the verified fetch path.
      const verified = await boundedFetch('https://misp.internal:8445/', {});
      expect(verified.bodyText).toBe('ok');
      expect(httpsRequest).not.toHaveBeenCalled();

      // A public allowlisted host never gets the unverified path, switch or not.
      const publicHost = await boundedFetch('https://api.abuseipdb.com/api/v2/check', { allowInsecure: true });
      expect(publicHost.bodyText).toBe('ok');
      expect(httpsRequest).not.toHaveBeenCalled();
      expect(dnsLookup).toHaveBeenCalledWith('api.abuseipdb.com', { all: true });

      // A local-suffix name that is not allowlisted is refused before any transport.
      const unlisted = await expectEgressError(boundedFetch('https://other.internal/', { allowInsecure: true }));
      expect(unlisted.code).toBe('policy');
      expect(httpsRequest).not.toHaveBeenCalled();
    });
  });

  test('passes explicit allowedHosts and allowInsecure through to the policy', async () => {
    fetchMock.mockResolvedValue(fakeResponse(200, {}, streamOf([bytes('ok')])));
    const result = await boundedFetch('http://shuffle.example.com/hook', {
      allowedHosts: ['shuffle.example.com'],
      allowInsecure: true,
    });
    expect(result.bodyText).toBe('ok');
    expect(fetchMock.mock.calls[0][0]).toBe('http://shuffle.example.com/hook');
  });

  test.each([301, 302, 307, 308])('treats a %s redirect as an error and does not follow it', async (status) => {
    const cancelled = jest.fn();
    fetchMock.mockResolvedValue(
      fakeResponse(status, { location: 'https://evil.example.net/' }, streamOf([bytes('moved')], cancelled))
    );

    const error = await expectEgressError(boundedFetch('https://hooks.example.com/'));
    expect(error.code).toBe('redirect');
    expect(error.status).toBe(status);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect((fetchMock.mock.calls[0][1].signal as AbortSignal).aborted).toBe(true);
  });

  test('aborts once the streamed body exceeds maxResponseBytes', async () => {
    const cancelled = jest.fn();
    let pulls = 0;
    const endless = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulls += 1;
        controller.enqueue(new Uint8Array(100));
      },
      cancel() {
        cancelled();
      },
    });
    fetchMock.mockResolvedValue(fakeResponse(200, {}, endless));

    const error = await expectEgressError(boundedFetch('https://big.example.com/', { maxResponseBytes: 350 }));
    expect(error.code).toBe('too_large');
    expect(error.status).toBe(200);
    expect(error.message).toContain('350');
    // 4 chunks of 100 bytes cross the 350-byte cap; the stream is not drained.
    expect(pulls).toBeLessThanOrEqual(5);
    expect(cancelled).toHaveBeenCalled();
    expect((fetchMock.mock.calls[0][1].signal as AbortSignal).aborted).toBe(true);
  });

  test('accepts a body exactly at the cap', async () => {
    fetchMock.mockResolvedValue(fakeResponse(200, {}, streamOf([bytes('abc'), bytes('def')])));
    const result = await boundedFetch('https://api.example.com/', { maxResponseBytes: 6 });
    expect(result.bodyText).toBe('abcdef');
  });

  test('rejects early when content-length already exceeds the cap', async () => {
    const cancelled = jest.fn();
    fetchMock.mockResolvedValue(fakeResponse(200, { 'content-length': '5000' }, streamOf([bytes('x')], cancelled)));
    const error = await expectEgressError(boundedFetch('https://api.example.com/', { maxResponseBytes: 1000 }));
    expect(error.code).toBe('too_large');
    expect((fetchMock.mock.calls[0][1].signal as AbortSignal).aborted).toBe(true);
  });

  test('times out a request that never answers', async () => {
    fetchMock.mockImplementation(
      (_url, init) =>
        new Promise((_resolve, reject) => {
          init.signal!.addEventListener('abort', () => {
            const abortError = new Error('This operation was aborted');
            abortError.name = 'AbortError';
            reject(abortError);
          });
        })
    );

    const started = Date.now();
    const error = await expectEgressError(boundedFetch('https://slow.example.com/', { timeoutMs: 30 }));
    expect(error.code).toBe('timeout');
    expect(error.message).toContain('30 ms');
    expect(Date.now() - started).toBeLessThan(5000);
  });

  test('times out while the body is still streaming', async () => {
    fetchMock.mockImplementation(async (_url, init) => {
      const signal = init.signal as AbortSignal;
      const stalled = new ReadableStream<Uint8Array>({
        pull(controller) {
          controller.enqueue(bytes('partial'));
          return new Promise<void>((_resolve, reject) => {
            signal.addEventListener('abort', () => reject(new Error('aborted')));
          });
        },
      });
      return fakeResponse(200, {}, stalled);
    });

    const error = await expectEgressError(boundedFetch('https://slow.example.com/', { timeoutMs: 30 }));
    expect(error.code).toBe('timeout');
  });

  test('clamps the timeout to the maximum and falls back to the default', async () => {
    fetchMock.mockImplementation(
      (_url, init) =>
        new Promise((_resolve, reject) => {
          init.signal!.addEventListener('abort', () => reject(new Error('aborted')));
        })
    );
    jest.useFakeTimers();
    try {
      const over = expectEgressError(boundedFetch('https://slow.example.com/', { timeoutMs: 600000 }));
      jest.advanceTimersByTime(MAX_EGRESS_TIMEOUT_MS);
      expect((await over).message).toContain(`${MAX_EGRESS_TIMEOUT_MS} ms`);

      const bad = expectEgressError(boundedFetch('https://slow.example.com/', { timeoutMs: -1 }));
      jest.advanceTimersByTime(DEFAULT_EGRESS_TIMEOUT_MS);
      expect((await bad).message).toContain(`${DEFAULT_EGRESS_TIMEOUT_MS} ms`);
    } finally {
      jest.useRealTimers();
    }
  });

  test('maps transport failures to a network error', async () => {
    fetchMock.mockRejectedValue(new Error('getaddrinfo ENOTFOUND hooks.example.com'));
    const error = await expectEgressError(boundedFetch('https://hooks.example.com/'));
    expect(error.code).toBe('network');
    expect(error.message).toContain('ENOTFOUND');
  });

  test('maps a failing body stream to a network error', async () => {
    const broken = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.error(new Error('socket hang up'));
      },
    });
    fetchMock.mockResolvedValue(fakeResponse(200, {}, broken));
    const error = await expectEgressError(boundedFetch('https://hooks.example.com/'));
    expect(error.code).toBe('network');
    expect(error.message).toContain('socket hang up');
  });
});
