import {
  READ_ONLY_NATIVE_PATTERNS,
  assertNativeReadPattern,
  countNative,
  isNoAccessError,
  isNotAvailableError,
  searchNative,
} from './native_read';

function searchResponse(hits: any[], total = hits.length, aggregations?: any) {
  return {
    body: {
      hits: { total: { value: total, relation: 'eq' }, hits },
      ...(aggregations ? { aggregations } : {}),
    },
  };
}

function clientThatThrows(error: any) {
  return {
    search: jest.fn(async () => {
      throw error;
    }),
    count: jest.fn(async () => {
      throw error;
    }),
    index: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
    bulk: jest.fn(),
  };
}

describe('native read helper', () => {
  test('allowlist covers the states and threat-intel enrichment families only', () => {
    expect(READ_ONLY_NATIVE_PATTERNS).toEqual(['wazuh-states-', 'wazuh-threatintel-enrichments']);
  });

  test('accepts explicit names and trailing-wildcard patterns inside the allowlist', () => {
    for (const ok of [
      'wazuh-states-inventory-system*',
      'wazuh-states-inventory-system-*',
      'wazuh-states-vulnerabilities*',
      'wazuh-states-sca',
      'wazuh-threatintel-enrichments*',
      'wazuh-threatintel-enrichments',
      ' wazuh-states-inventory-ports* ',
    ]) {
      expect(assertNativeReadPattern(ok)).toBe(ok.trim());
    }
  });

  test('refuses patterns outside the allowlist', () => {
    for (const bad of [
      'wazuh-alerts-*',
      'wazuh-alerts-4.x-2026.11.20',
      'wazuh-findings-v5-security',
      '.ds-wazuh-findings-v5-security-000001',
      'wazuh-threatintel-',
      'wazuh-threatintel-other*',
      '.wazuh-cti-catalog',
      'wazuh-active-responses',
      'wazuh-case-management-cases',
      'wazuh-monitoring-*',
      '.opendistro_security',
      '.kibana_1',
      'wazuh-states',
      'wazuh-state-*',
    ]) {
      expect(() => assertNativeReadPattern(bad)).toThrow(/outside the read-only allowlist|Unsafe native read pattern/);
    }
  });

  test('refuses wildcards, multi-target strings, exclusions and path characters', () => {
    for (const bad of [
      '',
      '*',
      '_all',
      'wazuh-states-*,wazuh-alerts-*',
      'wazuh-states-inventory-*,*',
      '-wazuh-states-*',
      'wazuh-states-**',
      '*wazuh-states-',
      'wazuh-states-*-system',
      'WAZUH-STATES-*',
      'wazuh-states-sca/_doc',
      'wazuh-states-<x>',
      'wazuh-states-sca x',
    ]) {
      expect(() => assertNativeReadPattern(bad)).toThrow(/explicit|Unsafe native read pattern/);
    }
  });

  test('refuses plugin storage even if the allowlist were widened', () => {
    READ_ONLY_NATIVE_PATTERNS.push('wazuh-alert-');
    try {
      expect(() => assertNativeReadPattern('wazuh-alert-status-v2-*')).toThrow(/overlaps plugin storage/);
      expect(() => assertNativeReadPattern('wazuh-alert-manager-v2-meta')).toThrow(/overlaps plugin storage/);
    } finally {
      READ_ONLY_NATIVE_PATTERNS.pop();
    }
  });

  test('searchNative returns hits and total, and only ever calls search', async () => {
    const hit = { _id: 'a1', _index: 'wazuh-states-inventory-system-default', _source: { agent: { id: '001' } } };
    const client = {
      search: jest.fn(async () => searchResponse([hit], 1, { os: { buckets: [] } })),
      index: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
      bulk: jest.fn(),
    };
    const body = { size: 1, query: { term: { 'agent.id': '001' } } };
    const result = await searchNative(client, {
      indexPattern: 'wazuh-states-inventory-system*',
      body,
      purpose: 'asset-context',
    });
    expect(result).toEqual({ status: 'ok', hits: [hit], total: 1, aggregations: { os: { buckets: [] } } });
    expect(client.search).toHaveBeenCalledTimes(1);
    expect(client.search).toHaveBeenCalledWith({ index: 'wazuh-states-inventory-system*', body });
    expect(client.index).not.toHaveBeenCalled();
    expect(client.update).not.toHaveBeenCalled();
    expect(client.delete).not.toHaveBeenCalled();
    expect(client.bulk).not.toHaveBeenCalled();
  });

  test('searchNative tolerates a legacy numeric total and empty hits', async () => {
    const client = { search: jest.fn(async () => ({ body: { hits: { total: 0, hits: [] } } })) };
    const result = await searchNative(client, {
      indexPattern: 'wazuh-threatintel-enrichments*',
      body: { query: { match_all: {} } },
      purpose: 'cti-local',
    });
    expect(result).toEqual({ status: 'ok', hits: [], total: 0 });
  });

  test('searchNative refuses a pattern outside the allowlist before calling the client', async () => {
    const client = { search: jest.fn() };
    await expect(
      searchNative(client, { indexPattern: 'wazuh-alerts-*', body: {}, purpose: 'bad' })
    ).rejects.toThrow(/outside the read-only allowlist/);
    expect(client.search).not.toHaveBeenCalled();
  });

  test('403 becomes no_access', async () => {
    const client = clientThatThrows({ meta: { statusCode: 403 }, message: 'forbidden' });
    expect(await searchNative(client, { indexPattern: 'wazuh-states-sca', body: {}, purpose: 'x' })).toEqual({
      status: 'no_access',
    });
    expect(await countNative(client, { indexPattern: 'wazuh-states-sca', body: {}, purpose: 'x' })).toEqual({
      status: 'no_access',
    });
  });

  test('security_exception without a status code becomes no_access', async () => {
    const client = clientThatThrows({ body: { error: { type: 'security_exception' } }, message: 'no permissions' });
    expect(await searchNative(client, { indexPattern: 'wazuh-states-sca', body: {}, purpose: 'x' })).toEqual({
      status: 'no_access',
    });
  });

  test('404 and index_not_found_exception become not_available', async () => {
    const by404 = clientThatThrows({ meta: { statusCode: 404 }, message: 'not found' });
    expect(await searchNative(by404, { indexPattern: 'wazuh-states-sca', body: {}, purpose: 'x' })).toEqual({
      status: 'not_available',
    });
    expect(await countNative(by404, { indexPattern: 'wazuh-states-sca', body: {}, purpose: 'x' })).toEqual({
      status: 'not_available',
    });
    const byType = clientThatThrows({
      meta: { body: { error: { type: 'index_not_found_exception' } } },
      message: 'no such index',
    });
    expect(await searchNative(byType, { indexPattern: 'wazuh-states-sca', body: {}, purpose: 'x' })).toEqual({
      status: 'not_available',
    });
  });

  test('other failures are rethrown', async () => {
    const error = { meta: { statusCode: 503 }, message: 'cluster unavailable' };
    const client = clientThatThrows(error);
    await expect(
      searchNative(client, { indexPattern: 'wazuh-states-sca', body: {}, purpose: 'x' })
    ).rejects.toBe(error);
    await expect(countNative(client, { indexPattern: 'wazuh-states-sca', body: {}, purpose: 'x' })).rejects.toBe(
      error
    );
  });

  test('countNative returns the count and only ever calls count', async () => {
    const client = {
      count: jest.fn(async () => ({ body: { count: 42 } })),
      search: jest.fn(),
      index: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
    };
    const body = { query: { term: { 'vulnerability.severity': 'Critical' } } };
    const result = await countNative(client, {
      indexPattern: 'wazuh-states-vulnerabilities*',
      body,
      purpose: 'asset-context',
    });
    expect(result).toEqual({ status: 'ok', total: 42 });
    expect(client.count).toHaveBeenCalledWith({ index: 'wazuh-states-vulnerabilities*', body });
    expect(client.search).not.toHaveBeenCalled();
    expect(client.index).not.toHaveBeenCalled();
    expect(client.update).not.toHaveBeenCalled();
    expect(client.delete).not.toHaveBeenCalled();
  });

  test('error classifiers read both client error shapes', () => {
    expect(isNoAccessError({ statusCode: 403 })).toBe(true);
    expect(isNoAccessError({ meta: { statusCode: 404 } })).toBe(false);
    expect(isNotAvailableError({ statusCode: 404 })).toBe(true);
    expect(isNotAvailableError({ body: { error: { type: 'index_not_found_exception' } } })).toBe(true);
    expect(isNotAvailableError({ meta: { statusCode: 500 } })).toBe(false);
    expect(isNoAccessError(undefined)).toBe(false);
    expect(isNotAvailableError(null)).toBe(false);
  });
});
