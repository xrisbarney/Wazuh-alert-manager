import { API_ROOT, ACTIVITY_WRITE_ALIAS, META_INDEX } from '../../common';
import { defineAssetRoutes, parseLabelsParam } from './assets';
import { clearAssetContextCache, itHygieneAvailable } from '../lib/asset_context';
import { TARGET_WAZUH_MAJOR, TARGET_WAZUH_VERSION } from '../../common/build_info';

jest.mock('../lib/authorization', () => ({ requirePluginAdmin: jest.fn() }));
jest.mock('../lib/identity', () => ({ trustedIdentity: jest.fn(async () => ({ name: 'analyst', source: 'security_plugin', roles: [], securityRoles: [], backendRoles: [] })) }));

// eslint-disable-next-line @typescript-eslint/no-var-requires
const requirePluginAdmin: jest.Mock = require('../lib/authorization').requirePluginAdmin;
// eslint-disable-next-line @typescript-eslint/no-var-requires
const trustedIdentity: jest.Mock = require('../lib/identity').trustedIdentity;

function forbidden() {
  const error: any = new Error('Administrator permission is required for this operation.');
  error.statusCode = 403;
  throw error;
}

function clientWith(settings: any | null) {
  const writes: any[] = [];
  const client = {
    get: jest.fn(async (req: any) => {
      if (req.index === META_INDEX && settings !== null) return { body: { _source: settings } };
      throw Object.assign(new Error('not found'), { meta: { statusCode: 404 } });
    }),
    index: jest.fn(async (req: any) => {
      writes.push(req);
      if (req.index === META_INDEX) settings = req.body;
      return { body: { result: 'created' } };
    }),
    writes,
  };
  return client;
}

function response() {
  return {
    ok: jest.fn((r: any) => ({ kind: 'ok', ...r })),
    badRequest: jest.fn((r: any) => ({ kind: 'badRequest', ...r })),
    forbidden: jest.fn((r: any) => ({ kind: 'forbidden', ...r })),
    notFound: jest.fn((r: any) => ({ kind: 'notFound', ...r })),
    customError: jest.fn((r: any) => ({ kind: 'customError', ...r })),
  };
}

function routes() {
  const router: any = { get: jest.fn(), post: jest.fn(), put: jest.fn() };
  defineAssetRoutes(router);
  const find = (method: 'get' | 'put', path: string) => {
    const registration = router[method].mock.calls.find(([config]: any[]) => config.path === `${API_ROOT}${path}`);
    expect(registration).toBeDefined();
    return registration as [any, any];
  };
  return {
    getSettings: find('get', '/assets/settings'),
    putSettings: find('put', '/assets/settings'),
    resolve: find('get', '/assets/resolve'),
    context: find('get', '/assets/context'),
  };
}

const context = (client: any) => ({ core: { opensearch: { client: { asCurrentUser: client } } } });

const web = { id: 'web', match: { kind: 'glob', value: 'web-*' }, criticality: 'high', tags: ['pci'] };

describe('asset settings routes', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    requirePluginAdmin.mockResolvedValue({ name: 'admin', isPluginAdmin: true });
  });

  test('every route validates its request and is administrator-only', async () => {
    const { getSettings, putSettings, resolve } = routes();
    expect(getSettings[0].validate).toBe(false);
    expect(putSettings[0].validate.body).toBeDefined();
    expect(resolve[0].validate.query).toBeDefined();
    requirePluginAdmin.mockImplementation(forbidden);
    const client = clientWith(null);
    for (const [, handler] of [getSettings, putSettings, resolve]) {
      const res = response();
      const out = await handler(context(client), { body: { assets: [] }, query: {} }, res);
      expect(out.kind).toBe('forbidden');
    }
    expect(client.index).not.toHaveBeenCalled();
  });

  test('GET returns defaults when nothing is stored', async () => {
    const { getSettings } = routes();
    const out = await getSettings[1](context(clientWith(null)), {}, response());
    expect(out).toEqual({ kind: 'ok', body: { assets: [], updated_at: undefined, updated_by: undefined } });
  });

  test('PUT stores the list through the meta index and audits it', async () => {
    const { putSettings, getSettings } = routes();
    const client = clientWith(null);
    const out = await putSettings[1](context(client), { body: { assets: [web] } }, response());
    expect(out.kind).toBe('ok');
    expect(out.body.assets).toEqual([web]);
    expect(out.body.updated_by).toBe('admin');
    const meta = client.writes.find((w) => w.index === META_INDEX);
    expect(meta).toMatchObject({ id: 'asset_settings', refresh: 'wait_for' });
    const audit = client.writes.find((w) => w.index === ACTIVITY_WRITE_ALIAS);
    expect(audit.body).toMatchObject({ action: 'asset_settings_updated', user: 'admin', to: '1', target_id: 'asset_settings' });
    const read = await getSettings[1](context(client), {}, response());
    expect(read.body.assets).toEqual([web]);
  });

  test('PUT answers 400 on a semantic error and writes nothing', async () => {
    const { putSettings } = routes();
    const client = clientWith(null);
    const out = await putSettings[1](
      context(client),
      { body: { assets: [{ ...web, id: 'bad', match: { kind: 'label', value: 'no-key' } }] } },
      response()
    );
    expect(out.kind).toBe('badRequest');
    expect(out.body.message).toMatch(/key=value/);
    expect(client.index).not.toHaveBeenCalled();
  });

  test('resolve runs the matcher over name, csv groups and key=value labels', async () => {
    const { resolve } = routes();
    const client = clientWith({
      assets: [web, { id: 'dmz', match: { kind: 'group', value: 'dmz' }, criticality: 'critical', tags: [] },
        { id: 'prod', match: { kind: 'label', value: 'env=prod' }, criticality: 'low', tags: ['prod'] }],
    });
    const byName = await resolve[1](context(client), { query: { agentName: 'web-09' } }, response());
    expect(byName.body).toEqual({ criticality: 'high', tags: ['pci'], matchedId: 'web', matchedBy: 'glob' });
    const byGroup = await resolve[1](context(client), { query: { agentName: 'db', groups: 'default, dmz' } }, response());
    expect(byGroup.body).toMatchObject({ criticality: 'critical', matchedBy: 'group' });
    const byLabel = await resolve[1](context(client), { query: { labels: 'env=prod,tier=gold' } }, response());
    expect(byLabel.body).toMatchObject({ criticality: 'low', matchedBy: 'label', tags: ['prod'] });
    const none = await resolve[1](context(client), { query: { agentName: 'nothing' } }, response());
    expect(none.body).toEqual({ criticality: null, tags: [], matchedId: null, matchedBy: null });
  });

  test('parseLabelsParam', () => {
    expect(parseLabelsParam('env=prod, tier = gold ,bad,=x')).toEqual({ env: 'prod', tier: 'gold' });
    expect(parseLabelsParam('')).toBeNull();
    expect(parseLabelsParam(undefined)).toBeNull();
  });
});

describe('GET /assets/context (step 6.4b)', () => {
  beforeEach(() => clearAssetContextCache());

  function statesClient(error?: any) {
    return {
      search: jest.fn(async (req: any) => {
        if (error) throw error;
        return { body: { hits: { total: { value: 0, relation: 'eq' }, hits: [] } } };
      }),
      index: jest.fn(),
    };
  }

  test('validates the query shape and requires an agent id or name; never asks for admin', async () => {
    const { context: route } = routes();
    const [config, handler] = route;
    expect(config.validate.query).toBeDefined();
    // The schema itself: an unknown key and an empty id are refused before the handler runs.
    expect(() => config.validate.query.validate({ agentId: '001', extra: 'x' })).toThrow();
    expect(() => config.validate.query.validate({ agentId: '' })).toThrow();
    expect(config.validate.query.validate({ agentId: '001' })).toEqual({ agentId: '001' });
    const client = statesClient();
    const out = await handler(context(client), { query: {} }, response());
    expect(out.kind).toBe('badRequest');
    expect(out.body.message).toMatch(/agentId or agentName/);
    const blank = await handler(context(client), { query: { agentId: '  ' } }, response());
    expect(blank.kind).toBe('badRequest');
    expect(client.search).not.toHaveBeenCalled();
    expect(requirePluginAdmin).not.toHaveBeenCalled();
  });

  test('reads the states families as the current user and answers per-family statuses with deep links', async () => {
    const { context: route } = routes();
    const client = statesClient();
    const out = await route[1](context(client), { query: { agentId: '001', agentName: 'web-01' } }, response());
    expect(out.kind).toBe('ok');
    expect(out.body).toMatchObject({ agentId: '001', agentName: 'web-01', cached: false });
    expect(out.body.families.system).toEqual({ status: 'ok', os: null, hostname: null });
    // The route builds links from the BUILD target: a 4.12 build withholds the
    // IT Hygiene link (the app arrived in 4.13) and a 5.0 build withholds the
    // Configuration Assessment one, so assert what this build is meant to emit.
    const buildTarget = { major: TARGET_WAZUH_MAJOR, version: TARGET_WAZUH_VERSION };
    expect(out.body.links.itHygiene).toBe(
      itHygieneAvailable(buildTarget) ? '/app/it-hygiene#/overview/?tab=it-hygiene&tabView=dashboard&agentId=001' : null
    );
    expect(out.body.links.vulnerabilityDetection).toBe('/app/vulnerability-detection#/overview/?tab=vuls&tabView=dashboard&agentId=001');
    expect(out.body.links.configurationAssessment).toBe(
      Number(TARGET_WAZUH_MAJOR) === 4 ? '/app/configuration-assessment#/overview/?tab=sca&tabView=inventory&agentId=001' : null
    );
    // SCA is not indexed on the 4.x line; a 5.0 build reads the states family
    // and answers counts instead (the fixture holds no SCA documents).
    expect(out.body.families.sca).toEqual(
      Number(TARGET_WAZUH_MAJOR) === 4
        ? { status: 'not_available', reason: expect.stringMatching(/not indexed on Wazuh 4\.x/) }
        : { status: 'ok', total: 0, passed: 0, failed: 0 }
    );
    for (const call of client.search.mock.calls) expect(String(call[0].index)).toMatch(/^wazuh-states-/);
    expect(client.index).not.toHaveBeenCalled();
    const again = await route[1](context(client), { query: { agentId: '001', agentName: 'web-01' } }, response());
    expect(again.body.cached).toBe(true);
  });

  test('an anonymous identity (security plugin could not name the user) never shares a cache slot', async () => {
    const { context: route } = routes();
    const client = statesClient();
    trustedIdentity.mockResolvedValueOnce({ name: 'dashboard_user', source: 'anonymous', roles: [], securityRoles: [], backendRoles: [] });
    const first = await route[1](context(client), { query: { agentId: '001' } }, response());
    expect(first.body.cached).toBe(false);
    trustedIdentity.mockResolvedValueOnce({ name: 'dashboard_user', source: 'anonymous', roles: [], securityRoles: [], backendRoles: [] });
    const second = await route[1](context(client), { query: { agentId: '001' } }, response());
    expect(second.body.cached).toBe(false);
    expect(client.search.mock.calls.length).toBeGreaterThan(0);
  });

  test('a missing role grant is a no_access family, not a failed request', async () => {
    const { context: route } = routes();
    const client = statesClient(Object.assign(new Error('forbidden'), { meta: { statusCode: 403 } }));
    const out = await route[1](context(client), { query: { agentId: '001' } }, response());
    expect(out.kind).toBe('ok');
    expect(out.body.families.system).toEqual({ status: 'no_access' });
    expect(out.body.families.vulnerabilities).toEqual({ status: 'no_access' });
  });
});
