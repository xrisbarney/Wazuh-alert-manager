import { API_ROOT, PLUGIN_VERSION, TARGET_OSD_VERSION } from '../../common';
import { defineSystemRoutes } from './system';
import { resetSavedObjectsBridgeStatus, setSavedObjectsBridgeStatus } from '../lib/saved_objects_bridge';

jest.mock('../lib/identity', () => ({ trustedIdentity: jest.fn() }));
const { trustedIdentity } = jest.requireMock('../lib/identity') as { trustedIdentity: jest.Mock };

const ANALYST = { name: 'analyst', source: 'security_plugin', roles: ['kibana_user'], securityRoles: ['kibana_user'], backendRoles: [] };
const ANONYMOUS = { name: 'dashboard_user', source: 'anonymous', roles: [], securityRoles: [], backendRoles: [] };
const ADMIN = { name: 'admin', source: 'security_plugin', roles: ['all_access'], securityRoles: ['all_access'], backendRoles: [] };

const FAILED_BRIDGE = {
  indexPatterns: 'error' as const,
  message: 'Discover/Reporting bridge failed (1 problem(s)): index-pattern/wam-cases: no permissions for [indices:data/write/index] on .kibana.',
  version: null,
  checkedAt: '2026-11-20T10:00:00.000Z',
  objects: { 'wam-alerts': 'created' as const, 'wam-cases': 'error' as const },
};

type Handler = (context: any, request: any, response: any) => Promise<any>;

function captureRoutes() {
  const handlers: Record<string, Handler> = {};
  const register = (config: any, handler: Handler) => {
    handlers[config.path] = handler;
  };
  const router: any = { get: register, post: register, put: register, delete: register, patch: register };
  defineSystemRoutes(router);
  return handlers;
}

const response = {
  ok: (payload: any) => ({ status: 200, ...payload }),
  customError: (payload: any) => ({ status: payload.statusCode, ...payload }),
  forbidden: (payload: any) => ({ status: 403, ...payload }),
  notFound: (payload: any) => ({ status: 404, ...payload }),
  badRequest: (payload: any) => ({ status: 400, ...payload }),
};

describe('GET /system/version', () => {
  beforeEach(() => {
    resetSavedObjectsBridgeStatus();
    trustedIdentity.mockReset();
    trustedIdentity.mockResolvedValue(ANALYST);
  });

  test('reports the build and the saved-objects bridge status (skipped before the bridge ran)', async () => {
    const handlers = captureRoutes();
    const result = await handlers[`${API_ROOT}/system/version`]({}, {}, response);
    expect(result.status).toBe(200);
    expect(result.headers['cache-control']).toContain('no-store');
    expect(result.body.pluginVersion).toBe(PLUGIN_VERSION);
    expect(result.body.targetOsdVersion).toBe(TARGET_OSD_VERSION);
    expect(result.body.savedObjectsBridge).toMatchObject({ indexPatterns: 'skipped', version: null, checkedAt: null, objects: {} });
    expect(typeof result.body.savedObjectsBridge.message).toBe('string');
  });

  test('gives plugin admins the detailed bridge outcome', async () => {
    trustedIdentity.mockResolvedValue(ADMIN);
    setSavedObjectsBridgeStatus(FAILED_BRIDGE);
    const handlers = captureRoutes();
    const result = await handlers[`${API_ROOT}/system/version`]({}, {}, response);
    expect(result.body.savedObjectsBridge).toEqual(FAILED_BRIDGE);
  });

  test.each([
    ['a non-admin user', ANALYST],
    ['an anonymous caller', ANONYMOUS],
  ])('redacts the error text and per-object map for %s', async (_label, identity) => {
    trustedIdentity.mockResolvedValue(identity);
    setSavedObjectsBridgeStatus(FAILED_BRIDGE);
    const handlers = captureRoutes();
    const result = await handlers[`${API_ROOT}/system/version`]({}, {}, response);
    const bridge = result.body.savedObjectsBridge;
    expect(bridge).toEqual({
      indexPatterns: 'error',
      message: expect.any(String),
      version: null,
      checkedAt: '2026-11-20T10:00:00.000Z',
      objects: {},
    });
    expect(bridge.message).not.toContain('.kibana');
    expect(bridge.message).not.toContain('no permissions');
    expect(bridge.message).not.toContain('wam-cases');
    expect(bridge.message).toContain('plugin administrator');
    // The build fields are unaffected by the redaction.
    expect(result.body.pluginVersion).toBe(PLUGIN_VERSION);
  });

  test('non-admins still learn the state when the bridge succeeded', async () => {
    setSavedObjectsBridgeStatus({ indexPatterns: 'ok', message: 'detailed: created 4, bridge version 15002', version: 15002, checkedAt: '2026-11-20T10:00:00.000Z', objects: { 'wam-alerts': 'created' } });
    const handlers = captureRoutes();
    const result = await handlers[`${API_ROOT}/system/version`]({}, {}, response);
    expect(result.body.savedObjectsBridge).toMatchObject({ indexPatterns: 'ok', version: 15002, objects: {} });
    expect(result.body.savedObjectsBridge.message).not.toContain('detailed');
  });
});
