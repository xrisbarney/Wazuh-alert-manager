import { API_ROOT } from '../../common';
import { buildAlertCountSearchBody, buildAlertListSearchBody, defineAlertRoutes } from './alerts';

jest.mock('../lib/opensearch', () => ({
  ...jest.requireActual('../lib/opensearch'),
  getCurrentUsername: jest.fn(async () => 'analyst'),
}));

describe('alert route exact totals', () => {
  test('requests exact total hits for the paged Workbench queue', () => {
    const body = buildAlertListSearchBody({
      from_offset: 20, size: 20, sortField: '@timestamp', sortDirection: 'desc',
      statuses: 'open',
    });

    expect(body.track_total_hits).toBe(true);
    expect(body.from).toBe(20);
    expect(body.size).toBe(20);
  });

  test('requests exact total hits for summary counts', () => {
    const body = buildAlertCountSearchBody({ from: '2026-08-29T00:00:00.000Z' });

    expect(body.track_total_hits).toBe(true);
    expect(body.size).toBe(0);
    expect(body.aggs.status_counts.terms.field).toBe('status');
  });
});

const ALERT_INDEX = 'wazuh-alert-status-v2-000001';
const alertSearch = (ids: string[]) => jest.fn(async () => ({
  body: { hits: { hits: ids.map((id) => ({ _id: id, _index: ALERT_INDEX, _source: { status: 'open' } })) } },
}));
const handlerFor = (method: 'get' | 'post' | 'put', path: string) => {
  const router: any = { get: jest.fn(), post: jest.fn(), put: jest.fn() };
  defineAlertRoutes(router);
  const registration = router[method].mock.calls.find(([config]: any[]) => config.path === `${API_ROOT}${path}`);
  expect(registration).toBeDefined();
  return registration![1];
};

describe('alert bulk update', () => {
  test('waits for status and assignment changes to be searchable before responding', async () => {
    const handler = handlerFor('post', '/alerts/bulk-update');
    const client = {
      search: alertSearch(['a1', 'a2']),
      // Per alert: the alert update plus its activity-log entry.
      bulk: jest.fn(async () => ({ body: { items: Array.from({ length: 4 }, () => ({ update: { status: 200 } })) } })),
    };
    const ok = jest.fn((value: any) => value);
    const customError = jest.fn((value: any) => value);

    await handler(
      { core: { opensearch: { client: { asCurrentUser: client } } } },
      { body: { ids: ['a1', 'a2'], status: 'in_progress', assignedTo: 'tier-2' } },
      { ok, customError, badRequest: jest.fn() }
    );

    expect(customError).not.toHaveBeenCalled();
    expect(ok).toHaveBeenCalledWith({ body: { requested: 2, updated: 2 } });
    const request = client.bulk.mock.calls[0][0] as any;
    expect(request.refresh).toBe('wait_for');
    expect(request.body[0]).toEqual({ update: { _index: ALERT_INDEX, _id: 'a1' } });
    expect(request.body[1].script.params.fields).toEqual(expect.objectContaining({ status: 'in_progress', assigned_to: 'tier-2', updated_by: 'analyst' }));
  });
});

describe('related alert linking', () => {

  test('waits for the link to be searchable so the panel re-read shows it (issue #11)', async () => {
    const router: any = { get: jest.fn(), post: jest.fn(), put: jest.fn() };
    defineAlertRoutes(router);
    const registration = router.post.mock.calls.find(([config]: any[]) => config.path === `${API_ROOT}/alerts/{id}/related`);
    expect(registration).toBeDefined();
    const handler = registration![1];

    const client = {
      search: jest.fn(async () => ({
        body: { hits: { hits: ['a1', 'a2'].map((id) => ({ _id: id, _index: ALERT_INDEX, _source: {} })) } },
      })),
      bulk: jest.fn(async () => ({ body: { items: [{ update: { status: 200 } }, { update: { status: 200 } }, { update: { status: 200 } }] } })),
    };
    const ok = jest.fn((value: any) => value);
    const customError = jest.fn((value: any) => value);

    await handler(
      { core: { opensearch: { client: { asCurrentUser: client } } } },
      { params: { id: 'a1' }, body: { relatedIds: ['a2'], mode: 'add' } },
      { ok, customError, badRequest: jest.fn(), notFound: jest.fn() }
    );

    expect(customError).not.toHaveBeenCalled();
    expect(ok).toHaveBeenCalledWith({ body: { updated: true, alertsUpdated: 2 } });
    const request = client.bulk.mock.calls[0][0] as any;
    expect(request.refresh).toBe('wait_for');
    expect(request.body[0]).toEqual({ update: { _index: ALERT_INDEX, _id: 'a1' } });
    expect(request.body[4]).toEqual({ update: { _index: ALERT_INDEX, _id: 'a2' } });
  });
});
