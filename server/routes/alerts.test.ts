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

describe('related alert linking', () => {
  const ALERT_INDEX = 'wazuh-alert-status-v2-000001';

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
