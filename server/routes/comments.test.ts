import { listComments } from './comments';

describe('comment pagination', () => {
  test('paginates 201 comments without materializing an unbounded result', async () => {
    const hits = Array.from({ length: 201 }, (_, index) => ({
      _id: `comment-${index}`,
      _source: { event_type: 'comment', alert_id: 'a1', text: String(index), author: 'analyst', created_at: '2026-08-28T00:00:00Z' },
      sort: [index, `comment-${index}`],
    }));
    const search = jest
      .fn()
      .mockResolvedValueOnce({ body: { hits: { total: { value: 201, relation: 'eq' }, hits } } })
      .mockResolvedValueOnce({ body: { hits: { total: { value: 201, relation: 'eq' }, hits: [hits[200]] } } });

    const first = await listComments({ search } as any, { alertId: 'a1' });
    expect(search.mock.calls[0][0].body.sort).toEqual([
      { created_at: { order: 'asc' } },
      { _doc: { order: 'asc' } },
    ]);
    expect(JSON.stringify(search.mock.calls[0][0].body.sort)).not.toContain('_id');
    expect(first.comments).toHaveLength(200);
    expect(first).toEqual(expect.objectContaining({ total: 201, truncated: true }));
    expect(first.nextCursor).toEqual(expect.any(String));

    const second = await listComments({ search } as any, { alertId: 'a1' }, { cursor: first.nextCursor! });
    expect(second.comments.map((comment) => comment.id)).toEqual(['comment-200']);
    expect(second).toEqual(expect.objectContaining({ total: 201, truncated: false, nextCursor: null }));
    expect(search.mock.calls[1][0].body.search_after).toEqual([199, 'comment-199']);
    await expect(listComments({ search } as any, { caseId: 'a1' }, { cursor: first.nextCursor! })).rejects.toThrow(/mismatched/i);
  });
});
