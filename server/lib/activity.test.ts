import { ACTIVITY_WRITE_ALIAS } from '../../common';
import { appendActivity, appendActivityOnce, getActivityEmitter, notifyActivityEmitter, registerActivityEmitter } from './activity';

function mockClient(options: { conflictOn?: string } = {}) {
  return {
    index: jest.fn(async ({ id }: any) => {
      if (options.conflictOn && id === options.conflictOn) throw Object.assign(new Error('conflict'), { meta: { statusCode: 409 } });
      return { body: { result: 'created' } };
    }),
  };
}

afterEach(() => registerActivityEmitter(null));

describe('activity emitter hook (step 1.3)', () => {
  test('without a registered emitter the writers behave exactly as before', async () => {
    expect(getActivityEmitter()).toBeNull();
    const client = mockClient();
    const doc = await appendActivity(client, { targetType: 'case', targetId: 'c-1', user: 'alice', action: 'case_created' });
    expect(client.index).toHaveBeenCalledWith(expect.objectContaining({ index: ACTIVITY_WRITE_ALIAS, id: doc.event_uid, body: doc }));
    await expect(notifyActivityEmitter(doc)).resolves.toBeUndefined();
  });

  test('a registered emitter is called once after a successful case write, with the stored document, never for other targets', async () => {
    const emitter = jest.fn(async () => {});
    registerActivityEmitter(emitter);
    expect(getActivityEmitter()).toBe(emitter);
    const client = mockClient();
    const doc = await appendActivity(client, { targetType: 'case', targetId: 'c-1', user: 'alice', action: 'assignment_change', from: null, to: 'bob' });
    expect(emitter).toHaveBeenCalledTimes(1);
    expect(emitter).toHaveBeenCalledWith(doc);
    expect((emitter.mock.calls[0] as any[])[0]).toEqual(expect.objectContaining({ target_type: 'case', case_id: 'c-1', action: 'assignment_change', to: 'bob' }));
    expect(client.index.mock.invocationCallOrder[0]).toBeLessThan(emitter.mock.invocationCallOrder[0]);

    await appendActivity(client, { targetType: 'alert', targetId: 'a-1', user: 'alice', action: 'status_change', to: 'closed' });
    await appendActivity(client, { targetType: 'system', targetId: 'report_run:x', user: 'scheduler', action: 'report_schedule_run' });
    await appendActivityOnce(client, 'rule-evt', { targetType: 'rule', targetId: 'r-1', user: 'alice', action: 'rule_updated' });
    expect(emitter).toHaveBeenCalledTimes(1);
  });

  test('appendActivityOnce calls the emitter after a create, not after a 409 (the first writer already did)', async () => {
    const emitter = jest.fn(async () => {});
    registerActivityEmitter(emitter);
    const client = mockClient({ conflictOn: 'dup' });
    const written = await appendActivityOnce(client, 'fresh', { targetType: 'case', targetId: 'c-1', user: 'automation', action: 'case_auto_created_evidence' });
    expect(written.event_uid).toBe('fresh');
    expect(emitter).toHaveBeenCalledWith(written);
    const replay = await appendActivityOnce(client, 'dup', { targetType: 'case', targetId: 'c-1', user: 'automation', action: 'case_auto_created_evidence' });
    expect(replay.event_uid).toBe('dup');
    expect(emitter).toHaveBeenCalledTimes(1);
  });

  test('a failing write never reaches the emitter; a throwing emitter never fails the write', async () => {
    const emitter = jest.fn(async () => { throw new Error('emitter down'); });
    registerActivityEmitter(emitter);
    const failing = { index: jest.fn(async () => { throw new Error('write failed'); }) };
    await expect(appendActivity(failing, { targetType: 'case', targetId: 'c-1', user: 'alice', action: 'case_created' })).rejects.toThrow('write failed');
    expect(emitter).not.toHaveBeenCalled();
    const client = mockClient();
    const doc = await appendActivity(client, { targetType: 'case', targetId: 'c-1', user: 'alice', action: 'case_created' });
    expect(doc.action).toBe('case_created');
    expect(emitter).toHaveBeenCalledTimes(1);
    const sync = jest.fn(() => { throw new Error('sync throw'); });
    registerActivityEmitter(sync);
    await expect(appendActivityOnce(client, 'once', { targetType: 'case', targetId: 'c-1', user: 'alice', action: 'case_created' })).resolves.toBeDefined();
    expect(sync).toHaveBeenCalledTimes(1);
  });
});
