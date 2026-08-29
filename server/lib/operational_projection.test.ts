import { alertUid, legacyAlertUid, projectOperationalAlert } from './operational_projection';

describe('operational alert projection', () => {
  test('uses source index and id for stable collision-safe identity', () => {
    expect(alertUid('wazuh-alerts-a', 'same')).toBe(alertUid('wazuh-alerts-a', 'same'));
    expect(alertUid('wazuh-alerts-a', 'same')).not.toBe(alertUid('wazuh-alerts-b', 'same'));
    expect(legacyAlertUid('same')).not.toBe(alertUid('wazuh-alerts-a', 'same'));
  });

  test('allowlists operational fields and drops arbitrary source data', () => {
    const doc = projectOperationalAlert({
      _index: 'wazuh-alerts-4.x-2026.08.28',
      _id: 'abc',
      _source: {
        '@timestamp': '2026-08-28T00:00:00.000Z',
        agent: { id: '001', name: 'host', ip: '10.0.0.2' },
        rule: { id: '5502', level: 5, groups: 'syslog', description: 'test' },
        data: {
          srcip: '10.0.0.1', srcport: '443', dstport: 65535,
          password: 'must-not-copy', process: '/bin/sh',
        },
        secret: 'must-not-copy',
      },
    });
    expect(doc.data.srcip).toBe('10.0.0.1');
    expect(doc.data.process.name).toBe('/bin/sh');
    expect(doc.data.srcport).toBe(443);
    expect(doc.data.dstport).toBe(65535);
    expect(doc.data.password).toBeUndefined();
    expect(doc.secret).toBeUndefined();
    expect(doc.source_index).toBe('wazuh-alerts-4.x-2026.08.28');
  });

  test('drops invalid port values rather than indexing malformed integers', () => {
    const doc = projectOperationalAlert({
      _index: 'wazuh-alerts-a', _id: '1',
      _source: { data: { srcport: 'not-a-port', dstport: 70000 } },
    });
    expect(doc.data.srcport).toBeNull();
    expect(doc.data.dstport).toBeNull();
  });
});
