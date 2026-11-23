import {
  evaluateEntityExpression,
  matchingEntityGroupIdentity,
  normalizeEntityExpression,
  normalizeEntityValue,
  validateEntityExpression,
} from './entity_expression';
import labAudit80792 from '../../lab/agent/samples/80792.json';

const expression = (groups: any[]) => ({ version: 1 as const, groups });
const predicate = (id: string, entity: string, value?: string, order = 0, operator = 'equals') => ({
  id,
  order,
  entity,
  operator,
  ...(value === undefined ? {} : { value }),
});

describe('security entity expressions', () => {
  test('a process predicate matches the auditd binary of a real lab connect() alert (step 9.4)', () => {
    const normalized = normalizeEntityExpression(
      expression([{ id: 'bin', order: 0, predicates: [predicate('p', 'process', '/usr/bin/curl')] }])
    );
    expect(labAudit80792._source.data).not.toHaveProperty('process');
    expect(evaluateEntityExpression(normalized, labAudit80792._source).matched).toBe(true);
    expect(evaluateEntityExpression(normalized, { data: { audit: { exe: '/usr/bin/wget' } } }).matched).toBe(false);
  });

  test('normalizes entity values deterministically', () => {
    expect(normalizeEntityValue('srcip', ' 192.168.001.010 ')).toBe('192.168.1.10');
    expect(normalizeEntityValue('dstip', '2001:0DB8:0:0:0:0:0:1')).toBe('2001:db8::1');
    expect(normalizeEntityValue('user', ' Administrator ')).toBe('administrator');
    expect(normalizeEntityValue('process', ' SSHD ')).toBe('sshd');
    expect(normalizeEntityValue('dstport', '00022')).toBe('22');
    expect(normalizeEntityValue('srcport', '65536')).toBeNull();
    expect(normalizeEntityValue('agent', ' host-A ')).toBe('host-A');
    // Indicator kinds (step 6.1) use the canonical forms of common/indicators.ts.
    expect(normalizeEntityValue('hash', ' D41D8CD98F00B204E9800998ECF8427E ')).toBe('d41d8cd98f00b204e9800998ecf8427e');
    expect(normalizeEntityValue('hash', 'not-a-hash')).toBeNull();
    expect(normalizeEntityValue('domain', 'Evil.Example.COM.')).toBe('evil.example.com');
    expect(normalizeEntityValue('domain', '203.0.113.9')).toBeNull();
    expect(normalizeEntityValue('url', 'HTTP://Evil.Example.com:8080/p?x=1')).toBe('http://evil.example.com:8080/p?x=1');
    expect(normalizeEntityValue('url', '/wp-login.php')).toBe('/wp-login.php');
    expect(normalizeEntityValue('url', 'plain text')).toBeNull();
  });

  test('matches hash, domain and url predicates against syscheck.*_after, data.hostname and data.url', () => {
    const input = expression([
      { id: 'file', order: 0, predicates: [predicate('h', 'hash', 'DA39A3EE5E6B4B0D3255BFEF95601890AFD80709')] },
      { id: 'web', order: 1, predicates: [predicate('d', 'domain', 'EVIL.example.com'), predicate('u', 'url', 'http://EVIL.example.com/x', 1)] },
    ]);
    const normalized = normalizeEntityExpression(input);
    expect(validateEntityExpression(normalized)).toEqual([]);
    const result = evaluateEntityExpression(normalized, {
      syscheck: { md5_after: 'd41d8cd98f00b204e9800998ecf8427e', sha1_after: 'da39a3ee5e6b4b0d3255bfef95601890afd80709' },
      data: { hostname: 'evil.example.com.', url: 'HTTP://evil.example.com/x' },
    });
    expect(result.matched).toBe(true);
    expect(result.matchingGroups.map((group) => group.groupId)).toEqual(['file', 'web']);
    expect(evaluateEntityExpression(normalized, { data: { hostname: 'other.example.com' } }).matched).toBe(false);
  });

  test('sorts by structural order while retaining IDs and normalizing values', () => {
    const normalized = normalizeEntityExpression(expression([
      { id: 'group-b', order: 2, predicates: [predicate('p-b', 'process', ' SSHD ', 3)] },
      { id: 'group-a', order: 1, predicates: [predicate('p-a', 'dstport', '022', 4)] },
    ]));
    expect(normalized.groups.map((group) => group.id)).toEqual(['group-a', 'group-b']);
    expect(normalized.groups[0].predicates[0]).toMatchObject({ id: 'p-a', order: 4, value: '22' });
  });

  test('evaluates AND within groups, OR across groups, and retains every matching group', () => {
    const input = expression([
      {
        id: 'network',
        order: 0,
        predicates: [predicate('source', 'srcip', '2001:db8::1'), predicate('port', 'dstport', '22', 1)],
      },
      {
        id: 'identity',
        order: 1,
        predicates: [predicate('user', 'user', 'ADMINISTRATOR'), predicate('process', 'process', 'sshd', 1)],
      },
    ]);
    const result = evaluateEntityExpression(normalizeEntityExpression(input), {
      data: {
        srcip: '2001:0db8:0:0::1',
        dstport: 22,
        srcuser: 'Administrator',
        process: { name: 'SSHD' },
      },
    });
    expect(result.matched).toBe(true);
    expect(result.matchingGroups.map((group) => group.groupId)).toEqual(['network', 'identity']);
    expect(result.matchingGroups[0].values).toEqual([
      { predicateId: 'source', entity: 'srcip', value: '2001:db8::1' },
      { predicateId: 'port', entity: 'dstport', value: '22' },
    ]);
    expect(matchingEntityGroupIdentity(result.matchingGroups[0])).toBe(
      '["network",0,[["source","srcip","2001:db8::1"],["port","dstport","22"]]]'
    );
  });

  test('does not match a group when any field is absent', () => {
    const input = expression([{
      id: 'network',
      order: 0,
      predicates: [predicate('source', 'srcip', undefined, 0, 'exists'), predicate('port', 'dstport', '22', 1)],
    }]);
    expect(evaluateEntityExpression(input as any, { data: { srcip: '10.0.0.1' } })).toEqual({
      matched: false,
      matchingGroups: [],
    });
  });

  test('rejects blank IDs, duplicate normalized predicates, invalid ports, and size limits', () => {
    const groups = [
      {
        id: '',
        order: 0,
        predicates: [predicate('p1', 'user', ' ADMIN '), predicate('p2', 'user', 'admin', 1)],
      },
      { id: 'g2', order: 1, predicates: [predicate('p3', 'dstport', '70000')] },
      { id: 'g3', order: 2, predicates: [predicate('p4', 'agent', 'a')] },
      { id: 'g4', order: 3, predicates: [predicate('p5', 'agent', 'b')] },
      { id: 'g5', order: 4, predicates: [predicate('p6', 'agent', 'c')] },
      { id: 'g6', order: 5, predicates: [predicate('p7', 'agent', 'd')] },
    ];
    const errors = validateEntityExpression(expression(groups) as any);
    expect(errors).toEqual(expect.arrayContaining([
      'Entity expression cannot contain more than 5 groups.',
      'Entity expression cannot contain more than 5 predicates in total.',
      'Each entity group needs a non-blank stable ID.',
      'Duplicate entity predicate: user:equals:admin.',
      'Entity predicate p3 has an invalid or blank value.',
    ]));
  });
});
