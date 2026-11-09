import {
  bandFromLabel,
  bandFromLevel,
  bandsAtOrAboveLevel,
  bandsBetweenLevels,
  effectiveLevel,
  meetsMinLevel,
  severityBandOf,
  severityRangeClause,
} from './severity';

describe('severity model across Wazuh 4.x levels and 5.0 labels', () => {
  test('numeric levels map to the bands the plugin has always badged', () => {
    expect(bandFromLevel(0)).toBe('low');
    expect(bandFromLevel(3)).toBe('low');
    expect(bandFromLevel(4)).toBe('medium');
    expect(bandFromLevel(6)).toBe('medium');
    expect(bandFromLevel(7)).toBe('high');
    expect(bandFromLevel(11)).toBe('high');
    expect(bandFromLevel(12)).toBe('critical');
    expect(bandFromLevel(16)).toBe('critical');
    expect(bandFromLevel('9')).toBe('high');
    expect(bandFromLevel(null)).toBeNull();
    expect(bandFromLevel('high')).toBeNull();
  });

  test('labels are normalized, never guessed', () => {
    expect(bandFromLabel('low')).toBe('low');
    expect(bandFromLabel(' HIGH ')).toBe('high');
    expect(bandFromLabel('informational')).toBe('informational');
    expect(bandFromLabel('info')).toBe('informational');
    expect(bandFromLabel('critical')).toBe('critical');
    expect(bandFromLabel('7')).toBeNull();
    expect(bandFromLabel('urgent')).toBeNull();
    expect(bandFromLabel(null)).toBeNull();
  });

  test('a canonical record resolves its band from level first, then label', () => {
    expect(severityBandOf({ rule: { level: 13 } })).toBe('critical');
    expect(severityBandOf({ rule: { level: null }, severity_label: 'medium' })).toBe('medium');
    expect(severityBandOf({ rule: { level: 3 }, severity_label: 'critical' })).toBe('low');
    expect(severityBandOf({})).toBeNull();
  });

  test('a numeric floor translates to the bands it covers', () => {
    expect(bandsAtOrAboveLevel(0)).toEqual(['low', 'medium', 'high', 'critical']);
    expect(bandsAtOrAboveLevel(4)).toEqual(['medium', 'high', 'critical']);
    expect(bandsAtOrAboveLevel(7)).toEqual(['high', 'critical']);
    expect(bandsAtOrAboveLevel(12)).toEqual(['critical']);
    expect(bandsBetweenLevels(0, 3)).toEqual(['informational', 'low']);
    expect(bandsBetweenLevels(4, 11)).toEqual(['medium', 'high']);
    expect(bandsBetweenLevels(null, 6)).toEqual(['informational', 'low', 'medium']);
    expect(bandsBetweenLevels(7, null)).toEqual(['high', 'critical']);
  });

  test('meetsMinLevel agrees for equivalent 4.x and 5.0 records', () => {
    expect(meetsMinLevel({ rule: { level: 7 } }, 7)).toBe(true);
    expect(meetsMinLevel({ rule: { level: 6 } }, 7)).toBe(false);
    expect(meetsMinLevel({ rule: { level: null }, severity_label: 'high' }, 7)).toBe(true);
    expect(meetsMinLevel({ rule: { level: null }, severity_label: 'medium' }, 7)).toBe(false);
    expect(meetsMinLevel({ rule: { level: null }, severity_label: 'informational' }, 0)).toBe(false);
    expect(meetsMinLevel({ rule: { level: null } }, 0)).toBe(false);
  });

  test('effectiveLevel never promotes a label above the lowest level of its band', () => {
    expect(effectiveLevel({ rule: { level: 9 } })).toBe(9);
    expect(effectiveLevel({ severity_label: 'high' })).toBe(7);
    expect(effectiveLevel({ severity_label: 'critical' })).toBe(12);
    expect(effectiveLevel({ severity_label: 'informational' })).toBe(0);
    expect(effectiveLevel({})).toBeNull();
  });

  test('the range clause matches either family and is absent when unbounded', () => {
    expect(severityRangeClause(null, null)).toBeNull();
    expect(severityRangeClause(4, 11)).toEqual({
      bool: {
        should: [{ range: { 'rule.level': { gte: 4, lte: 11 } } }, { terms: { severity_label: ['medium', 'high'] } }],
        minimum_should_match: 1,
      },
    });
    expect(severityRangeClause(12)).toEqual({
      bool: {
        should: [{ range: { 'rule.level': { gte: 12 } } }, { terms: { severity_label: ['critical'] } }],
        minimum_should_match: 1,
      },
    });
  });
});
