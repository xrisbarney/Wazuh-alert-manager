import { ReportMetrics, SlaPolicyResponse, TARGET_WAZUH_MAJOR } from '../../common';
import { formatDuration } from '../design';

/**
 * The resolve targets the SLA breakdown is measured against: the stored policy
 * (step 3.1) when it loaded, else the tiers the metrics response carries.
 * Level ranges are shown on a 4.x build only; a 5.0 build maps labels to bands.
 */
export function slaTargetsText(policy: SlaPolicyResponse | null, metrics: ReportMetrics | null): string {
  const bands: Array<'critical' | 'high' | 'medium' | 'low'> = ['critical', 'high', 'medium', 'low'];
  const labels = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
  const ranges = { critical: 'level 12+', high: 'level 7-11', medium: 'level 4-6', low: 'level 0-3' };
  const showRanges = Number(TARGET_WAZUH_MAJOR) !== 5;
  let minutesOf: (band: typeof bands[number]) => number | null;
  let suffix = '';
  if (policy) {
    minutesOf = (band) => policy.policy.targets[band]?.resolveMinutes ?? null;
    const isDefault = bands.every(
      (band) => policy.policy.targets[band]?.resolveMinutes === policy.defaults.targets[band]?.resolveMinutes
    );
    suffix = isDefault ? ' (default policy)' : policy.updated_by ? ` (policy saved by ${policy.updated_by})` : ' (custom policy)';
  } else if (metrics?.slaPolicy?.length) {
    minutesOf = (band) => metrics.slaPolicy.find((tier) => tier.label === labels[band])?.targetMinutes ?? null;
  } else {
    return 'Targets: loading the SLA policy';
  }
  const parts = bands.map((band) => {
    const minutes = minutesOf(band);
    return `${labels[band]}${showRanges ? ` (${ranges[band]})` : ''} ${minutes != null ? formatDuration(minutes) : '—'}`;
  });
  return `Targets: ${parts.join(' · ')}${suffix}`;
}
