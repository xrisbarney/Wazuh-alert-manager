// Single source of truth for how this plugin encodes meaning: severity bands,
// lifecycle status, and time formatting. Every view imports from here so the
// same level renders the same colour and label everywhere. Before this module,
// severity thresholds were duplicated with CONTRADICTING values across three
// files (a level-9 alert read as maximum-red in the table but "High" in the SLA
// report), and EUI's loudest colour (danger) was spent on 'open' - the normal
// state of most rows - leaving nothing to make a genuinely critical row stand
// out. Colours here are EUI semantic tokens only; never a hardcoded hex.

export type SeverityBand = 'critical' | 'high' | 'medium' | 'low';

// Thresholds standardised on the SLA policy already used server-side
// (server/routes/reports.ts): Critical >=12, High 7-11, Medium 4-6, Low 0-3.
export function severityBand(level: number | null | undefined): SeverityBand {
  const l = typeof level === 'number' ? level : 0;
  if (l >= 12) return 'critical';
  if (l >= 7) return 'high';
  if (l >= 4) return 'medium';
  return 'low';
}

export const SEVERITY_LABEL: Record<SeverityBand, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

// The warm/emphasis ramp belongs to severity alone: danger -> warning -> grey ->
// hollow, descending in visual weight. EuiBadge colour tokens.
export const SEVERITY_BADGE_COLOR: Record<SeverityBand, string> = {
  critical: 'danger',
  high: 'warning',
  medium: 'default',
  low: 'hollow',
};

// Case severity uses the same ramp keyed by name.
export const CASE_SEVERITY_BADGE_COLOR: Record<string, string> = {
  critical: 'danger',
  high: 'warning',
  medium: 'default',
  low: 'hollow',
};

// Lifecycle gets a cool/neutral ramp (EuiHealth colours) so it never competes
// with severity for the danger/warning tokens.
export const STATUS_LABEL: Record<string, string> = {
  open: 'Open',
  in_progress: 'In progress',
  closed: 'Closed',
};

export const STATUS_HEALTH_COLOR: Record<string, string> = {
  open: 'primary',
  in_progress: 'accent',
  closed: 'subdued',
};

export const statusLabel = (status: string): string => STATUS_LABEL[status] || status;
export const statusColor = (status: string): string => STATUS_HEALTH_COLOR[status] || 'subdued';

// SVG charts need concrete fills (semantic tokens aren't available there). These
// mirror the ramps above: status on a cool set that keeps its distance from the
// warm severity ramp. Sourced from the EUI visualisation palette.
export const STATUS_HEX: Record<string, string> = {
  open: '#0077CC', // primary blue
  in_progress: '#9170B8', // purple
  closed: '#98A2B3', // subdued grey
};

export const SEVERITY_HEX: Record<string, string> = {
  low: '#98A2B3', // grey — routine
  medium: '#FEC514', // amber
  high: '#F5892E', // orange
  critical: '#BD271E', // danger red
};

// ---- time formatting: one implementation, used everywhere ----

export function formatAbsolute(ts?: string | number | null): string {
  if (ts == null || ts === '') return '—';
  const d = new Date(ts);
  return isNaN(d.getTime()) ? '—' : d.toLocaleString();
}

/** Compact age like "just now", "6m", "3h", "2d" - for dense scan columns. */
export function formatRelative(ts?: string | number | null): string {
  if (ts == null || ts === '') return '—';
  const then = new Date(ts).getTime();
  if (isNaN(then)) return '—';
  const secs = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (secs < 45) return 'just now';
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.round(hrs / 24);
  if (days < 30) return `${days}d ago`;
  const months = Math.round(days / 30);
  if (months < 12) return `${months}mo ago`;
  return `${Math.round(months / 12)}y ago`;
}

/** Human duration from a minute count: "6m", "3h 10m", "2d 4h", or "—". */
export function formatDuration(minutes?: number | null): string {
  if (minutes == null || isNaN(minutes) || minutes < 0) return '—';
  const total = Math.round(minutes);
  if (total < 60) return `${total}m`;
  const hrs = Math.floor(total / 60);
  const mins = total % 60;
  if (hrs < 24) return mins ? `${hrs}h ${mins}m` : `${hrs}h`;
  const days = Math.floor(hrs / 24);
  const remHrs = hrs % 24;
  return remHrs ? `${days}d ${remHrs}h` : `${days}d`;
}
