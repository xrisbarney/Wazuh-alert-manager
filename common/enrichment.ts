// Stored enrichment helpers (step 6.3), shared by the per-alert lookup route
// (which writes the bounded `enrichment` object) and the browser (which shows
// stored verdicts and the queue badge). Pure functions, no I/O.

import { ENRICHMENT_VERDICTS, MAX_ALERT_ENRICHMENT_ITEMS, MAX_ALERT_ENRICHMENT_TAGS } from './constants';
import type {
  AlertEnrichment,
  AlertEnrichmentItem,
  EnrichmentLookupResponse,
  EnrichmentLookupType,
  EnrichmentVerdict,
} from './types';

/** Severity order used for the worst verdict (lower index = worse). */
const VERDICT_RANK: Record<EnrichmentVerdict, number> = { malicious: 0, suspicious: 1, clean: 2, unknown: 3 };

function isVerdict(value: unknown): value is EnrichmentVerdict {
  return typeof value === 'string' && (ENRICHMENT_VERDICTS as readonly string[]).includes(value);
}

/** Worst verdict across stored items: malicious > suspicious > clean > unknown. */
export function worstEnrichmentVerdict(items: ReadonlyArray<Pick<AlertEnrichmentItem, 'verdict'>> | null | undefined): EnrichmentVerdict | null {
  let best: EnrichmentVerdict | null = null;
  for (const item of items || []) {
    if (!isVerdict(item?.verdict)) continue;
    if (best === null || VERDICT_RANK[item.verdict] < VERDICT_RANK[best]) best = item.verdict;
  }
  return best;
}

/** Stored items of one indicator (every source), newest first. */
export function enrichmentItemsFor(
  enrichment: AlertEnrichment | null | undefined,
  type: EnrichmentLookupType | string,
  value: string
): AlertEnrichmentItem[] {
  return (enrichment?.items || []).filter((item) => item && item.type === type && item.value === value);
}

/** Sanitise one stored item: drop malformed entries, cap tags, coerce score. */
function normaliseItem(raw: any): AlertEnrichmentItem | null {
  if (!raw || typeof raw !== 'object') return null;
  const { type, value, source, verdict, checked_at: checkedAt } = raw;
  if (typeof type !== 'string' || typeof value !== 'string' || !value || typeof source !== 'string' || !source) return null;
  if (!isVerdict(verdict) || typeof checkedAt !== 'string' || !checkedAt) return null;
  const score = typeof raw.score === 'number' && Number.isFinite(raw.score) ? raw.score : null;
  const tags = Array.isArray(raw.tags)
    ? raw.tags.filter((tag: unknown) => typeof tag === 'string' && tag).slice(0, MAX_ALERT_ENRICHMENT_TAGS)
    : [];
  const link = typeof raw.link === 'string' && raw.link ? raw.link : null;
  return { type: type as EnrichmentLookupType, value, source, verdict, score, tags, link, checked_at: checkedAt };
}

/**
 * Merge a lookup response into the alert's stored enrichment. Successful
 * results replace the previous item of the same (source, type, value); error
 * results leave the previous item in place. The list is newest first and
 * capped at MAX_ALERT_ENRICHMENT_ITEMS (oldest dropped), tags at
 * MAX_ALERT_ENRICHMENT_TAGS each.
 */
export function mergeAlertEnrichment(
  existing: AlertEnrichment | null | undefined,
  lookup: EnrichmentLookupResponse,
  now: Date = new Date()
): AlertEnrichment {
  const fresh: AlertEnrichmentItem[] = [];
  for (const entry of lookup.results || []) {
    if (entry?.status !== 'ok' || !entry.result) continue;
    const item = normaliseItem({
      type: lookup.type,
      value: lookup.value,
      source: entry.result.source || entry.sourceId,
      verdict: entry.result.verdict,
      score: entry.result.score,
      tags: entry.result.tags,
      link: entry.result.link,
      checked_at: entry.result.checkedAt || now.toISOString(),
    });
    if (item) fresh.push(item);
  }
  const key = (item: AlertEnrichmentItem) => `${item.source}\u0000${item.type}\u0000${item.value}`;
  const replaced = new Set(fresh.map(key));
  const kept: AlertEnrichmentItem[] = [];
  for (const raw of existing?.items || []) {
    const item = normaliseItem(raw);
    if (item && !replaced.has(key(item))) kept.push(item);
  }
  const byNewest = (a: AlertEnrichmentItem, b: AlertEnrichmentItem) => (a.checked_at < b.checked_at ? 1 : a.checked_at > b.checked_at ? -1 : 0);
  fresh.sort(byNewest);
  kept.sort(byNewest);
  const items = [...fresh, ...kept].slice(0, MAX_ALERT_ENRICHMENT_ITEMS);
  return { updated_at: now.toISOString(), worst_verdict: worstEnrichmentVerdict(items), items };
}
