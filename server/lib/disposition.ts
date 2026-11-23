import { CLOSURE_REASON_MAX_LENGTH, DISPOSITIONS } from '../../common';
import type { Disposition } from '../../common';

/**
 * Disposition helpers (step 2.4) shared by the alert and case routes (kept out
 * of either route module so neither imports the other).
 */

export function isDisposition(value: unknown): value is Disposition {
  return typeof value === 'string' && (DISPOSITIONS as readonly string[]).includes(value);
}

/** The taxonomy values of a csv filter, in input order, unknown values dropped. */
export function dispositionFilterValues(csv: unknown): Disposition[] {
  return String(csv ?? '')
    .split(',')
    .filter(isDisposition);
}

/** Trimmed closure reason without control characters, capped at CLOSURE_REASON_MAX_LENGTH; null when empty or absent. */
export function normaliseClosureReason(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').trim();
  if (!trimmed) return null;
  return trimmed.length > CLOSURE_REASON_MAX_LENGTH ? trimmed.slice(0, CLOSURE_REASON_MAX_LENGTH) : trimmed;
}
