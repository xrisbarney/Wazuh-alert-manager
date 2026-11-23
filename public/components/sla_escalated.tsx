import React, { useEffect, useState } from 'react';
import { EuiBadge, EuiText } from '@elastic/eui';
import type { SlaMarkers, SlaPolicy } from '../../common';

/**
 * "Escalated: <names>" line of the alert / case flyouts (step 3.3). The
 * record carries escalation ids in `sla.escalated[]`; the names come from
 * the stored policy (readable by every user), cached per page for a minute.
 * A deleted escalation falls back to its id.
 */

interface PolicyReader {
  fetchSlaPolicy(): Promise<{ policy: SlaPolicy }>;
}

const NAME_CACHE_TTL_MS = 60 * 1000;
let cache: { names: Record<string, string>; expiresAt: number } | null = null;
let inFlight: Promise<Record<string, string>> | null = null;

/** Test seam. */
export function resetEscalationNameCache(): void {
  cache = null;
  inFlight = null;
}

async function escalationNames(apiService: PolicyReader): Promise<Record<string, string>> {
  if (cache && cache.expiresAt > Date.now()) return cache.names;
  if (inFlight) return inFlight;
  inFlight = apiService
    .fetchSlaPolicy()
    .then((res) => {
      const names: Record<string, string> = {};
      for (const escalation of res?.policy?.escalations || []) names[escalation.id] = escalation.name;
      cache = { names, expiresAt: Date.now() + NAME_CACHE_TTL_MS };
      return names;
    })
    .catch(() => cache?.names || {})
    .finally(() => {
      inFlight = null;
    });
  return inFlight;
}

interface Props {
  sla?: SlaMarkers | null;
  apiService: PolicyReader;
  testSubj?: string;
}

export const SlaEscalated: React.FC<Props> = ({ sla, apiService, testSubj = 'wamSlaEscalated' }) => {
  const ids = Array.isArray(sla?.escalated) ? sla!.escalated!.filter((id) => typeof id === 'string' && id) : [];
  const [names, setNames] = useState<Record<string, string>>(cache?.names || {});

  useEffect(() => {
    if (!ids.length) return;
    let cancelled = false;
    escalationNames(apiService).then((resolved) => {
      if (!cancelled) setNames(resolved);
    });
    return () => {
      cancelled = true;
    };
  }, [ids.join(',')]);

  if (!ids.length) return null;
  return (
    <EuiText size="s" className="wamSlaEscalated" data-test-subj={testSubj}>
      <span className="wamSlaEscalated__label">Escalated:</span>
      {ids.map((id) => (
        <EuiBadge key={id} color="warning" title={id}>
          {names[id] || id}
        </EuiBadge>
      ))}
    </EuiText>
  );
};
