import React, { useEffect, useState } from 'react';
import { EuiCallOut, EuiLoadingSpinner, EuiText } from '@elastic/eui';
import { AlertsApiService } from '../services/api';

interface Props {
  alertId: string;
  apiService: AlertsApiService;
}

/**
 * "We've seen this before" — deterministic triage help shown at the top of an
 * alert. Counts how the same rule has been handled on the same host, so an
 * analyst can gauge routine noise vs. something new without any LLM.
 */
export const PrecedentCallout: React.FC<Props> = ({ alertId, apiService }) => {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let live = true;
    setLoading(true);
    apiService
      .fetchPrecedent(alertId)
      .then((res) => live && setData(res))
      .catch(() => live && setData(null))
      .finally(() => live && setLoading(false));
    return () => {
      live = false;
    };
  }, [alertId]);

  if (loading) return <EuiLoadingSpinner size="s" />;
  if (!data || !data.ruleId || data.total <= 1) return null;

  const closed = data.byStatus.closed || 0;
  const inProgress = data.byStatus.in_progress || 0;
  const open = data.byStatus.open || 0;
  const scope = data.agentName ? `on ${data.agentName}` : 'across all hosts';
  // Mostly-closed history suggests routine noise; lots still open suggests new.
  const color = data.total > 3 && closed / data.total >= 0.8 ? 'success' : 'primary';

  return (
    <EuiCallOut size="s" color={color} iconType="clock" title={`Seen before: rule ${data.ruleId} has fired ${data.total.toLocaleString()} times ${scope}`}>
      <EuiText size="xs">
        {closed} closed · {inProgress} in progress · {open} open
        {data.escalatedToCase > 0 ? ` · ${data.escalatedToCase} escalated to a case` : ''}
        {data.total > 3 && closed / data.total >= 0.8 ? ' — usually closed, likely routine.' : ''}
      </EuiText>
    </EuiCallOut>
  );
};
