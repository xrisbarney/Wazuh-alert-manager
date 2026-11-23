import React from 'react';
import { EuiBadge, EuiToolTip } from '@elastic/eui';
import { AlertAsset, AssetCriticality } from '../../common';

/**
 * Asset criticality badge (step 6.4a). Rendered only when the record carries
 * a stamped criticality, so unmatched agents add nothing to the queue row.
 * Colour follows the case-severity badge palette; the word is always shown
 * so colour is never the sole carrier of meaning.
 */

export const ASSET_CRITICALITY_BADGE_COLOR: Record<AssetCriticality, string> = {
  low: 'default',
  medium: 'primary',
  high: 'warning',
  critical: 'danger',
};

export function assetCriticalityLabel(value: AssetCriticality): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

interface Props {
  asset?: AlertAsset | null;
  /** Queue rows: only the word, no "asset" prefix. */
  compact?: boolean;
  className?: string;
  testSubj?: string;
}

export const AssetBadge: React.FC<Props> = ({ asset, compact = false, className, testSubj }) => {
  const criticality = asset?.criticality;
  if (!criticality || !ASSET_CRITICALITY_BADGE_COLOR[criticality]) return null;
  const tags = asset?.tags || [];
  const groups = asset?.groups || [];
  const why = asset?.matched_by ? `matched by ${asset.matched_by}${asset.matched_id ? ` "${asset.matched_id}"` : ''}` : 'stamped by sync';
  const tooltip = [
    `Asset criticality: ${assetCriticalityLabel(criticality)} (${why})`,
    tags.length ? `Tags: ${tags.join(', ')}` : null,
    groups.length ? `Groups: ${groups.join(', ')}` : null,
  ]
    .filter(Boolean)
    .join('. ');
  return (
    <EuiToolTip content={tooltip}>
      <EuiBadge
        color={ASSET_CRITICALITY_BADGE_COLOR[criticality]}
        iconType="compute"
        className={['wamAssetBadge', className].filter(Boolean).join(' ')}
        data-test-subj={testSubj}
        data-criticality={criticality}
      >
        {compact ? assetCriticalityLabel(criticality) : `${assetCriticalityLabel(criticality)} asset`}
      </EuiBadge>
    </EuiToolTip>
  );
};
