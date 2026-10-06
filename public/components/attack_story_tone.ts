import { severityBand } from '../design';

// The attack graph uses the Wazuh console design's three-step ramp. It folds
// the shared severity bands (public/design.ts) so a rule level reads the same
// here as in the alert table: critical/high -> high, medium -> med, low -> low.
export type StoryTone = 'high' | 'med' | 'low';

export const storyTone = (level: number): StoryTone => {
  const band = severityBand(level);
  if (band === 'critical' || band === 'high') return 'high';
  if (band === 'medium') return 'med';
  return 'low';
};

// Wazuh console tokens: --color-danger-500, --color-warning-400, --color-neutral-550.
export const TONE_HEX: Record<StoryTone, string> = {
  high: '#EA2D0D',
  med: '#FACC15',
  low: '#808080',
};

// Edges use a slightly different ramp from the node fills in the design: a
// darker amber and a lighter grey, so lines read on the light stage.
export const EDGE_HEX: Record<StoryTone, string> = {
  high: '#EA2D0D',
  med: '#EAB308',
  low: '#A1A1AA',
};

export const TONE_LABEL: Record<StoryTone, string> = {
  high: 'High',
  med: 'Medium',
  low: 'Low',
};
