import { useState } from 'react';

// Light/Dark choice for the redesigned case views (Linked Alerts, Attack
// Graph). A per-browser preference; the key predates the Linked Alerts
// redesign, so existing choices carry over.
export type CaseTheme = 'light' | 'dark';

const THEME_KEY = 'wamAttackGraphTheme';

const readTheme = (): CaseTheme => {
  try {
    return window.localStorage.getItem(THEME_KEY) === 'dark' ? 'dark' : 'light';
  } catch (e) {
    return 'light';
  }
};

export function useCaseTheme(): [CaseTheme, (theme: CaseTheme) => void] {
  const [theme, setTheme] = useState<CaseTheme>(readTheme);
  const update = (next: CaseTheme) => {
    setTheme(next);
    try { window.localStorage.setItem(THEME_KEY, next); } catch (e) { /* preference just isn't remembered */ }
  };
  return [theme, update];
}
