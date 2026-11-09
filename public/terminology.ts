import React, { useContext } from 'react';
import type { BuildInfo } from './services/api';

/**
 * Wazuh 4.x calls the unit of work an alert; Wazuh 5.0 calls it a finding.
 * The plugin keeps one data model and one UI, but labels follow the platform
 * the build targets so the workbench reads naturally beside the native
 * dashboard. Only wording changes; routes, fields and storage do not.
 */
export interface Terminology {
  /** 'alert' | 'finding' */
  unit: string;
  /** 'alerts' | 'findings' */
  units: string;
  /** 'Alert' | 'Finding' */
  Unit: string;
  /** 'Alerts' | 'Findings' */
  Units: string;
  /** Which platform line produced the wording. */
  wazuhMajor: 4 | 5;
}

export const ALERT_TERMS: Terminology = { unit: 'alert', units: 'alerts', Unit: 'Alert', Units: 'Alerts', wazuhMajor: 4 };
export const FINDING_TERMS: Terminology = { unit: 'finding', units: 'findings', Unit: 'Finding', Units: 'Findings', wazuhMajor: 5 };

export function terminologyFor(build?: Pick<BuildInfo, 'targetWazuhMajor'> | null): Terminology {
  return build?.targetWazuhMajor === 5 ? FINDING_TERMS : ALERT_TERMS;
}

export const TerminologyContext = React.createContext<Terminology>(ALERT_TERMS);

export function useTerminology(): Terminology {
  return useContext(TerminologyContext);
}
