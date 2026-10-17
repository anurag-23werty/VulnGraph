/**
 * VulnGraph Risk Scoring Engine (Client-side what-if evaluation)
 * Formula Version: v1.2.0
 * 
 * Parity Guarantee:
 * With DEFAULT_WHAT_IF_PARAMS, this function matches server compute_risk()
 * to within 0.01 tolerance across all ground-truth findings.
 */

export interface WhatIfParams {
  exposureFloor: number;      // default: 0.15 (0.0 to 0.50)
  sensitivityWeight: number;  // default: 1.0 (0.5 to 2.0)
  blastWeight: number;        // default: 1.0 (0.5 to 2.0)
  includeKev: boolean;        // default: false
}

export const DEFAULT_WHAT_IF_PARAMS: WhatIfParams = {
  exposureFloor: 0.15,
  sensitivityWeight: 1.0,
  blastWeight: 1.0,
  includeKev: false,
};

export interface RiskComponents {
  cvss_norm: number;
  exposure: number;
  sensitivity: number;
  blast: number;
  critical_path_multiplier?: number;
}

export function computeClientRisk(
  components: RiskComponents,
  params: WhatIfParams = DEFAULT_WHAT_IF_PARAMS,
  isKev: boolean = false
): number {
  const effectiveExposure = Math.max(components.exposure, params.exposureFloor);
  const weightedSensitivity = components.sensitivity * params.sensitivityWeight;
  const weightedBlast = Math.min(1.0, components.blast * params.blastWeight);
  const criticalMultiplier = components.critical_path_multiplier ?? 1.0;
  const kevMultiplier = (params.includeKev && isKev) ? 1.15 : 1.0;

  const rawScore = 10.0 * (
    components.cvss_norm *
    effectiveExposure *
    weightedSensitivity *
    weightedBlast
  ) * criticalMultiplier * kevMultiplier;

  return Math.round(Math.min(10.0, rawScore) * 100) / 100;
}

export function getVerdictFromScore(score: number): 'patch_immediately' | 'schedule_maintenance' | 'deprioritize' {
  if (score >= 7.0) return 'patch_immediately';
  if (score >= 4.0) return 'schedule_maintenance';
  return 'deprioritize';
}
