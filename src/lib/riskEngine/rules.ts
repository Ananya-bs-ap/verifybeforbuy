/**
 * Risk Scoring Rules and Thresholds
 * 
 * Rules Constitution:
 * 1. 0 - 100 Scale:
 *    - 0–25: Lower assessed risk
 *    - 26–50: Moderate assessed risk
 *    - 51–75: Elevated assessed risk
 *    - 76–100: High assessed risk
 * 2. Never claim counterfeit or fraud solely based on price or single indicator.
 * 3. Missing data reduces confidence/coverage, but is NOT scored as fraud.
 * 4. Distinct scoring caps prevent compounding identical underlying concerns.
 */

import { RiskCategory } from '../../types';

export const RISK_THRESHOLDS = {
  LOWER_MAX: 25,
  MODERATE_MAX: 50,
  ELEVATED_MAX: 75,
  HIGH_MAX: 100,
};

export function getRiskCategory(score: number): RiskCategory {
  if (score <= RISK_THRESHOLDS.LOWER_MAX) return 'lower';
  if (score <= RISK_THRESHOLDS.MODERATE_MAX) return 'moderate';
  if (score <= RISK_THRESHOLDS.ELEVATED_MAX) return 'elevated';
  return 'high';
}

export const CATEGORY_META: Record<RiskCategory, {
  label: string;
  badgeClass: string;
  colorClass: string;
  description: string;
}> = {
  lower: {
    label: 'Lower Assessed Risk',
    badgeClass: 'text-emerald-400 bg-emerald-950/60 border-emerald-800/60',
    colorClass: 'text-emerald-400',
    description: 'No significant high-risk patterns were detected in the available information.',
  },
  moderate: {
    label: 'Moderate Assessed Risk',
    badgeClass: 'text-sky-400 bg-sky-950/60 border-sky-800/60',
    colorClass: 'text-sky-400',
    description: 'A few indicators warrant caution or further verification before proceeding.',
  },
  elevated: {
    label: 'Elevated Assessed Risk',
    badgeClass: 'text-amber-400 bg-amber-950/60 border-amber-800/60',
    colorClass: 'text-amber-400',
    description: 'Multiple warning indicators suggest increased risk. Proceed with strict precautions.',
  },
  high: {
    label: 'High Assessed Risk',
    badgeClass: 'text-rose-400 bg-rose-950/60 border-rose-800/60',
    colorClass: 'text-rose-400',
    description: 'Critical warning signs detected (e.g., brand impersonation or credential traps). High likelihood of deception.',
  },
};

export const COMMON_DISCLAIMER =
  'This report provides a preliminary risk assessment based solely on the information available. It does not guarantee that a website or product is safe, fraudulent, genuine, or counterfeit. Risk assessment is an indicator of caution, not definitive proof.';
