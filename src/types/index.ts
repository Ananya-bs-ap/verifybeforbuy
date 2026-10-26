/**
 * VerifyBeforeBuy AI — Core Type Definitions
 * Strict types for risk assessment, indicators, findings, and history.
 */

export type AssessmentType = 'website' | 'product' | 'code';

export type RiskCategory = 'lower' | 'moderate' | 'elevated' | 'high';

export type EvidenceCoverage = 'minimal' | 'moderate' | 'high' | 'comprehensive';

export type IndicatorSeverity = 'info' | 'low' | 'medium' | 'high';

export interface RiskIndicator {
  id: string;
  name: string;
  category: 'url' | 'seller' | 'pricing' | 'content' | 'verification' | 'technical';
  severity: IndicatorSeverity;
  scoreImpact: number; // positive increases risk, negative (or separate positive signal) decreases
  isObserved: boolean; // true = computed from direct evidence; false = user-supplied claim
  description: string;
  remedyOrPrecaution: string;
}

export interface PositiveSignal {
  id: string;
  name: string;
  description: string;
  isVerified: boolean;
  scoreDeduction: number;
}

export interface AssessmentResult {
  id: string;
  timestamp: string;
  type: AssessmentType;
  inputSummary: {
    target: string;
    subtarget?: string;
    brand?: string;
    price?: number;
    referencePrice?: number;
    sellerName?: string;
    platform?: string;
  };
  score: number; // 0 - 100
  category: RiskCategory;
  confidence: EvidenceCoverage;
  confidenceScore: number; // 0 - 100 percent
  summary: string;
  indicators: RiskIndicator[];
  positiveSignals: PositiveSignal[];
  recommendations: string[];
  unverifiedAspects: string[];
  aiExplanation?: string;
  aiExplanationProvider?: 'gemini' | 'deterministic-fallback';
  disclaimer: string;
  isDemoMode?: boolean;
}

export interface WebsiteAnalysisInput {
  url: string;
  checkDomainAge?: boolean;
  notes?: string;
}

export interface ProductAnalysisInput {
  productName: string;
  brand?: string;
  listingUrl?: string;
  listedPrice?: number;
  referencePrice?: number;
  sellerName?: string;
  sellerRating?: number;
  sellerTenure?: string;
  hasReturnPolicy?: boolean;
  productDescription?: string;
  productIdentifier?: string; // UPC, EAN, SKU
  sourcePlatform?: string;
}

export interface CodeAnalysisInput {
  code: string;
  format?: string;
  isCameraScan?: boolean;
}

export interface SavedScanRecord {
  id: string;
  userId?: string;
  createdAt: string;
  type: AssessmentType;
  target: string;
  score: number;
  category: RiskCategory;
  confidence: EvidenceCoverage;
  result: AssessmentResult;
  storageSource: 'local' | 'supabase';
}

export interface SupabaseConfigStatus {
  isConfigured: boolean;
  urlConfigured: boolean;
  anonKeyConfigured: boolean;
  connectionState: 'unconfigured' | 'connected' | 'error';
  errorMessage?: string;
  projectId?: string;
}
