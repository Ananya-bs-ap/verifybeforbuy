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
    currency?: string;
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
  mlPhishingPrediction?: MlPhishingResult;
  mlProductPrediction?: MlProductResult;
  barcodeLookup?: BarcodeLookupResult;
  domainVerification?: DomainVerificationResult;
  sellerVerification?: SellerVerificationResult;
  marketPriceComparison?: MarketPriceComparisonResult;
  disclaimer: string;
  isDemoMode?: boolean;
}

export interface MlModelMetrics {
  accuracy: number;
  precision: number;
  recall: number;
  f1Score: number;
  confusionMatrix: {
    truePositives: number;
    falsePositives: number;
    trueNegatives: number;
    falseNegatives: number;
  };
}

export interface MlPhishingResult {
  url: string;
  isPhishing: boolean;
  probability: number; // 0.0 - 1.0
  riskScore: number; // 0 - 100
  riskCategory: RiskCategory;
  modelTrained: boolean;
  modelType: string;
  datasetName?: string;
  trainingSamples?: number;
  metrics?: MlModelMetrics;
  featuresExtracted?: Record<string, any>;
  indicatorsFlagged: string[];
  disclaimer: string;
  serviceAvailable: boolean;
}

export interface MlProductResult {
  productName: string;
  isHighRisk: boolean;
  probability: number; // 0.0 - 1.0
  riskScore: number; // 0 - 100
  riskCategory: RiskCategory;
  modelTrained: boolean;
  modelType: string;
  datasetName?: string;
  totalDatasetRows?: number;
  trainingSamples?: number;
  samplesTested?: number;
  isSyntheticDataset?: boolean;
  metrics?: MlModelMetrics;
  featuresExtracted?: Record<string, any>;
  indicatorsFlagged: string[];
  disclaimer: string;
  serviceAvailable: boolean;
}

export interface WebsiteAnalysisInput {
  url: string;
  checkDomainAge?: boolean;
  notes?: string;
}

export type ReturnPolicyStatus = 'available' | 'not_available' | 'unknown';

export interface ProductAnalysisInput {
  productName: string;
  brand?: string;
  listingUrl?: string;
  listedPrice?: number;
  referencePrice?: number;
  currency?: string;
  referenceCurrency?: string;
  sellerName?: string;
  sellerRating?: number;
  sellerTenure?: string;
  returnPolicyStatus?: ReturnPolicyStatus;
  hasReturnPolicy?: boolean;
  productDescription?: string;
  productIdentifier?: string; // UPC, EAN, GTIN, SKU
  sourcePlatform?: string;
}

export interface ExtractedProductDetails {
  productName?: string;
  brand?: string;
  listedPrice?: number;
  referencePrice?: number;
  currency?: string;
  referenceCurrency?: string;
  sellerName?: string;
  sellerRating?: number;
  productDescription?: string;
  productIdentifier?: string;
  returnPolicyStatus: ReturnPolicyStatus;
  sourcePlatform?: string;
}

export interface ProductFetchDetailsResponse {
  success: boolean;
  url: string;
  finalUrl?: string;
  marketplace?: string;
  accessRestricted?: boolean;
  requiresAuthorizedApi?: boolean;
  statusCode?: number;
  message: string;
  extracted?: ExtractedProductDetails;
  fieldSources: Record<string, string>;
  warnings: string[];
}

export interface CodeAnalysisInput {
  code: string;
  format?: string;
  isCameraScan?: boolean;
}

export type BarcodeLookupStatus = 'found' | 'not_found' | 'invalid_checksum' | 'error';

export type BarcodeDatabaseSourceType = 'live_database' | 'synthetic_demo' | 'none';

export interface BarcodeProductInfo {
  code: string;
  formatLabel?: string;
  productName?: string;
  brand?: string;
  manufacturer?: string;
  category?: string;
  imageUrl?: string;
  countries?: string;
  quantity?: string;
  databaseSource: string;
  sourceUrl?: string;
}

export interface BarcodeProviderError {
  database: string;
  reason: string;
  rateLimited?: boolean;
  timedOut?: boolean;
}

export interface BarcodeLookupResult {
  code: string;
  gs1Valid: boolean;
  formatLabel?: string;
  status: BarcodeLookupStatus;
  sourceType: BarcodeDatabaseSourceType;
  found: boolean;
  message: string;
  product?: BarcodeProductInfo;
  queriedDatabases: string[];
  providerErrors?: BarcodeProviderError[];
  cached: boolean;
  fetchedAt: string;
}

export type VerificationCheckStatus = 'verified' | 'suspicious' | 'unavailable';

export interface DnsVerificationInfo {
  status: VerificationCheckStatus;
  hostname: string;
  exists: boolean;
  resolvedIps: string[];
  ssrfBlocked?: boolean;
  error?: string;
}

export interface TlsVerificationInfo {
  status: VerificationCheckStatus;
  checked: boolean;
  applicable: boolean;
  isTrusted?: boolean;
  isExpired?: boolean;
  isNotYetValid?: boolean;
  authorizationError?: string;
  validFrom?: string;
  validTo?: string;
  daysRemaining?: number;
  subjectCN?: string;
  issuer?: string;
  protocol?: string;
  error?: string;
}

export interface RdapVerificationInfo {
  status: VerificationCheckStatus;
  apexDomain?: string;
  rdapServer?: string;
  registrationDate?: string;
  expirationDate?: string;
  domainAgeDays?: number;
  registrar?: string;
  error?: string;
}

export interface RedirectHopInfo {
  fromUrl: string;
  toUrl: string;
  statusCode: number;
  httpToHttpsUpgrade: boolean;
  crossDomain: boolean;
  blockedBySsrf?: boolean;
  reason?: string;
}

export interface RedirectVerificationInfo {
  status: VerificationCheckStatus;
  initialUrl: string;
  finalUrl: string;
  finalStatusCode?: number;
  hopCount: number;
  httpToHttpsUpgrade: boolean;
  crossDomainRedirect: boolean;
  downgradeHttpsToHttp: boolean;
  suspiciousDestination: boolean;
  suspiciousReasons: string[];
  hops: RedirectHopInfo[];
  error?: string;
}

export interface ThreatIntelMatch {
  provider: string;
  threatType: string;
  reference?: string;
}

export interface ThreatIntelProviderStatus {
  provider: string;
  checked: boolean;
  status: 'clean' | 'flagged' | 'unavailable';
  detail?: string;
}

export interface ThreatIntelVerificationInfo {
  status: VerificationCheckStatus;
  listed: boolean;
  matches: ThreatIntelMatch[];
  providers: ThreatIntelProviderStatus[];
}

export interface DomainVerificationResult {
  hostname: string;
  apexDomain: string;
  checkedAt: string;
  dns: DnsVerificationInfo;
  tls: TlsVerificationInfo;
  rdap: RdapVerificationInfo;
  redirects: RedirectVerificationInfo;
  threatIntel: ThreatIntelVerificationInfo;
  cached?: boolean;
}

export type SellerVerificationStatus =
  | 'verified'
  | 'mismatch_or_warning'
  | 'unverified'
  | 'restricted'
  | 'unavailable';

export type AuthorizedSellerStatus =
  | 'confirmed_official'
  | 'third_party_unverified'
  | 'unavailable';

export interface SellerUserProvidedInfo {
  sellerName?: string;
  sellerRating?: number;
  returnPolicyStatus: ReturnPolicyStatus;
  brand?: string;
  sourcePlatform?: string;
}

export interface SellerRetrievedInfo {
  sellerName?: string;
  sellerProfileUrl?: string;
  sellerRating?: number;
  sellerRatingCount?: number;
  sellerAccountAgeDays?: number;
  foundingDate?: string;
  businessRegistration?: string;
  authorizedSellerStatus: AuthorizedSellerStatus;
  authorizedSellerDetail?: string;
  returnPolicyStatus: ReturnPolicyStatus;
  returnPolicySummary?: string;
  sourceUrl?: string;
  fieldSources: Record<string, string>;
}

export interface SellerComparisonSummary {
  sellerNameMatch: 'match' | 'mismatch' | 'not_comparable';
  ratingDiscrepancy?: number;
  returnPolicyMismatch: boolean;
  suspiciousHandleFlags: string[];
  inconsistencies: string[];
  warnings: string[];
}

export interface SellerVerificationResult {
  status: SellerVerificationStatus;
  source: 'public_metadata' | 'official_merchant_page' | 'authorized_api' | 'none';
  marketplace?: string;
  accessRestricted?: boolean;
  requiresAuthorizedApi?: boolean;
  statusCode?: number;
  message: string;
  userProvided: SellerUserProvidedInfo;
  retrieved: SellerRetrievedInfo;
  comparison: SellerComparisonSummary;
  checkedAt: string;
  cached?: boolean;
  error?: string;
}

export type MarketPriceType =
  | 'official_msrp'
  | 'current_retail'
  | 'historical_price'
  | 'user_reference';

export type ProductCondition = 'new' | 'refurbished' | 'used' | 'clearance' | 'unknown';

export type MarketPriceComparisonStatus =
  | 'verified_comparison'
  | 'partial_or_user_reference'
  | 'currency_mismatch'
  | 'unavailable';

export interface MarketPriceQuote {
  id: string;
  sourceName: string;
  sourceCategory:
    | 'official_manufacturer'
    | 'authorized_retailer_api'
    | 'public_metadata'
    | 'barcode_offers'
    | 'user_input';
  sourceUrl?: string;
  price: number;
  currency: string;
  convertedPrice?: number;
  convertedCurrency?: string;
  fxRateUsed?: number;
  fxSource?: string;
  priceType: MarketPriceType;
  matchedTitle?: string;
  condition: ProductCondition;
  variantMatch: 'exact' | 'compatible' | 'mismatch';
  variantMatchReason?: string;
  includedInStats: boolean;
  retrievedAt: string;
}

export interface MarketPriceStats {
  currency: string;
  minPrice?: number;
  maxPrice?: number;
  medianPrice?: number;
  externalQuoteCount: number;
  totalComparableCount: number;
  selectedReferencePrice: number;
  selectedReferenceType: MarketPriceType;
  selectedReferenceLabel: string;
  listedPrice?: number;
  percentageDifference?: number; // positive = % below reference, negative = % above reference
  vsMsrpPercentageDifference?: number;
}

export interface CurrencyConversionSummary {
  performed: boolean;
  fromCurrencies: string[];
  toCurrency: string;
  provider?: string;
  rates?: Record<string, number>;
  retrievedAt?: string;
  unavailableReason?: string;
}

export interface MarketPriceComparisonResult {
  status: MarketPriceComparisonStatus;
  message: string;
  targetCurrency: string;
  inferredCondition: ProductCondition;
  indianMarketPrioritized: boolean;
  quotes: MarketPriceQuote[];
  excludedMismatches: MarketPriceQuote[];
  stats?: MarketPriceStats;
  currencyConversion?: CurrencyConversionSummary;
  queriedSources: string[];
  sourceErrors: Array<{ source: string; reason: string }>;
  manualReferenceRetained: boolean;
  checkedAt: string;
  cached?: boolean;
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
