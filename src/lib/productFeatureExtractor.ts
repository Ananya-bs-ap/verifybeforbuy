/**
 * VerifyBeforeBuy AI — Shared Product Listing Feature Extractor
 *
 * Single source of truth used identically by BOTH:
 *   1. Offline training & evaluation (ml/train_product_model.ts)
 *   2. Real-time inference (src/lib/productMlInference.ts)
 *
 * Enforces:
 * - GS1 Modulo-10 checksum validation (not just numeric length)
 * - 3-state return policy handling ('available' | 'not_available' | 'unknown', treating 'unknown' neutrally)
 * - Same-currency compatibility check before computing reference price discount ratios
 * - Strict separation of genuine refurbishment/clearance context from unverified warranty/authorized claims
 */

import { ProductAnalysisInput, ReturnPolicyStatus } from '../types/index.ts';
import { verifyGs1CheckDigit } from './riskEngine/codeAnalyzer.ts';
import { areCurrenciesCompatible, normalizeReturnPolicyStatus } from './productValidator.ts';

export const PRODUCT_FEATURE_KEYS = [
  'hasReferencePrice',
  'discountRatio',
  'isExtremeDiscount',
  'hasSellerName',
  'isGenericSellerHandle',
  'hasSellerRating',
  'lowSellerRating',
  'highSellerRating',
  'noReturnPolicy',
  'hasReplicaKeyword',
  'hasPaymentPressureKeyword',
  'hasClearanceOrRefurbContext',
  'hasValidGs1Barcode',
  'hasRiskyListingUrl',
] as const;

export type ProductFeatureKey = (typeof PRODUCT_FEATURE_KEYS)[number];

export interface ExtractedProductFeatures {
  hasReferencePrice: number;
  discountRatio: number;
  isExtremeDiscount: number;
  hasSellerName: number;
  isGenericSellerHandle: number;
  hasSellerRating: number;
  lowSellerRating: number;
  highSellerRating: number;
  noReturnPolicy: number;
  hasReplicaKeyword: number;
  hasPaymentPressureKeyword: number;
  hasClearanceOrRefurbContext: number;
  hasValidGs1Barcode: number;
  hasRiskyListingUrl: number;
}

export const REPLICA_KEYWORDS = [
  '1:1 replica',
  'mirror copy',
  'original clone',
  'oem version replica',
  'bypass authenticity',
  'unbranded luxury',
  'aa grade clone',
  'overrun factory stock',
  'first copy',
  'super clone',
  'aaa grade',
];

export const HIGH_PRESSURE_TACTICS = [
  'wire transfer only',
  'western union',
  'crypto payment only',
  'zelle only',
  'gift card payment',
  'do not dispute',
  'friends and family only',
  'act in next 5 minutes',
];

// Strictly secondary-market condition / clearance markers; unverified seller claims like
// "warranty", "authorized", or "factory sealed" must NOT suppress risk indicators.
export const CLEARANCE_CONTEXT_KEYWORDS = [
  'refurbished',
  'recertified',
  'open-box',
  'open box',
  'clearance',
  'liquidation',
];

export const UNVERIFIED_AUTHORITY_CLAIM_KEYWORDS = [
  'warranty',
  'authorized',
  'official dealer',
  'factory sealed',
  '100% genuine',
  '100% authentic',
  'guaranteed authentic',
];

export const GENERIC_SELLER_PATTERNS = [
  'store123',
  'deals-shop',
  'deals_king',
  'seller',
  'user99',
  'discount_outlet',
  'luxury-outlet',
  'cheap_brand',
  'anon_shop',
  'flashsale',
];

export const HIGH_ABUSE_TLDS = ['.xyz', '.click', '.top', '.work', '.buzz', '.cfd', '.tk', '.ml', '.gq'];

export function detectUnverifiedAuthorityClaims(
  input: Pick<ProductAnalysisInput, 'productName' | 'productDescription'>
): string[] {
  const textBlob = `${input.productName || ''} ${input.productDescription || ''}`.toLowerCase();
  return UNVERIFIED_AUTHORITY_CLAIM_KEYWORDS.filter((kw) => textBlob.includes(kw));
}

export function extractProductFeatures(
  input: Partial<ProductAnalysisInput> & { productName?: string },
  featureOrder: readonly string[] = PRODUCT_FEATURE_KEYS
): {
  features: ExtractedProductFeatures;
  vector: number[];
  returnPolicyStatus: ReturnPolicyStatus;
  currenciesCompatible: boolean;
} {
  const currenciesCompatible = areCurrenciesCompatible(input.currency, input.referenceCurrency);
  const hasValidReferencePrice =
    input.referencePrice !== undefined &&
    Number.isFinite(input.referencePrice) &&
    input.referencePrice > 0 &&
    currenciesCompatible;

  const hasReferencePrice = hasValidReferencePrice ? 1 : 0;

  let discountRatio = 0;
  if (
    hasValidReferencePrice &&
    input.listedPrice !== undefined &&
    Number.isFinite(input.listedPrice) &&
    input.listedPrice > 0
  ) {
    discountRatio = Math.max(
      0,
      Math.min(1, (input.referencePrice! - input.listedPrice) / input.referencePrice!)
    );
  }
  const isExtremeDiscount = discountRatio >= 0.75 ? 1 : 0;

  const sellerTrim = (input.sellerName || '').trim();
  const hasSellerName = sellerTrim.length > 0 ? 1 : 0;
  const sellerLower = sellerTrim.toLowerCase();
  const isGenericSellerHandle =
    hasSellerName && GENERIC_SELLER_PATTERNS.some((p) => sellerLower.includes(p)) ? 1 : 0;

  const hasSellerRating =
    input.sellerRating !== undefined &&
    Number.isFinite(input.sellerRating) &&
    input.sellerRating > 0 &&
    input.sellerRating <= 5
      ? 1
      : 0;
  const lowSellerRating = hasSellerRating && input.sellerRating! < 3.5 ? 1 : 0;
  const highSellerRating = hasSellerRating && input.sellerRating! >= 4.5 ? 1 : 0;

  const returnPolicyStatus = normalizeReturnPolicyStatus(input);
  // Only explicit 'not_available' incurs noReturnPolicy; 'unknown' and 'available' remain 0
  const noReturnPolicy = returnPolicyStatus === 'not_available' ? 1 : 0;

  const textBlob = `${input.productName || ''} ${input.productDescription || ''}`.toLowerCase();
  const hasReplicaKeyword = REPLICA_KEYWORDS.some((kw) => textBlob.includes(kw)) ? 1 : 0;
  const hasPaymentPressureKeyword = HIGH_PRESSURE_TACTICS.some((kw) => textBlob.includes(kw)) ? 1 : 0;
  const hasClearanceOrRefurbContext = CLEARANCE_CONTEXT_KEYWORDS.some((kw) => textBlob.includes(kw))
    ? 1
    : 0;

  const cleanedCode = (input.productIdentifier || '').replace(/[\s-]/g, '');
  const hasValidGs1Barcode = verifyGs1CheckDigit(cleanedCode) ? 1 : 0;

  const urlLower = (input.listingUrl || '').trim().toLowerCase();
  let hasRiskyListingUrl = 0;
  if (urlLower.length > 0) {
    const usesHttp = urlLower.startsWith('http://');
    const usesAbuseTld = HIGH_ABUSE_TLDS.some((tld) => urlLower.includes(tld));
    const hasIp = /\b\d{1,3}(\.\d{1,3}){3}\b/.test(urlLower);
    const hasSuspiciousPath =
      urlLower.includes('cheap') || urlLower.includes('outlet-deals') || urlLower.includes('verify');
    if (usesHttp || usesAbuseTld || hasIp || hasSuspiciousPath) {
      hasRiskyListingUrl = 1;
    }
  }

  const features: ExtractedProductFeatures = {
    hasReferencePrice,
    discountRatio: Number(discountRatio.toFixed(4)),
    isExtremeDiscount,
    hasSellerName,
    isGenericSellerHandle,
    hasSellerRating,
    lowSellerRating,
    highSellerRating,
    noReturnPolicy,
    hasReplicaKeyword,
    hasPaymentPressureKeyword,
    hasClearanceOrRefurbContext,
    hasValidGs1Barcode,
    hasRiskyListingUrl,
  };

  const vector = (featureOrder as (keyof ExtractedProductFeatures)[]).map(
    (key) => features[key] ?? 0
  );

  return {
    features,
    vector,
    returnPolicyStatus,
    currenciesCompatible,
  };
}
