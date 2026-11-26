/**
 * VerifyBeforeBuy AI — ML Product Listing Risk Inference Engine
 *
 * Runs real-time inference using Logistic Regression parameters trained on
 * ml/data/product_listings_dataset.csv (10,000 labeled product listings).
 */

import trainedProductModelData from '../ml_product_model.json';
import { MlProductResult, ProductAnalysisInput, RiskCategory } from '../types/index.ts';
import { verifyGs1CheckDigit } from './riskEngine/codeAnalyzer.ts';
import { areCurrenciesCompatible, normalizeReturnPolicyStatus } from './productValidator.ts';

const REPLICA_KEYWORDS = [
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

const HIGH_PRESSURE_TACTICS = [
  'wire transfer only',
  'western union',
  'crypto payment only',
  'zelle only',
  'gift card payment',
  'do not dispute',
  'friends and family only',
  'act in next 5 minutes',
];

const CLEARANCE_CONTEXT_KEYWORDS = [
  'refurbished',
  'recertified',
  'open-box',
  'open box',
  'clearance',
  'liquidation',
  'warranty',
  'authorized',
  'factory sealed',
  'return policy',
];

const GENERIC_SELLER_PATTERNS = [
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

const HIGH_ABUSE_TLDS = ['.xyz', '.click', '.top', '.work', '.buzz', '.cfd', '.tk', '.ml', '.gq'];

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

export function extractProductFeatures(input: ProductAnalysisInput): {
  features: ExtractedProductFeatures;
  vector: number[];
} {
  const sameCurrency = areCurrenciesCompatible(input.currency, input.referenceCurrency);
  const hasReferencePrice =
    input.referencePrice !== undefined && input.referencePrice > 0 && sameCurrency ? 1 : 0;

  let discountRatio = 0;
  if (hasReferencePrice && input.listedPrice !== undefined && input.referencePrice! > 0) {
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

  const hasSellerRating = input.sellerRating !== undefined && input.sellerRating > 0 ? 1 : 0;
  const lowSellerRating = hasSellerRating && input.sellerRating! < 3.5 ? 1 : 0;
  const highSellerRating = hasSellerRating && input.sellerRating! >= 4.5 ? 1 : 0;
  const returnPolicyStatus = normalizeReturnPolicyStatus(input);
  // Only explicit 'not_available' incurs noReturnPolicy; 'unknown' remains neutral (0)
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

  const vector = (trainedProductModelData.features as (keyof ExtractedProductFeatures)[]).map(
    (key) => features[key] ?? 0
  );

  return { features, vector };
}

function sigmoid(z: number): number {
  if (z > 20) return 1.0;
  if (z < -20) return 0.0;
  return 1 / (1 + Math.exp(-z));
}

/**
 * Predicts product listing risk probability using the trained Logistic Regression model.
 */
export function predictProductRisk(input: ProductAnalysisInput): MlProductResult {
  const { features, vector } = extractProductFeatures(input);

  const means = trainedProductModelData.means;
  const stds = trainedProductModelData.stds;
  const weights = trainedProductModelData.weights;
  const bias = trainedProductModelData.bias;

  const standardized = vector.map((val, idx) => (val - means[idx]) / (stds[idx] || 1));

  let z = bias;
  for (let i = 0; i < standardized.length; i++) {
    z += weights[i] * standardized[i];
  }

  const rawProb = sigmoid(z);
  const probability = Math.round(rawProb * 1000) / 1000;
  const isHighRisk = probability >= 0.5;
  const riskScore = Math.min(100, Math.max(0, Math.round(probability * 100)));

  let riskCategory: RiskCategory = 'lower';
  if (riskScore >= 75) riskCategory = 'high';
  else if (riskScore >= 50) riskCategory = 'elevated';
  else if (riskScore >= 25) riskCategory = 'moderate';

  const indicatorsFlagged: string[] = [];
  if (features.hasReplicaKeyword) {
    indicatorsFlagged.push('Explicit imitation/replica phrasing detected in listing text');
  }
  if (features.hasPaymentPressureKeyword) {
    indicatorsFlagged.push('Unprotected payment demand (wire/crypto/no-dispute phrasing)');
  }
  if (features.hasRiskyListingUrl) {
    indicatorsFlagged.push('Listing URL uses high-risk TLD, raw IP, or unencrypted HTTP');
  }
  if (features.noReturnPolicy) {
    indicatorsFlagged.push('No stated return window or buyer protection policy');
  }
  if (features.lowSellerRating) {
    indicatorsFlagged.push('Low seller feedback rating (< 3.5 / 5.0)');
  }
  if (features.isGenericSellerHandle) {
    indicatorsFlagged.push('Generic or disposable-looking seller handle');
  }
  if (features.isExtremeDiscount && !features.hasClearanceOrRefurbContext) {
    indicatorsFlagged.push(
      `Extreme markdown (${Math.round(features.discountRatio * 100)}% off MSRP) without clearance/refurbished context`
    );
  }

  const datasetLabel = (trainedProductModelData.dataset || '').toLowerCase();
  const isSyntheticDataset =
    datasetLabel.includes('curated') ||
    datasetLabel.includes('synthetic') ||
    datasetLabel.includes('product_listings_dataset.csv');

  return {
    productName: input.productName,
    isHighRisk,
    probability,
    riskScore,
    riskCategory,
    modelTrained: true,
    modelType: trainedProductModelData.modelType,
    datasetName: trainedProductModelData.dataset,
    totalDatasetRows: trainedProductModelData.totalDatasetRows,
    trainingSamples: trainedProductModelData.samplesTrained,
    samplesTested: trainedProductModelData.samplesTested,
    isSyntheticDataset,
    metrics: trainedProductModelData.metrics,
    featuresExtracted: features,
    indicatorsFlagged,
    disclaimer: isSyntheticDataset
      ? 'This product listing classifier is currently trained on a synthetic corpus (product_listings_dataset.csv). Its accuracy reflects synthetic training rules—not verified real-world counterfeit detection performance or physical product authenticity.'
      : 'Machine learning classification evaluates listing metadata, pricing variance, and seller signals. It is a caution indicator for suspicious listings and does not inspect physical goods.',
    serviceAvailable: true,
  };
}

export function getProductModelMetadata() {
  const datasetLabel = (trainedProductModelData.dataset || '').toLowerCase();
  const isSyntheticDataset =
    datasetLabel.includes('curated') ||
    datasetLabel.includes('synthetic') ||
    datasetLabel.includes('product_listings_dataset.csv');

  return {
    modelType: trainedProductModelData.modelType,
    dataset: trainedProductModelData.dataset,
    totalDatasetRows: trainedProductModelData.totalDatasetRows,
    samplesTrained: trainedProductModelData.samplesTrained,
    samplesTested: trainedProductModelData.samplesTested,
    trainedAt: trainedProductModelData.trainedAt,
    isSyntheticDataset,
    metrics: trainedProductModelData.metrics,
    featureCount: trainedProductModelData.features.length,
    features: trainedProductModelData.features,
    featureWeights: trainedProductModelData.featureWeights || {},
  };
}
