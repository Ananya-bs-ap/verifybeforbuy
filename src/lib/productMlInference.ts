/**
 * VerifyBeforeBuy AI — ML Product Listing Risk Inference Engine
 *
 * Runs real-time inference using Logistic Regression parameters trained with
 * shared feature extraction (src/lib/productFeatureExtractor.ts) on
 * ml/data/product_listings_dataset.csv (10,000 synthetic labelled listings).
 */

import trainedProductModelData from '../ml_product_model.json';
import { MlProductResult, ProductAnalysisInput, RiskCategory } from '../types/index.ts';
import {
  ExtractedProductFeatures,
  extractProductFeatures,
} from './productFeatureExtractor.ts';

export { extractProductFeatures };
export type { ExtractedProductFeatures };

function sigmoid(z: number): number {
  if (z > 20) return 1.0;
  if (z < -20) return 0.0;
  return 1 / (1 + Math.exp(-z));
}

function isSyntheticCorpusLabel(datasetName?: string): boolean {
  const datasetLabel = (datasetName || '').toLowerCase();
  return (
    datasetLabel.includes('curated') ||
    datasetLabel.includes('synthetic') ||
    datasetLabel.includes('product_listings_dataset.csv')
  );
}

/**
 * Predicts product listing risk probability using the trained Logistic Regression model.
 * Shares exact feature extraction logic with ml/train_product_model.ts.
 */
export function predictProductRisk(input: ProductAnalysisInput): MlProductResult {
  const { features, vector } = extractProductFeatures(
    input,
    trainedProductModelData.features
  );

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

  const isSyntheticDataset = isSyntheticCorpusLabel(trainedProductModelData.dataset);

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
    splitMetadata: (trainedProductModelData as any).splitMetadata,
    metrics: trainedProductModelData.metrics,
    featuresExtracted: features,
    indicatorsFlagged,
    disclaimer: isSyntheticDataset
      ? 'Synthetic-data-trained product listing risk classifier (product_listings_dataset.csv). Its evaluation metrics measure fit to synthetic listing patterns—not verified real-world counterfeit detection accuracy or physical product authenticity.'
      : 'Machine learning product listing risk classifier evaluating metadata, pricing variance, and seller signals. It is a caution indicator for suspicious listings and does not verify physical product authenticity.',
    serviceAvailable: true,
  };
}

export function getProductModelMetadata() {
  const isSyntheticDataset = isSyntheticCorpusLabel(trainedProductModelData.dataset);

  return {
    modelType: trainedProductModelData.modelType,
    dataset: trainedProductModelData.dataset,
    totalDatasetRows: trainedProductModelData.totalDatasetRows,
    samplesTrained: trainedProductModelData.samplesTrained,
    samplesTested: trainedProductModelData.samplesTested,
    trainedAt: trainedProductModelData.trainedAt,
    isSyntheticDataset,
    splitMetadata: (trainedProductModelData as any).splitMetadata,
    metrics: trainedProductModelData.metrics,
    featureCount: trainedProductModelData.features.length,
    features: trainedProductModelData.features,
    featureWeights: trainedProductModelData.featureWeights || {},
  };
}
