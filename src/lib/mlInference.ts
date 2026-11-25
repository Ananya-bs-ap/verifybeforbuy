/**
 * VerifyBeforeBuy AI — ML Phishing Inference Engine
 * 
 * Runs real-time inference using model parameters trained on the Kaggle malicious_phish.csv dataset.
 * Extracts lexical and structural URL signals, applies standardized weights,
 * and outputs phishing probability, risk category, and key risk indicators.
 */

import trainedModelData from '../ml_model.json';
import { MlPhishingResult, RiskCategory } from '../types/index.ts';

const SUSPICIOUS_KEYWORDS = [
  'login', 'verify', 'secure', 'account', 'update', 'banking', 'free',
  'discount', 'wholesale', 'outlet', 'cheap', 'bonus', 'winner', 'signin',
  'wallet', 'password', 'confirm', 'claim', 'prize', 'ebay', 'paypal',
  'apple', 'amazon', 'netflix', 'microsoft', 'support', 'service'
];

const HIGH_RISK_TLDS = new Set([
  '.xyz', '.click', '.top', '.work', '.buzz', '.cam', '.rest',
  '.fit', '.cfd', '.monster', '.gq', '.ml', '.cf', '.ga', '.tk',
  '.cc', '.ru', '.cn', '.icu'
]);

const KNOWN_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly',
  'ow.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at'
]);

export interface ExtractedUrlFeatures {
  urlLength: number;
  hostnameLength: number;
  pathLength: number;
  countDots: number;
  countHyphens: number;
  countAt: number;
  countQuestion: number;
  countPercent: number;
  countSlash: number;
  hasIpAddress: number;
  countSubdomains: number;
  hasHttps: number;
  hasHyphenInDomain: number;
  hasSuspiciousKeyword: number;
  isHighRiskTld: number;
  digitRatio: number;
  hasDoubleSlashInPath: number;
  isShortener: number;
}

export function extractUrlFeatures(rawUrl: string): { features: ExtractedUrlFeatures; vector: number[] } {
  let cleanUrl = rawUrl.trim();
  const lowerUrl = cleanUrl.toLowerCase();
  const hasHttps = lowerUrl.startsWith('https://') ? 1 : 0;

  if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
    cleanUrl = 'http://' + cleanUrl;
  }

  let hostname = '';
  let pathStr = '';
  try {
    const parsed = new URL(cleanUrl);
    hostname = parsed.hostname || '';
    pathStr = parsed.pathname || '';
  } catch {
    const noProto = cleanUrl.replace(/^https?:\/\//i, '');
    const firstSlash = noProto.indexOf('/');
    if (firstSlash !== -1) {
      hostname = noProto.substring(0, firstSlash);
      pathStr = noProto.substring(firstSlash);
    } else {
      hostname = noProto;
    }
  }

  const cleanHost = hostname.split(':')[0].toLowerCase();
  const urlLen = rawUrl.length;
  const hostLen = cleanHost.length;
  const pathLen = pathStr.length;

  let digitsCount = 0;
  for (let i = 0; i < rawUrl.length; i++) {
    const code = rawUrl.charCodeAt(i);
    if (code >= 48 && code <= 57) digitsCount++;
  }
  const digitRatio = urlLen > 0 ? Number((digitsCount / urlLen).toFixed(4)) : 0;

  const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(cleanHost) ? 1 : 0;

  let subdomains = 0;
  let hostForSub = cleanHost;
  if (hostForSub.startsWith('www.')) hostForSub = hostForSub.slice(4);
  const parts = hostForSub.split('.');
  if (parts.length > 2) {
    subdomains = parts.length - 2;
  }

  const hasKeyword = SUSPICIOUS_KEYWORDS.some(kw => lowerUrl.includes(kw)) ? 1 : 0;
  const isHighRisk = Array.from(HIGH_RISK_TLDS).some(tld => cleanHost.endsWith(tld)) ? 1 : 0;
  const isShort = KNOWN_SHORTENERS.has(cleanHost) ? 1 : 0;
  const hasDoubleSlash = pathStr.includes('//') ? 1 : 0;

  const features: ExtractedUrlFeatures = {
    urlLength: urlLen,
    hostnameLength: hostLen,
    pathLength: pathLen,
    countDots: (rawUrl.match(/\./g) || []).length,
    countHyphens: (rawUrl.match(/-/g) || []).length,
    countAt: rawUrl.includes('@') ? 1 : 0,
    countQuestion: (rawUrl.match(/\?/g) || []).length,
    countPercent: (rawUrl.match(/%/g) || []).length,
    countSlash: (rawUrl.match(/\//g) || []).length,
    hasIpAddress: isIp,
    countSubdomains: subdomains,
    hasHttps,
    hasHyphenInDomain: cleanHost.includes('-') ? 1 : 0,
    hasSuspiciousKeyword: hasKeyword,
    isHighRiskTld: isHighRisk,
    digitRatio,
    hasDoubleSlashInPath: hasDoubleSlash,
    isShortener: isShort,
  };

  const vector = (trainedModelData.features as (keyof ExtractedUrlFeatures)[]).map(
    key => features[key] ?? 0
  );

  return { features, vector };
}

function sigmoid(z: number): number {
  if (z > 20) return 1.0;
  if (z < -20) return 0.0;
  return 1 / (1 + Math.exp(-z));
}

/**
 * Predicts phishing probability for a given URL using the trained Logistic Regression model.
 */
export function predictPhishing(rawUrl: string): MlPhishingResult {
  const { features, vector } = extractUrlFeatures(rawUrl);

  const means = trainedModelData.means;
  const stds = trainedModelData.stds;
  const weights = trainedModelData.weights;
  const bias = trainedModelData.bias;

  // Standardize input vector
  const standardized = vector.map((val, idx) => (val - means[idx]) / (stds[idx] || 1));

  // Compute logit (z = bias + sum(w_i * x_i))
  let z = bias;
  for (let i = 0; i < standardized.length; i++) {
    z += weights[i] * standardized[i];
  }

  const rawProb = sigmoid(z);
  const probability = Math.round(rawProb * 1000) / 1000;
  const isPhishing = probability >= 0.50;
  const riskScore = Math.min(100, Math.max(0, Math.round(probability * 100)));

  let riskCategory: RiskCategory = 'lower';
  if (riskScore >= 75) {
    riskCategory = 'high';
  } else if (riskScore >= 50) {
    riskCategory = 'elevated';
  } else if (riskScore >= 25) {
    riskCategory = 'moderate';
  }

  // Identify specific flagged indicators from feature values
  const indicatorsFlagged: string[] = [];
  if (features.hasIpAddress) {
    indicatorsFlagged.push('Raw IP address used instead of reputable domain name');
  }
  if (features.isHighRiskTld) {
    indicatorsFlagged.push('Uncommon high-risk Top-Level Domain (TLD) associated with disposable campaigns');
  }
  if (features.hasSuspiciousKeyword) {
    indicatorsFlagged.push('Security/verification keyword embedded in URL path to mimic authentic portal');
  }
  if (features.countSubdomains > 2) {
    indicatorsFlagged.push(`Abnormal subdomain nesting depth (${features.countSubdomains} levels)`);
  }
  if (features.hasHyphenInDomain) {
    indicatorsFlagged.push('Hyphenated hostname structure often used to spoof legitimate brand spellings');
  }
  if (features.countAt > 0) {
    indicatorsFlagged.push('@ character in URL used to deceive browser host recognition');
  }
  if (features.digitRatio > 0.15) {
    indicatorsFlagged.push(`Unusually high numeric character density (${Math.round(features.digitRatio * 100)}%)`);
  }
  if (features.urlLength > 80) {
    indicatorsFlagged.push(`Excessively long URL structure (${features.urlLength} characters)`);
  }
  if (features.isShortener) {
    indicatorsFlagged.push('URL shortening redirection service masking true target endpoint');
  }
  if (features.hasDoubleSlashInPath) {
    indicatorsFlagged.push('Double-slash sequence in path potentially used for open redirection');
  }
  if (!features.hasHttps) {
    indicatorsFlagged.push('Insecure HTTP protocol without transport layer TLS encryption');
  }

  return {
    url: rawUrl,
    isPhishing,
    probability,
    riskScore,
    riskCategory,
    modelTrained: true,
    modelType: trainedModelData.modelType,
    datasetName: trainedModelData.dataset,
    trainingSamples: trainedModelData.samplesTrained,
    metrics: trainedModelData.metrics,
    featuresExtracted: features,
    indicatorsFlagged,
    disclaimer: 'Machine learning classification evaluates website deceptive potential based on lexical URL patterns trained on 80,000 real-world samples. It does not replace physical inspection or constitute formal proof of product authenticity.',
    serviceAvailable: true,
  };
}

export function getModelMetadata() {
  return {
    modelType: trainedModelData.modelType,
    dataset: trainedModelData.dataset,
    totalDatasetRows: trainedModelData.totalDatasetRows,
    samplesTrained: trainedModelData.samplesTrained,
    samplesTested: trainedModelData.samplesTested,
    trainedAt: trainedModelData.trainedAt,
    metrics: trainedModelData.metrics,
    featureCount: trainedModelData.features.length,
    features: trainedModelData.features,
    featureWeights: (trainedModelData as any).featureWeights || {},
  };
}
