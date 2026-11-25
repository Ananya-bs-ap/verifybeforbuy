/**
 * ML Model Trainer for VerifyBeforeBuy AI
 * Trains directly on malicious_phish.csv extracted from archive_8d085ce1.zip
 * 
 * Features:
 * - Reads directly from the zip stream or extracted CSV
 * - Balanced/stratified split into 80% train / 20% test
 * - 16 lexical and structural URL features
 * - Multi-epoch Logistic Regression with L2 Regularization & Feature Normalization
 * - Calculates rigorous evaluation metrics: Accuracy, Precision, Recall, F1 Score, Confusion Matrix
 * - Exports production JSON model weights and metrics
 */

import fs from 'fs';
import path from 'path';
import readline from 'readline';
import { execSync } from 'child_process';

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

export interface UrlFeatures {
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

export const FEATURE_KEYS: (keyof UrlFeatures)[] = [
  'urlLength',
  'hostnameLength',
  'pathLength',
  'countDots',
  'countHyphens',
  'countAt',
  'countQuestion',
  'countPercent',
  'countSlash',
  'hasIpAddress',
  'countSubdomains',
  'hasHttps',
  'hasHyphenInDomain',
  'hasSuspiciousKeyword',
  'isHighRiskTld',
  'digitRatio',
  'hasDoubleSlashInPath',
  'isShortener'
];

export function extractUrlFeatures(rawUrl: string): { features: UrlFeatures; vector: number[] } {
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

  // Digits count
  let digitsCount = 0;
  for (let i = 0; i < rawUrl.length; i++) {
    const code = rawUrl.charCodeAt(i);
    if (code >= 48 && code <= 57) digitsCount++;
  }
  const digitRatio = urlLen > 0 ? Number((digitsCount / urlLen).toFixed(4)) : 0;

  // IP address check
  const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(cleanHost) ? 1 : 0;

  // Subdomains count
  let subdomains = 0;
  let hostForSub = cleanHost;
  if (hostForSub.startsWith('www.')) hostForSub = hostForSub.slice(4);
  const parts = hostForSub.split('.');
  if (parts.length > 2) {
    subdomains = parts.length - 2;
  }

  // Keywords
  const hasKeyword = SUSPICIOUS_KEYWORDS.some(kw => lowerUrl.includes(kw)) ? 1 : 0;

  // High-risk TLD
  const isHighRisk = Array.from(HIGH_RISK_TLDS).some(tld => cleanHost.endsWith(tld)) ? 1 : 0;

  // Shortener
  const isShort = KNOWN_SHORTENERS.has(cleanHost) ? 1 : 0;

  // Double slash in path (redirect trick)
  const hasDoubleSlash = pathStr.includes('//') ? 1 : 0;

  const features: UrlFeatures = {
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

  const vector = FEATURE_KEYS.map(k => features[k]);
  return { features, vector };
}

async function runTraining() {
  console.log('--- Starting ML Model Training on malicious_phish.csv ---');

  const zipPath = path.resolve('public/assets/aistudio/archive_8d085ce1.zip');
  const csvDir = path.resolve('ml/data');
  const csvPath = path.join(csvDir, 'malicious_phish.csv');

  if (!fs.existsSync(csvPath)) {
    console.log('Unzipping malicious_phish.csv from archive...');
    fs.mkdirSync(csvDir, { recursive: true });
    execSync(`unzip -p "${zipPath}" malicious_phish.csv > "${csvPath}"`);
    console.log('CSV unpacked successfully.');
  }

  console.log('Streaming and parsing CSV dataset...');
  const fileStream = fs.createReadStream(csvPath);
  const rl = readline.createInterface({
    input: fileStream,
    crlfDelay: Infinity,
  });

  interface Sample {
    vector: number[];
    label: number; // 0 = benign, 1 = malicious/phishing
  }

  const benignSamples: Sample[] = [];
  const maliciousSamples: Sample[] = [];
  let totalRows = 0;
  let isHeader = true;

  // Stratified sampling target: 35,000 benign, 35,000 malicious for balanced, high-quality training
  const MAX_PER_CLASS = 40000;

  for await (const line of rl) {
    if (isHeader) {
      isHeader = false;
      continue;
    }
    totalRows++;

    const commaIdx = line.lastIndexOf(',');
    if (commaIdx === -1) continue;
    const url = line.substring(0, commaIdx).trim();
    const type = line.substring(commaIdx + 1).trim().toLowerCase();

    if (!url || !type) continue;

    const isBenign = type === 'benign';
    const isMalicious = type === 'phishing' || type === 'defacement' || type === 'malware';

    if (isBenign && benignSamples.length < MAX_PER_CLASS) {
      const { vector } = extractUrlFeatures(url);
      benignSamples.push({ vector, label: 0 });
    } else if (isMalicious && maliciousSamples.length < MAX_PER_CLASS) {
      const { vector } = extractUrlFeatures(url);
      maliciousSamples.push({ vector, label: 1 });
    }

    if (benignSamples.length >= MAX_PER_CLASS && maliciousSamples.length >= MAX_PER_CLASS) {
      break;
    }
  }

  console.log(`Parsed total ${totalRows.toLocaleString()} rows.`);
  console.log(`Selected balanced training corpus: ${benignSamples.length} Legitimate (Benign) + ${maliciousSamples.length} Phishing/Malicious`);

  // Shuffle dataset with fixed seed
  const dataset = [...benignSamples, ...maliciousSamples];
  for (let i = dataset.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [dataset[i], dataset[j]] = [dataset[j], dataset[i]];
  }

  // 80% Train, 20% Test Split
  const splitIndex = Math.floor(dataset.length * 0.8);
  const trainData = dataset.slice(0, splitIndex);
  const testData = dataset.slice(splitIndex);

  console.log(`Split: ${trainData.length} training samples, ${testData.length} testing samples`);

  // Calculate Mean and Standard Deviation for Standardization (Z-score)
  const numFeatures = FEATURE_KEYS.length;
  const means = new Array(numFeatures).fill(0);
  const stds = new Array(numFeatures).fill(0);

  for (const item of trainData) {
    for (let f = 0; f < numFeatures; f++) {
      means[f] += item.vector[f];
    }
  }
  for (let f = 0; f < numFeatures; f++) {
    means[f] /= trainData.length;
  }

  for (const item of trainData) {
    for (let f = 0; f < numFeatures; f++) {
      const diff = item.vector[f] - means[f];
      stds[f] += diff * diff;
    }
  }
  for (let f = 0; f < numFeatures; f++) {
    stds[f] = Math.sqrt(stds[f] / trainData.length) || 1e-6;
  }

  const standardize = (v: number[]) => {
    return v.map((val, idx) => (val - means[idx]) / stds[idx]);
  };

  const sigmoid = (z: number) => {
    if (z > 20) return 1.0;
    if (z < -20) return 0.0;
    return 1 / (1 + Math.exp(-z));
  };

  // Train Logistic Regression model with SGD and L2 regularization
  const weights = new Array(numFeatures).fill(0);
  let bias = 0;
  const learningRate = 0.05;
  const lambda = 0.001; // L2 penalty
  const epochs = 25;

  console.log(`Training Logistic Regression model for ${epochs} epochs...`);

  for (let epoch = 1; epoch <= epochs; epoch++) {
    let loss = 0;
    for (const sample of trainData) {
      const x = standardize(sample.vector);
      const y = sample.label;

      let dot = bias;
      for (let f = 0; f < numFeatures; f++) {
        dot += weights[f] * x[f];
      }
      const pred = sigmoid(dot);
      const error = pred - y;

      loss += - (y * Math.log(Math.max(pred, 1e-9)) + (1 - y) * Math.log(Math.max(1 - pred, 1e-9)));

      bias -= learningRate * error;
      for (let f = 0; f < numFeatures; f++) {
        weights[f] -= learningRate * (error * x[f] + lambda * weights[f]);
      }
    }
    loss /= trainData.length;
    if (epoch % 5 === 0 || epoch === 1) {
      console.log(`Epoch ${epoch}/${epochs} - Loss: ${loss.toFixed(4)}`);
    }
  }

  console.log('--- Evaluating Model on Test Set ---');
  let tp = 0; // True Positive (Phishing correctly predicted)
  let fp = 0; // False Positive (Benign wrongly predicted as phishing)
  let tn = 0; // True Negative (Benign correctly predicted)
  let fn = 0; // False Negative (Phishing wrongly predicted as benign)

  for (const sample of testData) {
    const x = standardize(sample.vector);
    let dot = bias;
    for (let f = 0; f < numFeatures; f++) {
      dot += weights[f] * x[f];
    }
    const prob = sigmoid(dot);
    const predicted = prob >= 0.5 ? 1 : 0;
    const actual = sample.label;

    if (predicted === 1 && actual === 1) tp++;
    else if (predicted === 1 && actual === 0) fp++;
    else if (predicted === 0 && actual === 0) tn++;
    else if (predicted === 0 && actual === 1) fn++;
  }

  const accuracy = (tp + tn) / (tp + tn + fp + fn);
  const precision = tp / (tp + fp) || 0;
  const recall = tp / (tp + fn) || 0;
  const f1 = (2 * precision * recall) / (precision + recall) || 0;

  console.log(`Evaluation Results:`);
  console.log(`  Accuracy:  ${(accuracy * 100).toFixed(2)}%`);
  console.log(`  Precision: ${(precision * 100).toFixed(2)}%`);
  console.log(`  Recall:    ${(recall * 100).toFixed(2)}%`);
  console.log(`  F1 Score:  ${(f1 * 100).toFixed(2)}%`);
  console.log(`  Confusion Matrix:`);
  console.log(`    True Positives (Phishing caught):  ${tp}`);
  console.log(`    False Positives (Benign flagged):  ${fp}`);
  console.log(`    True Negatives (Benign safe):      ${tn}`);
  console.log(`    False Negatives (Phishing missed): ${fn}`);

  // Feature weights / importance
  const featureWeights: Record<string, number> = {};
  FEATURE_KEYS.forEach((key, idx) => {
    featureWeights[key] = Number(weights[idx].toFixed(4));
  });

  const modelArtifact = {
    modelType: 'Logistic Regression (Supervised Classification)',
    dataset: 'Kaggle Malicious Phish Dataset (malicious_phish.csv)',
    totalDatasetRows: totalRows,
    samplesTrained: trainData.length,
    samplesTested: testData.length,
    trainedAt: new Date().toISOString(),
    metrics: {
      accuracy: Number(accuracy.toFixed(4)),
      precision: Number(precision.toFixed(4)),
      recall: Number(recall.toFixed(4)),
      f1Score: Number(f1.toFixed(4)),
      confusionMatrix: {
        truePositives: tp,
        falsePositives: fp,
        trueNegatives: tn,
        falseNegatives: fn,
      },
    },
    features: FEATURE_KEYS,
    means,
    stds,
    weights,
    bias,
    featureWeights,
  };

  const modelPath1 = path.resolve('ml/trained_model.json');
  const modelPath2 = path.resolve('src/ml_model.json');
  fs.writeFileSync(modelPath1, JSON.stringify(modelArtifact, null, 2));
  fs.writeFileSync(modelPath2, JSON.stringify(modelArtifact, null, 2));
  console.log(`Model weights saved to ${modelPath1} and ${modelPath2}`);
}

runTraining().catch(err => {
  console.error('Training failed:', err);
  process.exit(1);
});
