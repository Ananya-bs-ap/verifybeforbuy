/**
 * ML Product Listing Risk Model Trainer for VerifyBeforeBuy AI
 *
 * Accepts an externally supplied labelled CSV dataset without automatically generating
 * or overwriting dataset files. Preserves the 11-column schema and 14 Logistic Regression
 * features, using GS1 Modulo-10 checksum validation and 3-state return policy semantics
 * aligned with src/lib/productMlInference.ts.
 *
 * Usage:
 *   npx tsx ml/train_product_model.ts --csv ml/data/your_real_labelled_dataset.csv
 *   npx tsx ml/train_product_model.ts --csv ml/data/your_real_labelled_dataset.csv --dataset-name "Real Marketplace Fraud Dataset"
 */

import fs from 'fs';
import path from 'path';
import { verifyGs1CheckDigit } from '../src/lib/riskEngine/codeAnalyzer.ts';
import { ReturnPolicyStatus } from '../src/types/index.ts';

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

export const EXPECTED_DATASET_COLUMNS = [
  'productName',
  'brand',
  'listedPrice',
  'referencePrice',
  'sellerName',
  'sellerRating',
  'hasReturnPolicy',
  'productDescription',
  'productIdentifier',
  'listingUrl',
  'label',
] as const;

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

export interface RawProductRow {
  productName: string;
  brand: string;
  listedPrice?: number;
  referencePrice?: number;
  sellerName: string;
  sellerRating?: number;
  returnPolicyStatus: ReturnPolicyStatus;
  hasReturnPolicy?: boolean;
  productDescription: string;
  productIdentifier: string;
  listingUrl: string;
  label: 0 | 1; // 0 = lower-risk legitimate listing, 1 = high-risk deceptive listing
}

/**
 * Extract the 14 standardized ML features consistently with src/lib/productMlInference.ts.
 * - Uses GS1 Modulo-10 checksum validation for hasValidGs1Barcode
 * - Treats 'unknown' / missing return policy neutrally (noReturnPolicy = 0)
 */
export function extractProductFeatureVector(row: Omit<RawProductRow, 'label'>): number[] {
  const hasRef = row.referencePrice !== undefined && row.referencePrice > 0 ? 1 : 0;
  let discountRatio = 0;
  if (hasRef && row.listedPrice !== undefined && row.referencePrice! > 0) {
    discountRatio = Math.max(
      0,
      Math.min(1, (row.referencePrice! - row.listedPrice) / row.referencePrice!)
    );
  }
  const isExtremeDiscount = discountRatio >= 0.75 ? 1 : 0;

  const sellerTrim = (row.sellerName || '').trim();
  const hasSellerName = sellerTrim.length > 0 ? 1 : 0;
  const sellerLower = sellerTrim.toLowerCase();
  const isGenericSellerHandle =
    hasSellerName && GENERIC_SELLER_PATTERNS.some((p) => sellerLower.includes(p)) ? 1 : 0;

  const hasSellerRating = row.sellerRating !== undefined && row.sellerRating > 0 ? 1 : 0;
  const lowSellerRating = hasSellerRating && row.sellerRating! < 3.5 ? 1 : 0;
  const highSellerRating = hasSellerRating && row.sellerRating! >= 4.5 ? 1 : 0;

  const returnPolicyStatus: ReturnPolicyStatus =
    row.returnPolicyStatus ||
    (row.hasReturnPolicy === true
      ? 'available'
      : row.hasReturnPolicy === false
        ? 'not_available'
        : 'unknown');
  const noReturnPolicy = returnPolicyStatus === 'not_available' ? 1 : 0;

  const textBlob = `${row.productName} ${row.productDescription}`.toLowerCase();
  const hasReplicaKeyword = REPLICA_KEYWORDS.some((kw) => textBlob.includes(kw)) ? 1 : 0;
  const hasPaymentPressureKeyword = HIGH_PRESSURE_TACTICS.some((kw) => textBlob.includes(kw)) ? 1 : 0;
  const hasClearanceOrRefurbContext = CLEARANCE_CONTEXT_KEYWORDS.some((kw) => textBlob.includes(kw))
    ? 1
    : 0;

  const cleanedCode = (row.productIdentifier || '').replace(/[\s-]/g, '');
  const hasValidGs1Barcode = verifyGs1CheckDigit(cleanedCode) ? 1 : 0;

  const urlLower = (row.listingUrl || '').trim().toLowerCase();
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

  return [
    hasRef,
    Number(discountRatio.toFixed(4)),
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
  ];
}

// Deterministic PRNG (Mulberry32) for reproducible shuffling & splitting
function createRng(seed: number) {
  let state = seed >>> 0;
  return () => {
    state += 0x6d2b79f5;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t ^= t + Math.imul(t ^ (t >>> 7), 61 | t);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Full RFC-4180 multi-line CSV parser supporting quoted fields containing commas/newlines.
 */
function parseCsvRecords(content: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let inQuotes = false;

  const normalized = content.replace(/^\uFEFF/, '');
  for (let i = 0; i < normalized.length; i++) {
    const ch = normalized[i];
    if (inQuotes) {
      if (ch === '"') {
        if (normalized[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ',') {
      row.push(field);
      field = '';
    } else if (ch === '\r') {
      if (normalized[i + 1] === '\n') i++;
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else if (ch === '\n') {
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else {
      field += ch;
    }
  }

  if (field.length > 0 || row.length > 0) {
    row.push(field);
    rows.push(row);
  }

  return rows.filter((r) => r.some((cell) => cell.trim() !== ''));
}

const COLUMN_ALIASES: Record<(typeof EXPECTED_DATASET_COLUMNS)[number], string[]> = {
  productName: ['productname', 'product_name', 'title', 'name', 'item_name'],
  brand: ['brand', 'manufacturer', 'brand_name'],
  listedPrice: ['listedprice', 'listed_price', 'discounted_price', 'sale_price', 'price'],
  referencePrice: ['referenceprice', 'reference_price', 'retail_price', 'msrp', 'original_price'],
  sellerName: ['sellername', 'seller_name', 'merchant', 'store_name', 'seller'],
  sellerRating: ['sellerrating', 'seller_rating', 'overall_rating', 'product_rating', 'rating'],
  hasReturnPolicy: ['hasreturnpolicy', 'has_return_policy', 'return_policy', 'returnpolicystatus', 'returns_accepted'],
  productDescription: ['productdescription', 'product_description', 'description', 'notes'],
  productIdentifier: ['productidentifier', 'product_identifier', 'upc', 'gtin', 'ean', 'sku', 'asin', 'uniq_id'],
  listingUrl: ['listingurl', 'listing_url', 'product_url', 'url', 'link'],
  label: ['label', 'is_fraud', 'is_counterfeit', 'is_scam', 'fraudulent', 'risk_label', 'target'],
};

function parseOptionalNumber(raw: string | undefined): number | undefined {
  if (!raw) return undefined;
  const cleaned = raw.replace(/[^0-9.-]/g, '');
  if (!cleaned) return undefined;
  const parsed = Number(cleaned);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function parseReturnPolicyCell(raw: string | undefined): {
  status: ReturnPolicyStatus;
  boolVal?: boolean;
} {
  const val = (raw || '').trim().toLowerCase();
  if (val === 'true' || val === 'available' || val === 'yes' || val === '1') {
    return { status: 'available', boolVal: true };
  }
  if (val === 'false' || val === 'not_available' || val === 'not available' || val === 'no' || val === '0') {
    return { status: 'not_available', boolVal: false };
  }
  return { status: 'unknown', boolVal: undefined };
}

function parseTargetLabel(raw: string | undefined): 0 | 1 | null {
  const val = (raw || '').trim().toLowerCase();
  if (val === '1' || val === 'true' || val === 'fraud' || val === 'counterfeit' || val === 'scam' || val === 'high_risk' || val === 'fake' || val === 'suspicious') {
    return 1;
  }
  if (val === '0' || val === 'false' || val === 'legitimate' || val === 'genuine' || val === 'safe' || val === 'low_risk' || val === 'authentic') {
    return 0;
  }
  return null;
}

function resolveCliArgs(): { csvPath?: string; datasetName?: string } {
  const args = process.argv.slice(2);
  let csvPath = process.env.PRODUCT_DATASET_PATH;
  let datasetName: string | undefined;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--csv' && args[i + 1]) {
      csvPath = args[++i];
    } else if (args[i].startsWith('--csv=')) {
      csvPath = args[i].slice('--csv='.length);
    } else if (args[i] === '--dataset-name' && args[i + 1]) {
      datasetName = args[++i];
    } else if (args[i].startsWith('--dataset-name=')) {
      datasetName = args[i].slice('--dataset-name='.length);
    } else if (!args[i].startsWith('--') && !csvPath) {
      csvPath = args[i];
    }
  }

  return { csvPath, datasetName };
}

export async function runProductTraining() {
  const { csvPath: requestedCsv, datasetName } = resolveCliArgs();

  if (!requestedCsv) {
    console.error('No external dataset CSV specified.');
    console.error(
      'Automatic synthetic dataset generation is disabled so existing data and trained artifacts are never overwritten.'
    );
    console.error('\nTo train on a real externally supplied labelled CSV dataset, run:');
    console.error('  npx tsx ml/train_product_model.ts --csv path/to/real_labelled_listings.csv');
    console.error('\nRequired CSV columns (or supported aliases):');
    console.error(`  ${EXPECTED_DATASET_COLUMNS.join(', ')}`);
    process.exit(1);
  }

  const resolvedCsvPath = path.resolve(requestedCsv);
  if (!fs.existsSync(resolvedCsvPath)) {
    console.error(`Dataset file not found: ${resolvedCsvPath}`);
    process.exit(1);
  }

  console.log('--- Starting Product Listing Risk ML Model Training ---');
  console.log(`Reading externally supplied CSV (read-only): ${resolvedCsvPath}`);

  const rawContent = fs.readFileSync(resolvedCsvPath, 'utf-8');
  const records = parseCsvRecords(rawContent);
  if (records.length < 2) {
    console.error('CSV must contain a header row and at least one labelled data row.');
    process.exit(1);
  }

  const headerLookup = new Map<string, number>();
  records[0].forEach((colName, idx) => {
    headerLookup.set(colName.trim().toLowerCase(), idx);
  });

  const colIndex: Record<string, number> = {};
  for (const canonicalCol of EXPECTED_DATASET_COLUMNS) {
    const matchedAlias = COLUMN_ALIASES[canonicalCol].find((alias) => headerLookup.has(alias));
    if (matchedAlias !== undefined) {
      colIndex[canonicalCol] = headerLookup.get(matchedAlias)!;
    }
  }

  if (colIndex.label === undefined || colIndex.productName === undefined) {
    console.error(
      'Invalid dataset schema: CSV must contain at least a productName/title column and a binary target label column (e.g., label, is_fraud, is_counterfeit).'
    );
    process.exit(1);
  }

  const parsedSamples: { vector: number[]; label: 0 | 1 }[] = [];
  let skippedInvalidRows = 0;

  for (let i = 1; i < records.length; i++) {
    const row = records[i];
    const getCell = (key: string) => (colIndex[key] !== undefined ? row[colIndex[key]] ?? '' : '');

    const label = parseTargetLabel(getCell('label'));
    const productName = getCell('productName').trim();
    if (label === null || !productName) {
      skippedInvalidRows++;
      continue;
    }

    const returnParsed = parseReturnPolicyCell(getCell('hasReturnPolicy'));
    const listedPrice = parseOptionalNumber(getCell('listedPrice'));
    const referencePrice = parseOptionalNumber(getCell('referencePrice'));
    const rawRating = parseOptionalNumber(getCell('sellerRating'));
    const sellerRating =
      rawRating !== undefined && rawRating >= 0 && rawRating <= 5 ? rawRating : undefined;

    const sampleRow: Omit<RawProductRow, 'label'> = {
      productName,
      brand: getCell('brand').trim(),
      listedPrice: listedPrice !== undefined && listedPrice > 0 ? listedPrice : undefined,
      referencePrice: referencePrice !== undefined && referencePrice > 0 ? referencePrice : undefined,
      sellerName: getCell('sellerName').trim(),
      sellerRating,
      returnPolicyStatus: returnParsed.status,
      hasReturnPolicy: returnParsed.boolVal,
      productDescription: getCell('productDescription').trim(),
      productIdentifier: getCell('productIdentifier').trim(),
      listingUrl: getCell('listingUrl').trim(),
    };

    parsedSamples.push({
      vector: extractProductFeatureVector(sampleRow),
      label,
    });
  }

  const class0Count = parsedSamples.filter((s) => s.label === 0).length;
  const class1Count = parsedSamples.filter((s) => s.label === 1).length;
  if (parsedSamples.length < 50 || class0Count === 0 || class1Count === 0) {
    console.error(
      `Insufficient or single-class labelled data (valid rows=${parsedSamples.length}, class0=${class0Count}, class1=${class1Count}). Both class 0 and class 1 examples are required.`
    );
    process.exit(1);
  }

  console.log(
    `Loaded ${parsedSamples.length} labelled listings (class 0=${class0Count}, class 1=${class1Count}, skipped=${skippedInvalidRows}).`
  );

  // Deterministic Fisher-Yates shuffle
  const rng = createRng(987654321);
  for (let i = parsedSamples.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [parsedSamples[i], parsedSamples[j]] = [parsedSamples[j], parsedSamples[i]];
  }

  // 80% Train / 20% Test Split (strictly zero leakage)
  const splitIdx = Math.floor(parsedSamples.length * 0.8);
  const trainData = parsedSamples.slice(0, splitIdx);
  const testData = parsedSamples.slice(splitIdx);

  console.log(`Split: ${trainData.length} training samples, ${testData.length} holdout testing samples`);

  const numFeatures = PRODUCT_FEATURE_KEYS.length;
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

  const standardize = (v: number[]) => v.map((val, idx) => (val - means[idx]) / stds[idx]);
  const sigmoid = (z: number) => {
    if (z > 20) return 1.0;
    if (z < -20) return 0.0;
    return 1 / (1 + Math.exp(-z));
  };

  // Train Logistic Regression with SGD + L2 Regularization
  const weights = new Array(numFeatures).fill(0);
  let bias = 0;
  const learningRate = 0.03;
  const lambda = 0.002;
  const epochs = 30;

  for (let epoch = 1; epoch <= epochs; epoch++) {
    let loss = 0;
    for (const sample of trainData) {
      const x = standardize(sample.vector);
      const y = sample.label;

      let z = bias;
      for (let f = 0; f < numFeatures; f++) {
        z += weights[f] * x[f];
      }
      const pred = sigmoid(z);
      const err = pred - y;

      loss += -(y * Math.log(Math.max(pred, 1e-9)) + (1 - y) * Math.log(Math.max(1 - pred, 1e-9)));

      bias -= learningRate * err;
      for (let f = 0; f < numFeatures; f++) {
        weights[f] -= learningRate * (err * x[f] + lambda * weights[f]);
      }
    }
    loss /= trainData.length;
    if (epoch % 10 === 0 || epoch === 1) {
      console.log(`Epoch ${epoch}/${epochs} - Binary Cross-Entropy Loss: ${loss.toFixed(4)}`);
    }
  }

  // Evaluate on unseen 20% test split
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;

  for (const sample of testData) {
    const x = standardize(sample.vector);
    let z = bias;
    for (let f = 0; f < numFeatures; f++) {
      z += weights[f] * x[f];
    }
    const prob = sigmoid(z);
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

  console.log('\n--- Holdout Test Set Evaluation Results ---');
  console.log(`  Accuracy:  ${(accuracy * 100).toFixed(2)}%`);
  console.log(`  Precision: ${(precision * 100).toFixed(2)}%`);
  console.log(`  Recall:    ${(recall * 100).toFixed(2)}%`);
  console.log(`  F1 Score:  ${(f1 * 100).toFixed(2)}%`);
  console.log(`  Confusion Matrix: TP=${tp}, TN=${tn}, FP=${fp}, FN=${fn}`);

  const featureWeights: Record<string, number> = {};
  PRODUCT_FEATURE_KEYS.forEach((key, idx) => {
    featureWeights[key] = Number(weights[idx].toFixed(4));
  });

  const csvBaseName = path.basename(resolvedCsvPath);
  const artifact = {
    modelType: 'Logistic Regression (Supervised Binary Classification)',
    dataset: datasetName || `External Labelled Dataset (${csvBaseName})`,
    totalDatasetRows: parsedSamples.length,
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
    features: [...PRODUCT_FEATURE_KEYS],
    means,
    stds,
    weights,
    bias,
    featureWeights,
  };

  const out1 = path.resolve('ml/trained_product_model.json');
  const out2 = path.resolve('src/ml_product_model.json');
  fs.writeFileSync(out1, JSON.stringify(artifact, null, 2));
  fs.writeFileSync(out2, JSON.stringify(artifact, null, 2));
  console.log(`\nSaved trained product model to:\n- ${out1}\n- ${out2}`);
}

const isDirectRun =
  typeof process !== 'undefined' &&
  Array.isArray(process.argv) &&
  process.argv[1]?.includes('train_product_model');

if (isDirectRun) {
  runProductTraining().catch((err) => {
    console.error('Product model training failed:', err);
    process.exit(1);
  });
}
