/**
 * ML Product Listing Risk Model Trainer for VerifyBeforeBuy AI
 *
 * Accepts an externally supplied labelled CSV dataset without automatically generating
 * or overwriting dataset files. Uses the shared feature extractor in
 * src/lib/productFeatureExtractor.ts (GS1 Modulo-10 checksum, 3-state return policy,
 * currency compatibility) and a deterministic, stratified, group-aware train/test split.
 *
 * Usage:
 *   npx tsx ml/train_product_model.ts --csv ml/data/product_listings_dataset.csv
 *   npx tsx ml/train_product_model.ts --csv path/to/your_real_labelled_dataset.csv --dataset-name "Real Marketplace Fraud Dataset"
 */

import fs from 'fs';
import path from 'path';
import {
  extractProductFeatures,
  PRODUCT_FEATURE_KEYS,
  ProductFeatureKey,
} from '../src/lib/productFeatureExtractor.ts';
import { ProductAnalysisInput, ReturnPolicyStatus } from '../src/types/index.ts';

export { PRODUCT_FEATURE_KEYS, extractProductFeatures };
export type { ProductFeatureKey };

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

const OPTIONAL_DATASET_COLUMNS = ['currency', 'referenceCurrency'] as const;

export interface RawProductRow extends ProductAnalysisInput {
  label: 0 | 1; // 0 = lower-risk listing, 1 = high-risk deceptive listing
}

/**
 * Shared feature extraction wrapper for training/test rows.
 */
export function extractProductFeatureVector(
  row: Omit<RawProductRow, 'label'>
): number[] {
  return extractProductFeatures(row, PRODUCT_FEATURE_KEYS).vector;
}

// Deterministic PRNG (Mulberry32) for reproducible shuffling & splitting
function createRng(seed: number) {
  let state = seed >>> 0;
  return () => {
    state += 0x6d2b79f5;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t ^= t + Math.imul(t ^ (t >>> 7), 61 | state);
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

const COLUMN_ALIASES: Record<
  (typeof EXPECTED_DATASET_COLUMNS)[number] | (typeof OPTIONAL_DATASET_COLUMNS)[number],
  string[]
> = {
  productName: ['productname', 'product_name', 'title', 'name', 'item_name'],
  brand: ['brand', 'manufacturer', 'brand_name'],
  listedPrice: ['listedprice', 'listed_price', 'discounted_price', 'sale_price', 'price'],
  referencePrice: ['referenceprice', 'reference_price', 'retail_price', 'msrp', 'original_price'],
  currency: ['currency', 'listed_currency', 'price_currency'],
  referenceCurrency: ['referencecurrency', 'reference_currency', 'msrp_currency'],
  sellerName: ['sellername', 'seller_name', 'merchant', 'store_name', 'seller'],
  sellerRating: ['sellerrating', 'seller_rating', 'overall_rating', 'product_rating', 'rating'],
  hasReturnPolicy: [
    'hasreturnpolicy',
    'has_return_policy',
    'return_policy',
    'returnpolicystatus',
    'returns_accepted',
  ],
  productDescription: ['productdescription', 'product_description', 'description', 'notes'],
  productIdentifier: [
    'productidentifier',
    'product_identifier',
    'upc',
    'gtin',
    'ean',
    'sku',
    'asin',
    'uniq_id',
  ],
  listingUrl: ['listingurl', 'listing_url', 'product_url', 'url', 'link'],
  label: [
    'label',
    'is_fraud',
    'is_counterfeit',
    'is_scam',
    'fraudulent',
    'risk_label',
    'target',
  ],
};

function parseOptionalNumber(raw: string | undefined): number | undefined {
  if (!raw) return undefined;
  const cleaned = raw.replace(/[^0-9.-]/g, '');
  if (!cleaned) return undefined;
  const parsed = Number(cleaned);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function parseOptionalCurrency(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  const upper = raw.trim().toUpperCase();
  return /^[A-Z]{3}$/.test(upper) ? upper : undefined;
}

function parseReturnPolicyCell(raw: string | undefined): {
  status: ReturnPolicyStatus;
  boolVal?: boolean;
} {
  const val = (raw || '').trim().toLowerCase();
  if (val === 'true' || val === 'available' || val === 'yes' || val === '1') {
    return { status: 'available', boolVal: true };
  }
  if (
    val === 'false' ||
    val === 'not_available' ||
    val === 'not available' ||
    val === 'no' ||
    val === '0'
  ) {
    return { status: 'not_available', boolVal: false };
  }
  return { status: 'unknown', boolVal: undefined };
}

function parseTargetLabel(raw: string | undefined): 0 | 1 | null {
  const val = (raw || '').trim().toLowerCase();
  if (
    val === '1' ||
    val === 'true' ||
    val === 'fraud' ||
    val === 'counterfeit' ||
    val === 'scam' ||
    val === 'high_risk' ||
    val === 'fake' ||
    val === 'suspicious'
  ) {
    return 1;
  }
  if (
    val === '0' ||
    val === 'false' ||
    val === 'legitimate' ||
    val === 'genuine' ||
    val === 'safe' ||
    val === 'low_risk' ||
    val === 'authentic'
  ) {
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

interface ParsedSample {
  vector: number[];
  vectorKey: string;
  templateKey: string;
  coarseDescriptionTemplate: string;
  label: 0 | 1;
}

function normalizeDescriptionTemplate(productName: string, productDescription: string): string {
  const trimmedName = productName.trim();
  let template = productDescription.trim();
  if (trimmedName.length > 0) {
    template = template.split(trimmedName).join('<PRODUCT>');
    const lowerName = trimmedName.toLowerCase();
    const lowerDesc = template.toLowerCase();
    const idx = lowerDesc.indexOf(lowerName);
    if (idx !== -1) {
      template = template.slice(0, idx) + '<PRODUCT>' + template.slice(idx + lowerName.length);
    }
  }
  return template.replace(/\s+/g, ' ').trim().toLowerCase();
}

function buildListingTemplateKey(row: Omit<RawProductRow, 'label'>, descTemplate: string): string {
  const seller = (row.sellerName || '').trim().toLowerCase();
  const url = (row.listingUrl || '').trim().toLowerCase();
  const ret = row.returnPolicyStatus || 'unknown';
  const rawId = (row.productIdentifier || '').trim();
  const idPattern = /^sku-\d+$/i.test(rawId) ? 'SKU-*' : rawId.toLowerCase();
  return `${descTemplate}||${seller}||${url}||${ret}||${idPattern}`;
}

/**
 * Deterministic, stratified, group-aware 80/20 split using Union-Find connected components
 * across BOTH exact feature vectors and normalized listing templates.
 */
function stratifiedGroupSplit(samples: ParsedSample[], seed = 987654321) {
  const n = samples.length;
  const parent = Array.from({ length: n }, (_, i) => i);
  const find = (x: number): number => {
    while (parent[x] !== x) {
      parent[x] = parent[parent[x]];
      x = parent[x];
    }
    return x;
  };
  const union = (a: number, b: number) => {
    const ra = find(a);
    const rb = find(b);
    if (ra !== rb) parent[rb] = ra;
  };

  const firstByVec = new Map<string, number>();
  const firstByTemplate = new Map<string, number>();

  for (let i = 0; i < n; i++) {
    const s = samples[i];
    const existingVec = firstByVec.get(s.vectorKey);
    if (existingVec !== undefined) union(i, existingVec);
    else firstByVec.set(s.vectorKey, i);

    const existingTmpl = firstByTemplate.get(s.templateKey);
    if (existingTmpl !== undefined) union(i, existingTmpl);
    else firstByTemplate.set(s.templateKey, i);
  }

  const componentMap = new Map<number, number[]>();
  for (let i = 0; i < n; i++) {
    const root = find(i);
    let arr = componentMap.get(root);
    if (!arr) {
      arr = [];
      componentMap.set(root, arr);
    }
    arr.push(i);
  }

  interface ComponentGroup {
    indices: number[];
    c0: number;
    c1: number;
    majorityLabel: 0 | 1;
  }

  const groups0: ComponentGroup[] = [];
  const groups1: ComponentGroup[] = [];
  let mixedLabelGroups = 0;

  for (const indices of componentMap.values()) {
    let c0 = 0;
    let c1 = 0;
    for (const idx of indices) {
      if (samples[idx].label === 0) c0++;
      else c1++;
    }
    if (c0 > 0 && c1 > 0) mixedLabelGroups++;
    const majorityLabel: 0 | 1 = c0 >= c1 ? 0 : 1;
    const grp: ComponentGroup = { indices, c0, c1, majorityLabel };
    if (majorityLabel === 0) groups0.push(grp);
    else groups1.push(grp);
  }

  const rng = createRng(seed);
  const shuffle = <T>(arr: T[]) => {
    for (let i = arr.length - 1; i > 0; i--) {
      const j = Math.floor(rng() * (i + 1));
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
  };

  shuffle(groups0);
  shuffle(groups1);

  const totalC0 = samples.filter((s) => s.label === 0).length;
  const totalC1 = samples.filter((s) => s.label === 1).length;
  const targetTestC0 = Math.round(totalC0 * 0.2);
  const targetTestC1 = Math.round(totalC1 * 0.2);

  const trainIndices: number[] = [];
  const testIndices: number[] = [];
  let testC0 = 0;
  let testC1 = 0;

  const assignStratum = (
    groups: ComponentGroup[],
    stratumTargetTest: number,
    stratumTotal: number,
    isClass0: boolean
  ) => {
    // Keep very large components (>12% of stratum) in training so test split remains balanced ~20%
    const maxSingleTestGroup = Math.max(25, Math.floor(stratumTotal * 0.12));
    for (const g of groups) {
      const countForStratum = isClass0 ? g.c0 : g.c1;
      const currentTest = isClass0 ? testC0 : testC1;
      const canPlaceInTest =
        g.indices.length <= maxSingleTestGroup &&
        currentTest < stratumTargetTest &&
        currentTest + countForStratum <= Math.round(stratumTargetTest * 1.05);

      if (canPlaceInTest) {
        testIndices.push(...g.indices);
        testC0 += g.c0;
        testC1 += g.c1;
      } else {
        trainIndices.push(...g.indices);
      }
    }
  };

  assignStratum(groups0, targetTestC0, totalC0, true);
  assignStratum(groups1, targetTestC1, totalC1, false);

  // Shuffle sample ordering within train & test deterministically for SGD
  shuffle(trainIndices);
  shuffle(testIndices);

  const trainData = trainIndices.map((idx) => samples[idx]);
  const testData = testIndices.map((idx) => samples[idx]);

  // Verify zero leakage of exact feature vectors and listing templates
  const trainVecs = new Set(trainData.map((s) => s.vectorKey));
  const testVecs = new Set(testData.map((s) => s.vectorKey));
  let featureVectorOverlapCount = 0;
  for (const v of testVecs) {
    if (trainVecs.has(v)) featureVectorOverlapCount++;
  }

  const trainTmpls = new Set(trainData.map((s) => s.templateKey));
  const testTmpls = new Set(testData.map((s) => s.templateKey));
  let listingTemplateOverlapCount = 0;
  for (const t of testTmpls) {
    if (trainTmpls.has(t)) listingTemplateOverlapCount++;
  }

  const trainCoarseDescs = new Set(trainData.map((s) => s.coarseDescriptionTemplate));
  const testCoarseDescs = new Set(testData.map((s) => s.coarseDescriptionTemplate));
  let coarseDescOverlap = 0;
  for (const d of testCoarseDescs) {
    if (trainCoarseDescs.has(d)) coarseDescOverlap++;
  }

  return {
    trainData,
    testData,
    splitMetadata: {
      strategy: 'Stratified Group-Aware Connected-Component Split (80/20 target)',
      totalGroups: componentMap.size,
      mixedLabelGroups,
      featureVectorOverlap: featureVectorOverlapCount,
      listingTemplateOverlap: listingTemplateOverlapCount,
      coarseDescriptionTemplatesUniqueTest: testCoarseDescs.size,
      coarseDescriptionTemplatesSharedWithTrain: coarseDescOverlap,
      coarseDescriptionOverlapNote:
        `${coarseDescOverlap}/${testCoarseDescs.size} coarse description sentence templates appear in both splits because the synthetic corpus reuses a small fixed pool of sentence patterns across listings.`,
      trainClass0: trainData.filter((s) => s.label === 0).length,
      trainClass1: trainData.filter((s) => s.label === 1).length,
      testClass0: testData.filter((s) => s.label === 0).length,
      testClass1: testData.filter((s) => s.label === 1).length,
    },
  };
}

/**
 * Exact Mann-Whitney / Wilcoxon rank-sum ROC-AUC with average rank tie handling.
 */
function computeRocAuc(scored: Array<{ prob: number; actual: 0 | 1 }>): number {
  const positives = scored.filter((s) => s.actual === 1).length;
  const negatives = scored.length - positives;
  if (positives === 0 || negatives === 0) return 0;

  const sorted = [...scored].sort((a, b) => a.prob - b.prob);
  let rankSumPos = 0;
  let i = 0;
  while (i < sorted.length) {
    let j = i + 1;
    while (j < sorted.length && sorted[j].prob === sorted[i].prob) j++;
    // 1-based average rank for ties [i .. j-1]
    const avgRank = (i + 1 + j) / 2;
    for (let k = i; k < j; k++) {
      if (sorted[k].actual === 1) rankSumPos += avgRank;
    }
    i = j;
  }

  return (rankSumPos - (positives * (positives + 1)) / 2) / (positives * negatives);
}

/**
 * Exact step-wise Average Precision / PR-AUC across descending score thresholds.
 */
function computePrAuc(scored: Array<{ prob: number; actual: 0 | 1 }>): number {
  const totalPositives = scored.filter((s) => s.actual === 1).length;
  if (totalPositives === 0) return 0;

  const sorted = [...scored].sort((a, b) => b.prob - a.prob);
  let tp = 0;
  let fp = 0;
  let prevRecall = 0;
  let prAuc = 0;

  let i = 0;
  while (i < sorted.length) {
    let j = i + 1;
    while (j < sorted.length && sorted[j].prob === sorted[i].prob) j++;
    for (let k = i; k < j; k++) {
      if (sorted[k].actual === 1) tp++;
      else fp++;
    }
    const recall = tp / totalPositives;
    const precision = tp / (tp + fp);
    prAuc += (recall - prevRecall) * precision;
    prevRecall = recall;
    i = j;
  }

  return prAuc;
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
  console.log(`Reading CSV (read-only): ${resolvedCsvPath}`);

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
  for (const canonicalCol of [...EXPECTED_DATASET_COLUMNS, ...OPTIONAL_DATASET_COLUMNS]) {
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

  const parsedSamples: ParsedSample[] = [];
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
    const currency = parseOptionalCurrency(getCell('currency'));
    const referenceCurrency = parseOptionalCurrency(getCell('referenceCurrency')) || currency;
    const rawRating = parseOptionalNumber(getCell('sellerRating'));
    const sellerRating =
      rawRating !== undefined && rawRating >= 0 && rawRating <= 5 ? rawRating : undefined;

    const sampleRow: Omit<RawProductRow, 'label'> = {
      productName,
      brand: getCell('brand').trim(),
      listedPrice: listedPrice !== undefined && listedPrice > 0 ? listedPrice : undefined,
      referencePrice: referencePrice !== undefined && referencePrice > 0 ? referencePrice : undefined,
      currency,
      referenceCurrency,
      sellerName: getCell('sellerName').trim(),
      sellerRating,
      returnPolicyStatus: returnParsed.status,
      hasReturnPolicy: returnParsed.boolVal,
      productDescription: getCell('productDescription').trim(),
      productIdentifier: getCell('productIdentifier').trim(),
      listingUrl: getCell('listingUrl').trim(),
    };

    const { vector } = extractProductFeatures(sampleRow, PRODUCT_FEATURE_KEYS);
    const coarseDescriptionTemplate = normalizeDescriptionTemplate(
      sampleRow.productName,
      sampleRow.productDescription || ''
    );
    const templateKey = buildListingTemplateKey(sampleRow, coarseDescriptionTemplate);

    parsedSamples.push({
      vector,
      vectorKey: vector.join('|'),
      templateKey,
      coarseDescriptionTemplate,
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

  // Deterministic, stratified, group-aware 80/20 split preventing identical feature vectors & listing templates from leaking
  const { trainData, testData, splitMetadata } = stratifiedGroupSplit(parsedSamples, 987654321);

  console.log(
    `Group-aware split: ${trainData.length} train (c0=${splitMetadata.trainClass0}, c1=${splitMetadata.trainClass1}) / ${testData.length} test (c0=${splitMetadata.testClass0}, c1=${splitMetadata.testClass1})`
  );
  console.log(
    `Leakage checks: featureVectorOverlap=${splitMetadata.featureVectorOverlap}, listingTemplateOverlap=${splitMetadata.listingTemplateOverlap}, coarseDescOverlap=${splitMetadata.coarseDescriptionTemplatesSharedWithTrain}/${splitMetadata.coarseDescriptionTemplatesUniqueTest}`
  );

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

  // Evaluate on unseen group-aware test split
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  const scoredTest: Array<{ prob: number; actual: 0 | 1 }> = [];

  for (const sample of testData) {
    const x = standardize(sample.vector);
    let z = bias;
    for (let f = 0; f < numFeatures; f++) {
      z += weights[f] * x[f];
    }
    const prob = sigmoid(z);
    const predicted = prob >= 0.5 ? 1 : 0;
    const actual = sample.label;
    scoredTest.push({ prob, actual });

    if (predicted === 1 && actual === 1) tp++;
    else if (predicted === 1 && actual === 0) fp++;
    else if (predicted === 0 && actual === 0) tn++;
    else if (predicted === 0 && actual === 1) fn++;
  }

  const accuracy = (tp + tn) / (tp + tn + fp + fn);
  const precision = tp / (tp + fp) || 0;
  const recall = tp / (tp + fn) || 0;
  const f1 = (2 * precision * recall) / (precision + recall) || 0;
  const rocAuc = computeRocAuc(scoredTest);
  const prAuc = computePrAuc(scoredTest);

  console.log('\n--- Group-Aware Holdout Test Set Evaluation Results ---');
  console.log(`  Accuracy:  ${(accuracy * 100).toFixed(2)}%`);
  console.log(`  Precision: ${(precision * 100).toFixed(2)}%`);
  console.log(`  Recall:    ${(recall * 100).toFixed(2)}%`);
  console.log(`  F1 Score:  ${(f1 * 100).toFixed(2)}%`);
  console.log(`  ROC-AUC:   ${(rocAuc * 100).toFixed(2)}% (${rocAuc.toFixed(4)})`);
  console.log(`  PR-AUC:    ${(prAuc * 100).toFixed(2)}% (${prAuc.toFixed(4)})`);
  console.log(`  Confusion Matrix: TP=${tp}, TN=${tn}, FP=${fp}, FN=${fn}`);

  const featureWeights: Record<string, number> = {};
  PRODUCT_FEATURE_KEYS.forEach((key, idx) => {
    featureWeights[key] = Number(weights[idx].toFixed(4));
  });

  const csvBaseName = path.basename(resolvedCsvPath);
  const resolvedDatasetLabel =
    datasetName ||
    (csvBaseName === 'product_listings_dataset.csv'
      ? 'Synthetic Product Listing Risk Corpus (product_listings_dataset.csv)'
      : `External Labelled Dataset (${csvBaseName})`);

  const artifact = {
    modelType: 'Logistic Regression (Supervised Binary Classification)',
    dataset: resolvedDatasetLabel,
    totalDatasetRows: parsedSamples.length,
    samplesTrained: trainData.length,
    samplesTested: testData.length,
    trainedAt: new Date().toISOString(),
    splitMetadata,
    metrics: {
      accuracy: Number(accuracy.toFixed(4)),
      precision: Number(precision.toFixed(4)),
      recall: Number(recall.toFixed(4)),
      f1Score: Number(f1.toFixed(4)),
      rocAuc: Number(rocAuc.toFixed(4)),
      prAuc: Number(prAuc.toFixed(4)),
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
