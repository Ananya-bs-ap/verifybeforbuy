/**
 * ML Product Listing Risk Model Trainer for VerifyBeforeBuy AI
 *
 * 1. Builds a curated, labeled product listing dataset (ml/data/product_listings_dataset.csv)
 *    with 10,000 diverse legitimate and high-risk deceptive product listings, including
 *    anti-bias clearance/refurbished examples.
 * 2. Loads the CSV, extracts 14 structured listing/pricing/seller/content features,
 *    and splits 80% Train / 20% Test without data leakage.
 * 3. Standardizes features strictly using training-set mean & std.
 * 4. Trains a Logistic Regression classifier with L2 regularization.
 * 5. Evaluates Accuracy, Precision, Recall, F1 Score, and Confusion Matrix on the holdout test set.
 * 6. Exports genuine trained parameters and metrics to ml/trained_product_model.json & src/ml_product_model.json.
 */

import fs from 'fs';
import path from 'path';

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
  hasReturnPolicy: boolean;
  productDescription: string;
  productIdentifier: string;
  listingUrl: string;
  label: 0 | 1; // 0 = lower-risk legitimate listing, 1 = high-risk deceptive listing
}

export function extractProductFeatureVector(row: Omit<RawProductRow, 'label'>): number[] {
  const hasRef = row.referencePrice !== undefined && row.referencePrice > 0 ? 1 : 0;
  let discountRatio = 0;
  if (hasRef && row.listedPrice !== undefined && row.referencePrice! > 0) {
    discountRatio = Math.max(0, Math.min(1, (row.referencePrice! - row.listedPrice) / row.referencePrice!));
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
  const noReturnPolicy = row.hasReturnPolicy === false ? 1 : 0;

  const textBlob = `${row.productName} ${row.productDescription}`.toLowerCase();
  const hasReplicaKeyword = REPLICA_KEYWORDS.some((kw) => textBlob.includes(kw)) ? 1 : 0;
  const hasPaymentPressureKeyword = HIGH_PRESSURE_TACTICS.some((kw) => textBlob.includes(kw)) ? 1 : 0;
  const hasClearanceOrRefurbContext = CLEARANCE_CONTEXT_KEYWORDS.some((kw) => textBlob.includes(kw)) ? 1 : 0;

  const cleanedCode = (row.productIdentifier || '').replace(/[\s-]/g, '');
  const hasValidGs1Barcode = /^\d{8}$|^\d{12}$|^\d{13}$|^\d{14}$/.test(cleanedCode) ? 1 : 0;

  const urlLower = (row.listingUrl || '').trim().toLowerCase();
  let hasRiskyListingUrl = 0;
  if (urlLower.length > 0) {
    const usesHttp = urlLower.startsWith('http://');
    const usesAbuseTld = HIGH_ABUSE_TLDS.some((tld) => urlLower.includes(tld));
    const hasIp = /\b\d{1,3}(\.\d{1,3}){3}\b/.test(urlLower);
    const hasSuspiciousPath = urlLower.includes('cheap') || urlLower.includes('outlet-deals') || urlLower.includes('verify');
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

// Deterministic PRNG (Mulberry32) for reproducible dataset creation and splitting
function createRng(seed: number) {
  let state = seed >>> 0;
  return () => {
    state += 0x6d2b79f5;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t ^= t + Math.imul(t ^ (t >>> 7), 61 | t);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function generateCuratedDataset(totalRows = 10000): RawProductRow[] {
  const rng = createRng(20261124);
  const pick = <T>(arr: T[]): T => arr[Math.floor(rng() * arr.length)];
  const randRange = (min: number, max: number) => min + rng() * (max - min);

  const brands = ['Sony', 'Apple', 'Nike', 'Samsung', 'Bose', 'Dyson', 'Rolex', 'Garmin', 'Canon', 'Coach'];
  const products = [
    'Wireless Noise Cancelling Headphones',
    'Smart Watch Series 9',
    'Running Sneakers Pro',
    'OLED Gaming Monitor',
    'Cordless Vacuum V15',
    'Automatic Dive Watch',
    'Mirrorless Camera Kit',
    'Leather Crossbody Bag',
    'Pro Earbuds 2nd Gen',
    'Bluetooth Portable Speaker',
  ];
  const reputableSellers = [
    'DirectRecertifiedAudio',
    'BestBuy Marketplace',
    'OfficialBrandOutlet',
    'VerifiedTechSupply',
    'AuthorizedRetailGroup',
    'NorthStarElectronics',
    'PrimeAudioDepot',
  ];
  const sketchySellers = [
    'deals_king_99',
    'store123_outlet',
    'discount_outlet_vip',
    'luxury-outlet-express',
    'user99_imports',
    'anon_shop_direct',
    'flashsale_hub',
  ];
  const safeUrls = [
    'https://www.amazon.com/dp/B08N5WRWNW',
    'https://www.bestbuy.com/site/product/64501',
    'https://www.ebay.com/itm/295123456',
    'https://www.target.com/p/certified-item',
    'https://www.walmart.com/ip/verified-electronics',
    '',
  ];
  const riskyUrls = [
    'https://luxury-outlet-deals.xyz/item/promo',
    'https://official-brand-cheap-outlet.top/checkout',
    'http://45.33.32.156:8080/shop-deal',
    'https://brand-clearance-verify.click/order',
    'https://vip-discount-store.work/buy-now',
    '',
  ];
  const validBarcodes = ['027242919419', '012000000133', '5000112637922', '190199220019', '8806094211023'];

  const rows: RawProductRow[] = [];
  const half = Math.floor(totalRows / 2);

  // 1. Generate Lower-Risk / Legitimate Listings (label = 0)
  for (let i = 0; i < half; i++) {
    const brand = pick(brands);
    const prod = pick(products);
    const refPrice = Number(randRange(80, 1200).toFixed(2));

    // Realistic mix: standard retail (55%), steep legitimate clearance/refurbished (22%),
    // minimal-info casual listing (13%), independent final-sale / imperfect rating seller (10%)
    const subtypeRoll = rng();
    let listedPrice: number | undefined = Number((refPrice * randRange(0.70, 1.05)).toFixed(2));
    let referencePrice: number | undefined = refPrice;
    let sellerName = pick(reputableSellers);
    let sellerRating: number | undefined = Number(randRange(4.0, 5.0).toFixed(1));
    let hasReturnPolicy = rng() > 0.14; // some legit vintage/final-sale sellers have no returns
    let description = `Brand new ${brand} ${prod} with standard manufacturer warranty and tracked shipping.`;
    let barcode = rng() > 0.30 ? pick(validBarcodes) : '';
    let url = pick(safeUrls);

    if (subtypeRoll > 0.55 && subtypeRoll <= 0.77) {
      // Legitimate steep clearance / refurbished item (anti-bias training scenario!)
      listedPrice = Number((refPrice * randRange(0.10, 0.38)).toFixed(2));
      description = `Official factory refurbished clearance ${brand} ${prod}. 30-day return policy and full original accessories included.`;
      hasReturnPolicy = true;
      sellerRating = Number(randRange(4.3, 5.0).toFixed(1));
    } else if (subtypeRoll > 0.77 && subtypeRoll <= 0.90) {
      // Minimal information casual/artisan listing (missing fields != fraud)
      referencePrice = undefined;
      sellerName = rng() > 0.5 ? 'ArtisanWorkshop' : '';
      sellerRating = undefined;
      barcode = '';
      url = '';
      description = `Gently used or handcrafted item in good condition.`;
    } else if (subtypeRoll > 0.90) {
      // Legit independent marketplace seller with steep used discount, imperfect rating, or generic handle
      listedPrice = Number((refPrice * randRange(0.25, 0.55)).toFixed(2));
      sellerName = rng() > 0.5 ? pick(sketchySellers) : 'SmallBatchResale';
      sellerRating = Number(randRange(2.9, 3.8).toFixed(1));
      hasReturnPolicy = rng() > 0.5;
      description = `Pre-owned ${brand} ${prod}, tested working, normal wear.`;
    }

    rows.push({
      productName: `${brand} ${prod}`,
      brand,
      listedPrice,
      referencePrice,
      sellerName,
      sellerRating,
      hasReturnPolicy,
      productDescription: description,
      productIdentifier: barcode,
      listingUrl: url,
      label: 0,
    });
  }

  // 2. Generate High-Risk / Deceptive Listings (label = 1)
  for (let i = 0; i < totalRows - half; i++) {
    const brand = pick(brands);
    const prod = pick(products);
    const refPrice = Number(randRange(180, 3500).toFixed(2));
    // Most are steeply discounted, though ~18% price near retail to fool buyers
    const listedPrice =
      rng() < 0.82
        ? Number((refPrice * randRange(0.04, 0.38)).toFixed(2))
        : Number((refPrice * randRange(0.55, 0.85)).toFixed(2));

    const hasReplica = rng() < 0.45;
    const hasPaymentPressure = rng() < 0.48;
    const ratingRoll = rng();
    // 55% low rating, 30% no rating (new unverified store), 15% decent/fake rating
    const sellerRating =
      ratingRoll < 0.55
        ? Number(randRange(1.2, 3.3).toFixed(1))
        : ratingRoll < 0.85
          ? undefined
          : Number(randRange(3.6, 4.4).toFixed(1));
    const hasNoReturns = rng() < 0.78;
    const isGenericSeller = rng() < 0.65;
    const usesSketchyUrl = rng() < 0.58;

    const descParts: string[] = [`Hot deal ${brand} ${prod}!`];
    if (hasReplica) descParts.push(pick(REPLICA_KEYWORDS) + ' quality.');
    if (hasPaymentPressure) descParts.push(`Pay via ${pick(HIGH_PRESSURE_TACTICS)}.`);
    if (!hasReplica && !hasPaymentPressure) {
      descParts.push('Limited stock direct factory drop, no box, no receipt.');
    }

    rows.push({
      productName: `${brand} ${prod}`,
      brand,
      listedPrice,
      referencePrice: rng() > 0.18 ? refPrice : undefined,
      sellerName: isGenericSeller ? pick(sketchySellers) : rng() > 0.25 ? 'QuickDropMerchants' : '',
      sellerRating,
      hasReturnPolicy: !hasNoReturns,
      productDescription: descParts.join(' '),
      productIdentifier: rng() < 0.70 ? `SKU-${Math.floor(randRange(1000, 9999))}` : pick(validBarcodes),
      listingUrl: usesSketchyUrl ? pick(riskyUrls.filter(Boolean)) : pick(safeUrls),
      label: 1,
    });
  }

  return rows;
}

function escapeCsv(val: string | number | boolean | undefined): string {
  if (val === undefined || val === null) return '';
  const str = String(val);
  if (str.includes(',') || str.includes('"') || str.includes('\n')) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

function parseCsvLine(line: string): string[] {
  const result: string[] = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (ch === ',' && !inQuotes) {
      result.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  result.push(current);
  return result;
}

async function runProductTraining() {
  console.log('--- Starting Product Listing Risk ML Model Training ---');

  const dataDir = path.resolve('ml/data');
  fs.mkdirSync(dataDir, { recursive: true });
  const csvPath = path.join(dataDir, 'product_listings_dataset.csv');

  const generated = generateCuratedDataset(10000);
  const header = [
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
  ].join(',');

  const csvLines = [
    header,
    ...generated.map((r) =>
      [
        escapeCsv(r.productName),
        escapeCsv(r.brand),
        escapeCsv(r.listedPrice),
        escapeCsv(r.referencePrice),
        escapeCsv(r.sellerName),
        escapeCsv(r.sellerRating),
        escapeCsv(r.hasReturnPolicy),
        escapeCsv(r.productDescription),
        escapeCsv(r.productIdentifier),
        escapeCsv(r.listingUrl),
        escapeCsv(r.label),
      ].join(',')
    ),
  ];

  fs.writeFileSync(csvPath, csvLines.join('\n'), 'utf-8');
  console.log(`Dataset saved to ${csvPath} (${generated.length} labeled listings).`);

  // Reload from CSV to verify clean end-to-end parsing
  const rawContent = fs.readFileSync(csvPath, 'utf-8').trim().split('\n');
  const parsedSamples: { vector: number[]; label: 0 | 1 }[] = [];

  for (let i = 1; i < rawContent.length; i++) {
    const cols = parseCsvLine(rawContent[i]);
    if (cols.length < 11) continue;
    const row: Omit<RawProductRow, 'label'> = {
      productName: cols[0],
      brand: cols[1],
      listedPrice: cols[2] ? parseFloat(cols[2]) : undefined,
      referencePrice: cols[3] ? parseFloat(cols[3]) : undefined,
      sellerName: cols[4],
      sellerRating: cols[5] ? parseFloat(cols[5]) : undefined,
      hasReturnPolicy: cols[6] === 'true',
      productDescription: cols[7],
      productIdentifier: cols[8],
      listingUrl: cols[9],
    };
    const label = cols[10].trim() === '1' ? 1 : 0;
    parsedSamples.push({
      vector: extractProductFeatureVector(row),
      label,
    });
  }

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

  const artifact = {
    modelType: 'Logistic Regression (Supervised Binary Classification)',
    dataset: 'Curated Product Listing Risk Corpus (product_listings_dataset.csv)',
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

runProductTraining().catch((err) => {
  console.error('Product model training failed:', err);
  process.exit(1);
});
