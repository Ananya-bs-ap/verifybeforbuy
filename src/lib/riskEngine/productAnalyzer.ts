/**
 * Product Listing & Seller Risk Analyzer
 * 
 * Evaluates listing details, price variance, seller information completeness,
 * and description patterns without falsely labeling steep discounts as counterfeit.
 * 
 * Critical rule: Never claim a product is fake or genuine solely due to price.
 * Low price = trigger for further inspection, NOT proof of fraud.
 * Missing fields = reduced confidence/coverage, NOT fraud penalty.
 */

import {
  ProductAnalysisInput,
  RiskIndicator,
  PositiveSignal,
  BarcodeLookupResult,
  BarcodeProductInfo,
} from '../../types';
import { validateGs1BarcodeFormat } from './codeAnalyzer';
import { areCurrenciesCompatible, normalizeReturnPolicyStatus } from '../productValidator';

interface AnalyzedProductResult {
  indicators: RiskIndicator[];
  positiveSignals: PositiveSignal[];
  evidenceWeight: number; // 0 - 100
  unverifiedAspects: string[];
}

const GENERIC_COMPARISON_STOPWORDS = new Set([
  'the', 'and', 'for', 'with', 'new', 'pack', 'size', 'can', 'bottle', 'box',
  'oz', 'fl', 'ml', 'g', 'kg', 'lb', 'gram', 'grams', 'liter', 'litre', 'fluid',
  'ounce', 'aluminum', 'refurbished', 'clearance', 'original', 'authentic',
  'official', 'demo', 'specimen', 'synthetic', 'item', 'product', 'edition',
  'series', 'model', 'version', 'inc', 'corp', 'ltd', 'llc',
]);

function normalizeCompareText(value: string): string {
  return value
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function tokenizeMeaningful(value: string): string[] {
  return normalizeCompareText(value)
    .split(' ')
    .filter((token) => token.length >= 2 && !GENERIC_COMPARISON_STOPWORDS.has(token));
}

/**
 * Compares user-submitted Product Name & Brand against an external barcode database record.
 * Treats mismatches strictly as potential warning indicators, never definitive proof of counterfeiting.
 */
export function compareProductWithBarcodeDb(
  input: ProductAnalysisInput,
  dbProduct: BarcodeProductInfo,
  isLiveDatabase: boolean = true
): {
  indicators: RiskIndicator[];
  positiveSignals: PositiveSignal[];
  unverifiedAspects: string[];
} {
  const indicators: RiskIndicator[] = [];
  const positiveSignals: PositiveSignal[] = [];
  const unverifiedAspects: string[] = [];

  const sourceLabel = isLiveDatabase ? dbProduct.databaseSource : `${dbProduct.databaseSource} (Demo)`;

  // Compare Brand if both entered and available in DB
  const enteredBrandNorm = normalizeCompareText(input.brand || '');
  const dbBrandRaw = dbProduct.brand || '';
  const dbBrandCandidates = dbBrandRaw
    .split(/[,;/|]/)
    .map((b) => normalizeCompareText(b))
    .filter(Boolean);

  if (enteredBrandNorm && dbBrandCandidates.length > 0) {
    const enteredBrandTokens = tokenizeMeaningful(enteredBrandNorm);
    const dbBrandTokens = dbBrandCandidates.flatMap((b) => tokenizeMeaningful(b));

    const brandMatches =
      dbBrandCandidates.some(
        (candidate) =>
          candidate === enteredBrandNorm ||
          candidate.includes(enteredBrandNorm) ||
          enteredBrandNorm.includes(candidate)
      ) ||
      enteredBrandTokens.some((tok) => dbBrandTokens.includes(tok));

    if (!brandMatches) {
      indicators.push({
        id: 'barcode-brand-mismatch',
        name: `Barcode Database Brand Mismatch Warning (${dbBrandRaw})`,
        category: 'verification',
        severity: 'medium',
        scoreImpact: 22,
        isObserved: true,
        description: `The supplied GS1 barcode resolves in ${sourceLabel} to brand "${dbBrandRaw}", which differs from the entered brand "${input.brand}". This discrepancy is a potential warning sign (listing mistake, swapped GTIN, or mislabeled item) and is not definitive proof of counterfeiting.`,
        remedyOrPrecaution: 'Confirm the printed packaging GTIN directly with the manufacturer or ask the seller why the barcode brand differs.',
      });
    } else if (isLiveDatabase) {
      positiveSignals.push({
        id: 'barcode-brand-match',
        name: `Live Barcode Database Brand Alignment (${dbBrandRaw})`,
        description: `Entered brand aligns with ${sourceLabel} record for barcode ${dbProduct.code}. (Note: database alignment does not prove physical item authenticity).`,
        isVerified: true,
        scoreDeduction: 5,
      });
    }
  }

  // Compare Product Name if both entered and available in DB
  const enteredNameNorm = normalizeCompareText(input.productName || '');
  const dbNameNorm = normalizeCompareText(dbProduct.productName || '');
  if (enteredNameNorm && dbNameNorm) {
    const enteredTokens = new Set([
      ...tokenizeMeaningful(enteredNameNorm),
      ...tokenizeMeaningful(input.brand || ''),
    ]);
    const dbNameTokens = tokenizeMeaningful(dbNameNorm);
    const dbAllTokens = new Set([...dbNameTokens, ...tokenizeMeaningful(dbBrandRaw)]);

    const overlappingTokens = dbNameTokens.filter((tok) => enteredTokens.has(tok));
    const directSubstringMatch =
      enteredNameNorm.includes(dbNameNorm) || dbNameNorm.includes(enteredNameNorm);
    const crossBrandTitleOverlap = Array.from(enteredTokens).some((tok) => dbAllTokens.has(tok));

    if (!directSubstringMatch && overlappingTokens.length === 0 && !crossBrandTitleOverlap) {
      indicators.push({
        id: 'barcode-product-name-mismatch',
        name: `Barcode Database Product Name Mismatch Warning`,
        category: 'verification',
        severity: 'medium',
        scoreImpact: 18,
        isObserved: true,
        description: `The GS1 barcode ${dbProduct.code} is registered in ${sourceLabel} as "${dbProduct.productName}", whereas this listing is titled "${input.productName}". Product name mismatches can occur due to wrong-barcode listings, multi-packs, or mislabeling and are not definitive proof of counterfeiting.`,
        remedyOrPrecaution: 'Verify the exact model/SKU and printed UPC/EAN on original product packaging before purchasing.',
      });
    } else if (isLiveDatabase && (directSubstringMatch || overlappingTokens.length > 0)) {
      positiveSignals.push({
        id: 'barcode-name-match',
        name: `Live Barcode Database Title Overlap (${sourceLabel})`,
        description: `Listing title aligns with ${sourceLabel} product entry "${dbProduct.productName}". (Database records cannot verify physical item condition or authenticity).`,
        isVerified: true,
        scoreDeduction: 4,
      });
    }
  }

  unverifiedAspects.push(
    `Physical authenticity of "${input.productName}" (barcode database lookup verifies catalog metadata only)`
  );

  return { indicators, positiveSignals, unverifiedAspects };
}

// Suspicious description phrases often seen in knockoff listings or replica marketing
const REPLICA_KEYWORDS = [
  '1:1 replica', 'mirror copy', 'original clone', 'oem version replica',
  'bypass authenticity', 'unbranded luxury', 'aa grade clone', 'overrun factory stock'
];

const HIGH_PRESSURE_TACTICS = [
  'wire transfer only', 'western union', 'crypto payment only', 'zelle only no buyer protection',
  'act in next 5 minutes or order cancelled', 'do not dispute'
];

export function analyzeProductListing(
  input: ProductAnalysisInput,
  barcodeLookup?: BarcodeLookupResult
): AnalyzedProductResult {
  const indicators: RiskIndicator[] = [];
  const positiveSignals: PositiveSignal[] = [];
  const unverifiedAspects: string[] = [];

  let evidencePoints = 0;
  const maxPossibleEvidence = 80;

  // 1. Evidence coverage audit
  if (input.productName) evidencePoints += 10;
  if (input.brand) evidencePoints += 10;
  if (input.listedPrice !== undefined && input.listedPrice > 0) evidencePoints += 15;
  if (input.referencePrice !== undefined && input.referencePrice > 0) evidencePoints += 15;
  if (input.sellerName) evidencePoints += 15;
  if (input.productDescription) evidencePoints += 10;
  if (input.productIdentifier) evidencePoints += 10;

  // Track what couldn't be independently validated
  unverifiedAspects.push('Physical item in-hand authenticity inspection');
  if (input.sellerRating !== undefined) {
    unverifiedAspects.push('Seller rating authenticity (user-submitted value, not verified via marketplace API)');
  } else {
    unverifiedAspects.push('Independent historical seller feedback & dispute records');
  }
  if (!input.referencePrice) {
    unverifiedAspects.push('Official Manufacturer Suggested Retail Price (MSRP) baseline');
  }

  // 2. Price Analysis (Strict Anti-Bias & Same-Currency Logic)
  const priceCurrency = (input.currency || input.referenceCurrency || 'USD').toUpperCase();
  if (input.listedPrice !== undefined && input.referencePrice !== undefined && input.referencePrice > 0) {
    if (!areCurrenciesCompatible(input.currency, input.referenceCurrency)) {
      unverifiedAspects.push(
        `Price comparison skipped: listed price currency (${input.currency}) differs from reference MSRP currency (${input.referenceCurrency})`
      );
    } else {
      const discount = ((input.referencePrice - input.listedPrice) / input.referencePrice) * 100;

      if (discount >= 85) {
        indicators.push({
          id: 'steep-discount-investigation',
          name: 'Extremely Large Price Variance (>85% off MSRP)',
          category: 'pricing',
          severity: 'medium',
          // Capped score impact - never high risk by itself!
          scoreImpact: 20,
          isObserved: true,
          description: `The item is listed at ${priceCurrency} ${input.listedPrice} vs. typical price of ${priceCurrency} ${input.referencePrice} (${Math.round(discount)}% discount). While clearance or refurbished sales exist, luxury or high-demand electronics at this price point warrant careful verification of seller return guarantees.`,
          remedyOrPrecaution: 'Verify whether the item is refurbished, open-box, seasonal clearance, or sold by an authorized distributor before buying.',
        });
      } else if (discount >= 60) {
        indicators.push({
          id: 'moderate-discount-caution',
          name: 'Significant Price Reduction (60–85% off)',
          category: 'pricing',
          severity: 'low',
          scoreImpact: 10,
          isObserved: true,
          description: `Listed with a ${Math.round(discount)}% price discount (${priceCurrency} ${input.listedPrice} vs ${priceCurrency} ${input.referencePrice}). Legitimate promotions occur regularly; verify seller authenticity credentials.`,
          remedyOrPrecaution: 'Compare with recent sold listings on established marketplaces.',
        });
      } else if (discount <= 25 && discount >= -20) {
        positiveSignals.push({
          id: 'market-aligned-pricing',
          name: 'Market-Consistent Price Range',
          description: `The listed price (${priceCurrency} ${input.listedPrice}) is in line with standard retail market expectations.`,
          isVerified: true,
          scoreDeduction: 10,
        });
      }
    }
  }

  // 3. Seller Assessment
  if (!input.sellerName || input.sellerName.trim() === '') {
    // Missing seller info is noted, but not treated as active fraud
    unverifiedAspects.push('Merchant / Seller Identity is unprovided');
  } else {
    const sName = input.sellerName.toLowerCase();
    const isGenericAnonymous = ['store123', 'deals-shop', 'seller', 'user99', 'discount_outlet'].some(g => sName.includes(g));

    if (isGenericAnonymous) {
      indicators.push({
        id: 'generic-seller-handle',
        name: 'Generic or Anonymous Seller Handle',
        category: 'seller',
        severity: 'low',
        scoreImpact: 12,
        isObserved: false, // user-supplied text
        description: `The seller handle "${input.sellerName}" appears generic or temporary.`,
        remedyOrPrecaution: 'Look for an established registered business name, tax ID, or physical contact address.',
      });
    }

    if (input.sellerRating !== undefined) {
      if (input.sellerRating < 3.0 && input.sellerRating > 0) {
        indicators.push({
          id: 'low-seller-rating',
          name: 'Below-Average User-Reported Seller Rating',
          category: 'seller',
          severity: 'medium',
          scoreImpact: 20,
          isObserved: false, // self-reported
          description: `Reported seller rating is ${input.sellerRating} / 5. Low ratings often indicate delayed shipments, fulfillment cancellations, or customer disputes.`,
          remedyOrPrecaution: 'Review buyer feedback specifically regarding item condition and return disputes.',
        });
      } else if (input.sellerRating >= 4.7) {
        positiveSignals.push({
          id: 'high-reported-rating',
          name: 'Reported High Positive Feedback',
          description: `Reported feedback rating of ${input.sellerRating} / 5 (note: unverified self-report).`,
          isVerified: false,
          scoreDeduction: 5,
        });
      }
    }
  }

  // 4. Return Policy & Buyer Protection (3-state: available | not_available | unknown)
  const returnPolicyStatus = normalizeReturnPolicyStatus(input);
  if (returnPolicyStatus === 'not_available') {
    indicators.push({
      id: 'no-return-policy',
      name: 'No Stated Return or Refund Guarantee',
      category: 'seller',
      severity: 'medium',
      scoreImpact: 18,
      isObserved: false,
      description: 'The listing explicitly states no returns or refunds ("as-is / final sale"), transferring financial risk to the buyer.',
      remedyOrPrecaution: 'Only make purchases where platform buyer protection or standard 14–30 day returns are guaranteed.',
    });
  } else if (returnPolicyStatus === 'available') {
    positiveSignals.push({
      id: 'returns-accepted',
      name: 'Return / Refund Guarantee Stated',
      description: 'Listing states that returns or buyer protections are available.',
      isVerified: false,
      scoreDeduction: 10,
    });
  } else {
    // Unknown / unprovided return policy is not treated as either a positive or negative signal
    unverifiedAspects.push('Return and refund policy availability (marked unknown / not specified)');
  }

  // 5. Description Content Inspection
  if (input.productDescription) {
    const descLower = input.productDescription.toLowerCase();

    // Check for explicit replica / clone terminology
    for (const kw of REPLICA_KEYWORDS) {
      if (descLower.includes(kw)) {
        indicators.push({
          id: `replica-term-${kw}`,
          name: `Explicit Replica / Copy Terminology ("${kw}")`,
          category: 'content',
          severity: 'high',
          scoreImpact: 40,
          isObserved: true,
          description: `The seller's description includes phrase "${kw}". This explicitly signals the item is an imitation or unauthorized reproduction.`,
          remedyOrPrecaution: 'Do not purchase if you require an authentic brand original.',
        });
        break;
      }
    }

    // Check for risky payment pressure
    for (const tactic of HIGH_PRESSURE_TACTICS) {
      if (descLower.includes(tactic)) {
        indicators.push({
          id: `unsafe-payment-tactic`,
          name: `Unprotected Payment Pressure ("${tactic}")`,
          category: 'content',
          severity: 'high',
          scoreImpact: 45,
          isObserved: true,
          description: `Seller requests unprotected payment method ("${tactic}"). Fraudulent listings frequently ask for direct wire, gift cards, or crypto to bypass dispute systems.`,
          remedyOrPrecaution: 'Never pay via direct wire, gift cards, or unprotected peer-to-peer apps.',
        });
        break;
      }
    }
  }

  // 6. Product Identifier (GS1 Modulo-10 Checksum Validation reused from codeAnalyzer)
  if (input.productIdentifier && input.productIdentifier.trim().length > 0) {
    const gs1 = validateGs1BarcodeFormat(input.productIdentifier);

    if (gs1.isStandardLength && gs1.isValidChecksum) {
      positiveSignals.push({
        id: 'valid-identifier-format',
        name: `Valid GS1 Modulo-10 Barcode (${gs1.formatLabel})`,
        description: `Identifier "${gs1.cleaned}" matches ${gs1.formatLabel} specification and passed GS1 Modulo-10 check-digit verification. (Note: physical packaging verification is still required because real barcodes can be copied).`,
        isVerified: true,
        scoreDeduction: 8,
      });

      if (barcodeLookup) {
        if (barcodeLookup.found && barcodeLookup.product) {
          const cmp = compareProductWithBarcodeDb(
            input,
            barcodeLookup.product,
            barcodeLookup.sourceType === 'live_database'
          );
          indicators.push(...cmp.indicators);
          positiveSignals.push(...cmp.positiveSignals);
          unverifiedAspects.push(...cmp.unverifiedAspects);
          evidencePoints += barcodeLookup.sourceType === 'live_database' ? 15 : 5;
        } else if (barcodeLookup.status === 'not_found') {
          unverifiedAspects.push(
            `Barcode ${gs1.cleaned}: Product not found in available databases (${barcodeLookup.queriedDatabases.join(', ') || 'public registries'}). Missing registration is not proof of counterfeiting.`
          );
        } else if (barcodeLookup.status === 'error') {
          unverifiedAspects.push(
            `External barcode database lookup could not be completed (${barcodeLookup.message}). No product details were fabricated.`
          );
        }
      }
    } else if (gs1.isStandardLength && !gs1.isValidChecksum) {
      indicators.push({
        id: 'invalid-gs1-checksum',
        name: `Invalid GS1 Checksum Digit (${gs1.formatLabel})`,
        category: 'technical',
        severity: 'high',
        scoreImpact: 25,
        isObserved: true,
        description: `Barcode "${gs1.cleaned}" has a standard ${gs1.formatLabel} length, but its final check digit fails the GS1 Modulo-10 checksum algorithm. This indicates a typo or fabricated barcode.`,
        remedyOrPrecaution: 'Double-check the printed digits or verify the official GTIN directly with the manufacturer.',
      });
    } else {
      indicators.push({
        id: 'nonstandard-identifier',
        name: 'Non-GS1 / Proprietary Product Identifier',
        category: 'technical',
        severity: 'low',
        scoreImpact: 8,
        isObserved: true,
        description: `Supplied identifier "${input.productIdentifier}" is not a standard 8, 12, 13, or 14-digit GS1 retail barcode (may be an internal SKU or model number).`,
        remedyOrPrecaution: 'Request an official GS1 UPC/EAN or verify the manufacturer model code directly.',
      });
    }
  }

  const coveragePercent = Math.min(Math.round((evidencePoints / maxPossibleEvidence) * 100), 100);

  return {
    indicators,
    positiveSignals,
    evidenceWeight: coveragePercent,
    unverifiedAspects,
  };
}
