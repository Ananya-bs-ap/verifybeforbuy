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

import { ProductAnalysisInput, RiskIndicator, PositiveSignal } from '../../types';

interface AnalyzedProductResult {
  indicators: RiskIndicator[];
  positiveSignals: PositiveSignal[];
  evidenceWeight: number; // 0 - 100
  unverifiedAspects: string[];
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

export function analyzeProductListing(input: ProductAnalysisInput): AnalyzedProductResult {
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

  // 2. Price Analysis (Strict Anti-Bias Logic)
  if (input.listedPrice !== undefined && input.referencePrice !== undefined && input.referencePrice > 0) {
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
        description: `The item is listed at $${input.listedPrice} vs. typical price of $${input.referencePrice} (${Math.round(discount)}% discount). While clearance or refurbished sales exist, luxury or high-demand electronics at this price point warrant careful verification of seller return guarantees.`,
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
        description: `Listed with a ${Math.round(discount)}% price discount. Legitimate promotions occur regularly; verify seller authenticity credentials.`,
        remedyOrPrecaution: 'Compare with recent sold listings on established marketplaces.',
      });
    } else if (discount <= 25 && discount >= -20) {
      positiveSignals.push({
        id: 'market-aligned-pricing',
        name: 'Market-Consistent Price Range',
        description: 'The listed price is in line with standard retail market expectations.',
        isVerified: true,
        scoreDeduction: 10,
      });
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

  // 4. Return Policy & Buyer Protection
  if (input.hasReturnPolicy === false) {
    indicators.push({
      id: 'no-return-policy',
      name: 'No Stated Return or Refund Guarantee',
      category: 'seller',
      severity: 'medium',
      scoreImpact: 18,
      isObserved: false,
      description: 'The listing does not specify a return or replacement window, transferring all financial risk to the buyer.',
      remedyOrPrecaution: 'Only make purchases where platform buyer protection or standard 14–30 day returns are guaranteed.',
    });
  } else if (input.hasReturnPolicy === true) {
    positiveSignals.push({
      id: 'returns-accepted',
      name: 'Return / Refund Guarantee Stated',
      description: 'Listing indicates returns or buyer protections are available.',
      isVerified: false,
      scoreDeduction: 10,
    });
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

  // 6. Product Identifier (UPC / GTIN / EAN)
  if (input.productIdentifier) {
    const cleaned = input.productIdentifier.replace(/[\s-]/g, '');
    const isStandardBarcode = /^\d{8}$|^\d{12}$|^\d{13}$|^\d{14}$/.test(cleaned);

    if (isStandardBarcode) {
      positiveSignals.push({
        id: 'valid-identifier-format',
        name: 'Standard GS1 Barcode Identifier Provided',
        description: `Identifier "${cleaned}" follows standard GTIN/UPC barcode specification. (Note: physical verification still required).`,
        isVerified: true,
        scoreDeduction: 8,
      });
    } else {
      indicators.push({
        id: 'nonstandard-identifier',
        name: 'Irregular Product Identifier Format',
        category: 'technical',
        severity: 'low',
        scoreImpact: 10,
        isObserved: true,
        description: `Supplied identifier "${input.productIdentifier}" does not match standard GTIN/UPC/EAN numeral lengths (8, 12, 13, or 14 digits).`,
        remedyOrPrecaution: 'Request the manufacturer SKU or official UPC from the seller.',
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
