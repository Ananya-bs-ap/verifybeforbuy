/**
 * Barcode and QR Code Risk Analyzer
 * 
 * Safely decodes and evaluates QR payloads and 1D retail barcodes (UPC-A, EAN-13, ITF, etc.).
 * 
 * Critical rule: Never claim a product is genuine solely because its barcode scans.
 * Counterfeiters routinely duplicate legitimate barcodes on counterfeit packaging.
 */

import { CodeAnalysisInput, RiskIndicator, PositiveSignal, BarcodeLookupResult } from '../../types';
import { analyzeUrlStructure } from './urlAnalyzer';
import { validateWebsiteUrl } from '../urlValidator';

// Clearly labeled synthetic demonstration records for testing
export interface DemoCatalogItem {
  code: string;
  format: string;
  brand: string;
  productName: string;
  category: string;
  suggestedRetailPrice: number;
  officialVerificationUrl?: string;
  isDemoRecord: true;
}

export const SYNTHETIC_DEMO_CATALOG: Record<string, DemoCatalogItem> = {
  // UPC-A 12-digit demo
  '012000000133': {
    code: '012000000133',
    format: 'UPC-A',
    brand: 'PepsiCo',
    productName: 'Pepsi Cola 12 Fl Oz (Demo Specimen)',
    category: 'Beverages',
    suggestedRetailPrice: 1.99,
    isDemoRecord: true,
  },
  // EAN-13 13-digit demo
  '5000112637922': {
    code: '5000112637922',
    format: 'EAN-13',
    brand: 'Coca-Cola European Partners',
    productName: 'Classic Coke 330ml Can (Demo Specimen)',
    category: 'Beverages',
    suggestedRetailPrice: 1.50,
    isDemoRecord: true,
  },
  // Electronics demo barcode
  '190199220019': {
    code: '190199220019',
    format: 'UPC-A',
    brand: 'Apple Inc. (Demo Ref)',
    productName: 'AirPods Pro 2nd Gen Case (Synthetic Demo Test)',
    category: 'Consumer Electronics',
    suggestedRetailPrice: 249.00,
    officialVerificationUrl: 'https://checkcoverage.apple.com',
    isDemoRecord: true,
  },
};

export interface AnalyzedCodeResult {
  indicators: RiskIndicator[];
  positiveSignals: PositiveSignal[];
  evidenceWeight: number;
  unverifiedAspects: string[];
  matchedDemoItem?: DemoCatalogItem;
  detectedFormat: string;
  payloadType: 'url' | 'gtin-barcode' | 'text' | 'wifi' | 'contact' | 'unknown';
  normalizedUrl?: string;
}

export function analyzeCodePayload(
  input: CodeAnalysisInput,
  barcodeLookup?: BarcodeLookupResult
): AnalyzedCodeResult {
  const indicators: RiskIndicator[] = [];
  const positiveSignals: PositiveSignal[] = [];
  const unverifiedAspects: string[] = [
    'Physical package serialization seal (counterfeits frequently print identical legitimate barcodes)',
    'GS1 global registry live ownership validation (requires paid GS1 Data Hub integration)',
    'Supply chain batch custody records',
  ];

  const raw = input.code.trim();
  let detectedFormat = input.format || 'Unknown Code';
  let payloadType: AnalyzedCodeResult['payloadType'] = 'unknown';

  // 1. Check if barcode is numerical GTIN / UPC / EAN
  const numericOnly = raw.replace(/[\s-]/g, '');
  const isAllDigits = /^\d+$/.test(numericOnly);

  if (isAllDigits && (numericOnly.length === 8 || numericOnly.length === 12 || numericOnly.length === 13 || numericOnly.length === 14)) {
    payloadType = 'gtin-barcode';
    if (numericOnly.length === 12) detectedFormat = 'UPC-A (12 digits)';
    else if (numericOnly.length === 13) detectedFormat = 'EAN-13 (13 digits)';
    else if (numericOnly.length === 8) detectedFormat = 'EAN-8 (8 digits)';
    else if (numericOnly.length === 14) detectedFormat = 'ITF-14 (14 digits)';

    // Verify standard GS1 modulo-10 check digit
    const isValidCheckDigit = verifyGs1CheckDigit(numericOnly);
    if (isValidCheckDigit) {
      positiveSignals.push({
        id: 'valid-gs1-checksum',
        name: 'Valid GS1 Modulo-10 Checksum',
        description: `The barcode "${numericOnly}" has a mathematically valid check digit under the international GS1 specification.`,
        isVerified: true,
        scoreDeduction: 12,
      });
    } else {
      indicators.push({
        id: 'invalid-gs1-checksum',
        name: 'Invalid GS1 Checksum Digit',
        category: 'technical',
        severity: 'high',
        scoreImpact: 35,
        isObserved: true,
        description: `The final checksum digit of "${numericOnly}" does not compute correctly under the GS1 standard algorithm. This indicates a typographical error or a fabricated barcode.`,
        remedyOrPrecaution: 'Inspect the printed barcode clearly or enter the numbers manually from packaging.',
      });
    }

    if (barcodeLookup) {
      if (barcodeLookup.found && barcodeLookup.sourceType === 'live_database' && barcodeLookup.product) {
        const db = barcodeLookup.product;
        positiveSignals.push({
          id: 'live-database-match',
          name: `Matched Live Product Database (${db.databaseSource})`,
          description: `Retrieved registered item "${db.productName || 'Unnamed Product'}"${db.brand ? ` (${db.brand})` : ''} from ${db.databaseSource}. Database presence verifies registration metadata only and never proves a physical item is genuine.`,
          isVerified: true,
          scoreDeduction: 10,
        });
        return {
          indicators,
          positiveSignals,
          evidenceWeight: 75,
          unverifiedAspects,
          matchedDemoItem: undefined,
          detectedFormat,
          payloadType,
        };
      }

      if (barcodeLookup.found && barcodeLookup.sourceType === 'synthetic_demo') {
        const matched = SYNTHETIC_DEMO_CATALOG[numericOnly];
        positiveSignals.push({
          id: 'demo-catalog-match',
          name: 'Matched Synthetic Demo Specimen (Not Live Database)',
          description: `Product was not found in live databases; matched local synthetic demo record (${barcodeLookup.product?.brand || matched?.brand || 'Demo'} — ${barcodeLookup.product?.productName || matched?.productName || numericOnly}). Never proves physical authenticity.`,
          isVerified: false,
          scoreDeduction: 8,
        });
        return {
          indicators,
          positiveSignals,
          evidenceWeight: 55,
          unverifiedAspects,
          matchedDemoItem: matched,
          detectedFormat,
          payloadType,
        };
      }

      if (barcodeLookup.status === 'not_found') {
        unverifiedAspects.push(
          `Product not found in available databases (${barcodeLookup.queriedDatabases.join(', ') || 'public registries'}). Unregistered or regional SKUs are not evidence of counterfeiting.`
        );
        return {
          indicators,
          positiveSignals,
          evidenceWeight: 45,
          unverifiedAspects,
          detectedFormat,
          payloadType,
        };
      }

      if (barcodeLookup.status === 'error') {
        unverifiedAspects.push(
          `External barcode database lookup unavailable or timed out (${barcodeLookup.message}). No product details were fabricated.`
        );
        return {
          indicators,
          positiveSignals,
          evidenceWeight: 40,
          unverifiedAspects,
          detectedFormat,
          payloadType,
        };
      }
    }

    // Offline fallback when server lookup was omitted: check local 3-item synthetic demo catalog
    const matched = SYNTHETIC_DEMO_CATALOG[numericOnly];
    if (matched) {
      positiveSignals.push({
        id: 'demo-catalog-match',
        name: 'Matched Demo Database Specimen (Not Proof of Authenticity)',
        description: `Matched local 3-item demo database entry: ${matched.brand} — ${matched.productName}. Demo match only illustrates catalog lookup and never verifies physical authenticity.`,
        isVerified: false,
        scoreDeduction: 10,
      });
      return {
        indicators,
        positiveSignals,
        evidenceWeight: 65,
        unverifiedAspects,
        matchedDemoItem: matched,
        detectedFormat,
        payloadType,
      };
    } else {
      unverifiedAspects.push('External live barcode database lookup did not run in offline mode (local demo database has 3 test items)');
      return {
        indicators,
        positiveSignals,
        evidenceWeight: 45,
        unverifiedAspects,
        detectedFormat,
        payloadType,
      };
    }
  }

  // 2. Check if QR payload is an HTTP or HTTPS URL (also normalize www. QR payloads)
  if (/^https?:\/\//i.test(raw) || /^www\./i.test(raw)) {
    payloadType = 'url';
    detectedFormat = detectedFormat.includes('QR') ? detectedFormat : 'QR Code (Web URL)';

    const urlValidation = validateWebsiteUrl(raw);
    const normalizedUrl = urlValidation.valid && urlValidation.normalizedUrl ? urlValidation.normalizedUrl : undefined;

    // Analyze embedded URL for structural risks (never executes or opens URL)
    const urlAnalysis = analyzeUrlStructure(normalizedUrl || raw);
    indicators.push(...urlAnalysis.indicators);
    positiveSignals.push(...urlAnalysis.positiveSignals);
    unverifiedAspects.push(...urlAnalysis.unverifiedAspects);

    // QR phishing specific warning
    indicators.push({
      id: 'qr-quishing-warning',
      name: 'QR-Mediated Redirect (Quishing Risk)',
      category: 'url',
      severity: 'low',
      scoreImpact: 8,
      isObserved: true,
      description: 'Physical QR codes can be pasted over legitimate packaging or store stickers to redirect shoppers to malicious phishing clones.',
      remedyOrPrecaution: 'Inspect physical packaging to ensure no secondary sticker was placed over the original printed QR code, and review the URL text before visiting.',
    });

    return {
      indicators,
      positiveSignals,
      evidenceWeight: Math.max(urlAnalysis.evidenceWeight, 60),
      unverifiedAspects,
      detectedFormat,
      payloadType,
      normalizedUrl,
    };
  }

  // 3. Fallback non-URL QR or custom text payload (never invoke URL phishing checks)
  const upperRaw = raw.toUpperCase();
  if (upperRaw.startsWith('WIFI:')) {
    payloadType = 'wifi';
    detectedFormat = 'QR Code (Wi-Fi Configuration)';
  } else if (upperRaw.startsWith('BEGIN:VCARD')) {
    payloadType = 'contact';
    detectedFormat = 'QR Code (Contact vCard)';
  } else {
    payloadType = 'text';
    detectedFormat = 'Plain Text / Custom Payload';
  }

  if (raw.length < 3) {
    indicators.push({
      id: 'insufficient-code-length',
      name: 'Unusable Code Payload',
      category: 'technical',
      severity: 'medium',
      scoreImpact: 20,
      isObserved: true,
      description: 'The decoded payload contains fewer than 3 characters, which cannot be matched against any standard retail catalog.',
      remedyOrPrecaution: 'Re-align the camera or manually type the full number under the barcode lines.',
    });
  }

  return {
    indicators,
    positiveSignals,
    evidenceWeight: 30,
    unverifiedAspects,
    detectedFormat,
    payloadType,
  };
}

export interface Gs1ValidationResult {
  cleaned: string;
  isNumeric: boolean;
  isStandardLength: boolean;
  isValidChecksum: boolean;
  formatLabel?: string;
}

/**
 * Validate standard GS1 barcode lengths (8, 12, 13, 14) and Modulo-10 check digit
 */
export function validateGs1BarcodeFormat(rawCode: string): Gs1ValidationResult {
  const cleaned = (rawCode || '').replace(/[\s-]/g, '');
  const isNumeric = /^\d+$/.test(cleaned);
  const isStandardLength =
    isNumeric &&
    (cleaned.length === 8 || cleaned.length === 12 || cleaned.length === 13 || cleaned.length === 14);

  let formatLabel: string | undefined;
  if (isStandardLength) {
    if (cleaned.length === 8) formatLabel = 'EAN-8 (8 digits)';
    else if (cleaned.length === 12) formatLabel = 'UPC-A (12 digits)';
    else if (cleaned.length === 13) formatLabel = 'EAN-13 (13 digits)';
    else if (cleaned.length === 14) formatLabel = 'ITF-14 (14 digits)';
  }

  return {
    cleaned,
    isNumeric,
    isStandardLength,
    isValidChecksum: isStandardLength ? verifyGs1CheckDigit(cleaned) : false,
    formatLabel,
  };
}

/**
 * Standard GS1 Modulo-10 Check Digit calculation
 */
export function verifyGs1CheckDigit(digits: string): boolean {
  if (!/^\d{8}$|^\d{12}$|^\d{13}$|^\d{14}$/.test(digits)) return false;
  const chars = digits.split('').map(Number);
  const checkDigit = chars[chars.length - 1];
  const payload = chars.slice(0, -1);

  // For GTIN, weighting alternates 3 and 1 from right to left
  let sum = 0;
  let multiplier = 3;
  for (let i = payload.length - 1; i >= 0; i--) {
    sum += payload[i] * multiplier;
    multiplier = multiplier === 3 ? 1 : 3;
  }

  const calculated = (10 - (sum % 10)) % 10;
  return calculated === checkDigit;
}
