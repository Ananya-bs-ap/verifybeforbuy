/**
 * Shared Product Listing Input Validation & Normalization Helper
 * Validates prices, seller rating, listing URL, product identifier, and 3-state return policy
 * identically on both frontend and backend before risk scoring or ML inference.
 */

import { ProductAnalysisInput, ReturnPolicyStatus } from '../types/index.ts';
import { validateWebsiteUrl } from './urlValidator.ts';

export interface ProductValidationResult {
  valid: boolean;
  normalizedInput?: ProductAnalysisInput;
  listingUrlHostname?: string;
  error?: string;
}

export function normalizeReturnPolicyStatus(
  input: Pick<ProductAnalysisInput, 'returnPolicyStatus' | 'hasReturnPolicy'>
): ReturnPolicyStatus {
  if (
    input.returnPolicyStatus === 'available' ||
    input.returnPolicyStatus === 'not_available' ||
    input.returnPolicyStatus === 'unknown'
  ) {
    return input.returnPolicyStatus;
  }
  if (input.hasReturnPolicy === true) return 'available';
  if (input.hasReturnPolicy === false) return 'not_available';
  return 'unknown';
}

export function validateProductInput(rawInput: ProductAnalysisInput): ProductValidationResult {
  if (!rawInput || typeof rawInput !== 'object') {
    return { valid: false, error: 'Product analysis payload is required.' };
  }

  const productName = typeof rawInput.productName === 'string' ? rawInput.productName.trim() : '';
  if (!productName) {
    return { valid: false, error: 'Product name is required.' };
  }
  if (productName.length > 300) {
    return { valid: false, error: 'Product name must be 300 characters or fewer.' };
  }

  // Validate Listed Price (optional, but if supplied must be a positive finite number)
  let listedPrice = rawInput.listedPrice;
  if (listedPrice !== undefined && listedPrice !== null && (listedPrice as any) !== '') {
    const parsedPrice = typeof listedPrice === 'number' ? listedPrice : Number(listedPrice);
    if (!Number.isFinite(parsedPrice) || parsedPrice <= 0) {
      return {
        valid: false,
        error: 'Invalid listed price. Enter a positive amount greater than 0.',
      };
    }
    if (parsedPrice > 10_000_000) {
      return {
        valid: false,
        error: 'Invalid listed price. Amount exceeds supported maximum ($10,000,000).',
      };
    }
    listedPrice = parsedPrice;
  } else {
    listedPrice = undefined;
  }

  // Validate Reference / MSRP Price (optional, but if supplied must be a positive finite number)
  let referencePrice = rawInput.referencePrice;
  if (referencePrice !== undefined && referencePrice !== null && (referencePrice as any) !== '') {
    const parsedRef = typeof referencePrice === 'number' ? referencePrice : Number(referencePrice);
    if (!Number.isFinite(parsedRef) || parsedRef <= 0) {
      return {
        valid: false,
        error: 'Invalid market / MSRP price. Enter a positive amount greater than 0.',
      };
    }
    if (parsedRef > 10_000_000) {
      return {
        valid: false,
        error: 'Invalid market / MSRP price. Amount exceeds supported maximum ($10,000,000).',
      };
    }
    referencePrice = parsedRef;
  } else {
    referencePrice = undefined;
  }

  // Validate Seller Rating (optional, 0.0 to 5.0 inclusive)
  let sellerRating = rawInput.sellerRating;
  if (sellerRating !== undefined && sellerRating !== null && (sellerRating as any) !== '') {
    const parsedRating = typeof sellerRating === 'number' ? sellerRating : Number(sellerRating);
    if (!Number.isFinite(parsedRating) || parsedRating < 0 || parsedRating > 5) {
      return {
        valid: false,
        error: 'Invalid seller rating. Rating must be between 0.0 and 5.0.',
      };
    }
    sellerRating = parsedRating;
  } else {
    sellerRating = undefined;
  }

  // Validate Listing URL (optional, but if provided must be a valid HTTP/HTTPS website URL)
  let normalizedListingUrl: string | undefined = undefined;
  let listingUrlHostname: string | undefined = undefined;
  const rawListingUrl = typeof rawInput.listingUrl === 'string' ? rawInput.listingUrl.trim() : '';
  if (rawListingUrl.length > 0) {
    const urlCheck = validateWebsiteUrl(rawListingUrl);
    if (!urlCheck.valid || !urlCheck.normalizedUrl) {
      return {
        valid: false,
        error: `Invalid listing URL. ${urlCheck.error || 'Please enter a valid http:// or https:// website address.'}`,
      };
    }
    normalizedListingUrl = urlCheck.normalizedUrl;
    listingUrlHostname = urlCheck.hostname;
  }

  // Validate Product Identifier / UPC / GTIN / SKU (optional)
  let normalizedIdentifier: string | undefined = undefined;
  const rawIdentifier =
    typeof rawInput.productIdentifier === 'string' ? rawInput.productIdentifier.trim() : '';
  if (rawIdentifier.length > 0) {
    const stripped = rawIdentifier.replace(/[\s-]/g, '');
    if (stripped.length < 3 || stripped.length > 64) {
      return {
        valid: false,
        error: 'Invalid product identifier. Enter at least 3 characters (e.g., a 12-digit UPC, 13-digit EAN, or model SKU).',
      };
    }
    if (!/^[A-Za-z0-9][A-Za-z0-9\s\-_./]*[A-Za-z0-9]$/.test(rawIdentifier)) {
      return {
        valid: false,
        error: 'Invalid product identifier characters. Only letters, numbers, hyphens, dots, and slashes are allowed.',
      };
    }
    // If strictly numeric (barcode), enforce standard GS1 lengths (8, 12, 13, 14)
    // Note: 8/12/13/14-digit codes with bad check digits proceed to analysis so GS1 Modulo-10 flags them explicitly.
    if (/^\d+$/.test(stripped) && ![8, 12, 13, 14].includes(stripped.length)) {
      return {
        valid: false,
        error:
          'Invalid numeric barcode length. Standard GS1 barcodes must be 8 (EAN-8), 12 (UPC-A), 13 (EAN-13), or 14 (ITF-14) digits.',
      };
    }
    normalizedIdentifier = rawIdentifier;
  }

  const returnPolicyStatus = normalizeReturnPolicyStatus(rawInput);

  const normalizeCurr = (c?: string) => {
    if (typeof c !== 'string') return undefined;
    const upper = c.trim().toUpperCase();
    return /^[A-Z]{3}$/.test(upper) ? upper : undefined;
  };
  const currency = normalizeCurr(rawInput.currency);
  const referenceCurrency = normalizeCurr(rawInput.referenceCurrency) || currency;

  const normalizedInput: ProductAnalysisInput = {
    ...rawInput,
    productName,
    brand: typeof rawInput.brand === 'string' ? rawInput.brand.trim() : undefined,
    listingUrl: normalizedListingUrl,
    listedPrice,
    referencePrice,
    currency,
    referenceCurrency,
    sellerName: typeof rawInput.sellerName === 'string' ? rawInput.sellerName.trim() : undefined,
    sellerRating,
    returnPolicyStatus,
    hasReturnPolicy:
      returnPolicyStatus === 'available'
        ? true
        : returnPolicyStatus === 'not_available'
          ? false
          : undefined,
    productDescription:
      typeof rawInput.productDescription === 'string' ? rawInput.productDescription.trim() : undefined,
    productIdentifier: normalizedIdentifier,
    sourcePlatform:
      typeof rawInput.sourcePlatform === 'string' ? rawInput.sourcePlatform.trim() : rawInput.sourcePlatform,
  };

  return {
    valid: true,
    normalizedInput,
    listingUrlHostname,
  };
}

export function areCurrenciesCompatible(currencyA?: string, currencyB?: string): boolean {
  const a = (currencyA || '').trim().toUpperCase();
  const b = (currencyB || '').trim().toUpperCase();
  if (!a || !b) return true;
  return a === b;
}
