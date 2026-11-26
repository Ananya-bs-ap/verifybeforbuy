/**
 * VerifyBeforeBuy AI — Real-World Market Price Comparison Service
 *
 * Retrieves comparable reference prices from accessible public structured metadata,
 * official manufacturer/brand storefronts, GS1 barcode merchant offers (UPCitemdb),
 * and optional authorized retailer APIs via SSRF-hardened requests.
 *
 * Enforces strict accuracy & safety guarantees:
 * - Never fabricates prices or invokes Gemini to guess prices
 * - Never bypasses marketplace CAPTCHAs, authentication, or anti-bot restrictions
 * - Matches exact model, variant, storage capacity, quantity/pack, and condition before comparing
 * - Prioritizes Indian market (INR) sources when listing currency is INR
 * - Never compares mismatched currencies without a verified live FX conversion source
 * - Distinguishes official MSRP, current retail, historical price, and user-entered reference
 */

import {
  CurrencyConversionSummary,
  MarketPriceComparisonResult,
  MarketPriceComparisonStatus,
  MarketPriceQuote,
  MarketPriceStats,
  MarketPriceType,
  ProductAnalysisInput,
  ProductCondition,
} from '../src/types/index.ts';
import {
  decodeHtmlEntities,
  detectAccessRestrictionPage,
  detectMarketplaceFromUrl,
} from '../src/lib/productMetadataExtractor.ts';
import { validateGs1BarcodeFormat } from '../src/lib/riskEngine/codeAnalyzer.ts';
import { validateWebsiteUrl } from '../src/lib/urlValidator.ts';
import { areCurrenciesCompatible } from '../src/lib/productValidator.ts';
import { getRegistrableDomain } from './domainVerificationService.ts';
import {
  FetchTimeoutError,
  safeFetchPublicUrl,
  SsrfBlockedError,
} from './ssrfFetch.ts';

const MARKET_PRICE_CACHE_TTL_MS = 5 * 60 * 1000;
const FX_CACHE_TTL_MS = 6 * 60 * 60 * 1000;
const RATE_LIMIT_COOLDOWN_MS = 5 * 60 * 1000;

interface CacheEntry<T> {
  expiresAt: number;
  value: T;
}

const priceComparisonCache = new Map<string, CacheEntry<MarketPriceComparisonResult>>();
const fxRateCache = new Map<string, CacheEntry<{ rates: Record<string, number>; provider: string; retrievedAt: string }>>();
const sourceCooldowns = new Map<string, number>();

export function clearMarketPriceCache(): void {
  priceComparisonCache.clear();
  fxRateCache.clear();
  sourceCooldowns.clear();
}

export function getDefaultMarketPriceTimeoutMs(): number {
  const raw = process.env.MARKET_PRICE_TIMEOUT_MS;
  if (raw) {
    const parsed = Number(raw);
    if (Number.isFinite(parsed) && parsed >= 1000 && parsed <= 20_000) {
      return Math.round(parsed);
    }
  }
  return 6000;
}

export type MarketPriceFetchFn = (
  url: string,
  headers?: Record<string, string>
) => Promise<{
  finalUrl: string;
  statusCode: number;
  contentType: string;
  body: string;
}>;

export interface MarketPriceComparisonOptions {
  timeoutMs?: number;
  bypassCache?: boolean;
  fetchFn?: MarketPriceFetchFn;
  fxFetchFn?: MarketPriceFetchFn;
}

function sanitizeHttpUrl(raw: unknown): string | undefined {
  if (typeof raw !== 'string' || !raw.trim()) return undefined;
  try {
    const parsed = new URL(raw.trim());
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      return parsed.toString();
    }
  } catch {
    return undefined;
  }
  return undefined;
}

function normalizeCurrencyCode(raw: unknown): string | undefined {
  if (typeof raw !== 'string') return undefined;
  const upper = raw.trim().toUpperCase();
  if (/^[A-Z]{3}$/.test(upper)) return upper;
  if (upper === '$' || upper === 'US$') return 'USD';
  if (upper === '₹' || upper === 'RS' || upper === 'RS.' || upper === 'INR') return 'INR';
  if (upper === '€') return 'EUR';
  if (upper === '£') return 'GBP';
  return undefined;
}

function parsePriceNumber(val: unknown): number | undefined {
  if (typeof val === 'number') {
    return Number.isFinite(val) && val > 0 ? Number(val.toFixed(2)) : undefined;
  }
  if (typeof val === 'string') {
    const cleaned = val.replace(/[^0-9.,]/g, '');
    if (!cleaned) return undefined;
    const normalized =
      cleaned.includes(',') && cleaned.includes('.')
        ? cleaned.replace(/,/g, '')
        : cleaned.includes(',') && /,\d{2}$/.test(cleaned)
          ? cleaned.replace(',', '.')
          : cleaned.replace(/,/g, '');
    const num = Number(normalized);
    return Number.isFinite(num) && num > 0 ? Number(num.toFixed(2)) : undefined;
  }
  return undefined;
}

function roundMoney(value: number): number {
  return Number(value.toFixed(2));
}

function medianOf(sortedNumbers: number[]): number {
  const n = sortedNumbers.length;
  if (n === 0) return 0;
  const mid = Math.floor(n / 2);
  if (n % 2 === 1) return roundMoney(sortedNumbers[mid]);
  return roundMoney((sortedNumbers[mid - 1] + sortedNumbers[mid]) / 2);
}

// ============================================================================
// 1. Product Condition, Variant, Model, Capacity, and Quantity Matching
// ============================================================================

export interface ParsedProductSpecs {
  normalizedText: string;
  storageTokens: string[];
  dimensionTokens: string[];
  packCounts: number[];
  unitQuantities: string[];
  modelTierTokens: string[];
  modelCodes: string[];
  generationNumbers: string[];
  meaningfulTokens: string[];
  condition: ProductCondition;
}

const SPEC_STOPWORDS = new Set([
  'the', 'and', 'for', 'with', 'new', 'brand', 'original', 'official', 'authentic',
  'wireless', 'bluetooth', 'edition', 'series', 'version', 'color', 'colour',
  'black', 'white', 'silver', 'gold', 'blue', 'green', 'red', 'gray', 'grey',
  'titanium', 'midnight', 'starlight', 'obsidian', 'headphones', 'smartphone',
  'watch', 'item', 'product', 'sale', 'deal', 'best', 'price',
]);

export function detectConditionFromText(text: string): ProductCondition {
  const lower = (text || '').toLowerCase();
  if (!lower.trim()) return 'unknown';
  if (/\b(refurbished|recertified|renewed|reconditioned|open[\s-]?box|seller refurbished|factory refurbished)\b/.test(lower)) {
    return 'refurbished';
  }
  if (/\b(used|pre[\s-]?owned|second[\s-]?hand|2nd hand|as[\s-]?is)\b/.test(lower)) {
    return 'used';
  }
  if (/\b(clearance|liquidation|closeout|overstock|warehouse deal)\b/.test(lower)) {
    return 'clearance';
  }
  if (/\b(brand new|factory sealed|new in box|nib|bnib|mint sealed)\b/.test(lower)) {
    return 'new';
  }
  return 'unknown';
}

export function mapSchemaCondition(rawCondition: unknown, fallbackText = ''): ProductCondition {
  if (typeof rawCondition === 'string') {
    const lower = rawCondition.toLowerCase();
    if (lower.includes('refurbished') || lower.includes('renewed')) return 'refurbished';
    if (lower.includes('used') || lower.includes('damaged')) return 'used';
    if (lower.includes('new')) return 'new';
  }
  return detectConditionFromText(fallbackText);
}

export function parseProductSpecs(rawText: string): ParsedProductSpecs {
  const text = (rawText || '').trim();
  const lower = text.toLowerCase();
  const normalizedText = lower.replace(/[^a-z0-9.\s-]/g, ' ').replace(/\s+/g, ' ').trim();

  // Storage capacity (32GB, 64GB, 128GB, 256GB, 512GB, 1TB, 2TB, 4TB) — exclude "RAM" suffixes when labeled
  const storageSet = new Set<string>();
  const storageRegex = /\b(32|64|128|256|512)\s*gb\b(?!\s*ram)|\b([1248])\s*tb\b/gi;
  let m: RegExpExecArray | null;
  while ((m = storageRegex.exec(lower)) !== null) {
    storageSet.add((m[1] ? `${m[1]}gb` : `${m[2]}tb`).toLowerCase());
  }

  // Dimensions / watch case / screen size (e.g. 41mm, 45mm, 13-inch, 15.6 inch)
  const dimSet = new Set<string>();
  const dimRegex = /\b(\d{2}(?:\.\d)?)\s*(mm|inch|inches|")\b/gi;
  while ((m = dimRegex.exec(lower)) !== null) {
    const unit = m[2].startsWith('inch') || m[2] === '"' ? 'inch' : 'mm';
    dimSet.add(`${m[1]}${unit}`);
  }

  // Pack / bundle quantity (e.g. "2-pack", "pack of 4", "12 pcs", "3 count")
  const packSet = new Set<number>();
  const packRegex1 = /\b(?:pack|set|box|bundle)\s*of\s*(\d{1,3})\b/gi;
  const packRegex2 = /\b(\d{1,3})\s*-?\s*(?:pack|pcs|pieces|count|ct|units)\b/gi;
  while ((m = packRegex1.exec(lower)) !== null) {
    const qty = Number(m[1]);
    if (Number.isFinite(qty) && qty >= 1) packSet.add(qty);
  }
  while ((m = packRegex2.exec(lower)) !== null) {
    const qty = Number(m[1]);
    if (Number.isFinite(qty) && qty >= 1) packSet.add(qty);
  }

  // Volume / weight (e.g. 100ml, 500g, 1.5l, 12oz)
  const unitSet = new Set<string>();
  const unitRegex = /\b(\d+(?:\.\d+)?)\s*(ml|l|litre|liter|g|kg|oz|lb)\b/gi;
  while ((m = unitRegex.exec(lower)) !== null) {
    let unit = m[2].toLowerCase();
    if (unit === 'litre' || unit === 'liter') unit = 'l';
    unitSet.add(`${m[1]}${unit}`);
  }

  // Model tiers (distinguish Pro vs Pro Max vs Ultra vs Plus vs Mini vs Air vs Lite vs FE vs SE)
  const tierSet = new Set<string>();
  if (/\bpro\s*max\b/.test(lower)) tierSet.add('pro max');
  else if (/\bpro\b/.test(lower)) tierSet.add('pro');
  if (/\bultra\b/.test(lower)) tierSet.add('ultra');
  if (/\bplus\b/.test(lower)) tierSet.add('plus');
  if (/\bmini\b/.test(lower)) tierSet.add('mini');
  if (/\bair\b/.test(lower)) tierSet.add('air');
  if (/\blite\b/.test(lower)) tierSet.add('lite');
  if (/\bfe\b/.test(lower)) tierSet.add('fe');
  if (/\bse\b/.test(lower)) tierSet.add('se');

  // Alphanumeric model codes (e.g. xm4, xm5, wh1000xm5, a2931, m3, s24, 16, etc.)
  const modelCodeSet = new Set<string>();
  const codeRegex = /\b(?:[a-z]{1,6}-?\d{1,5}[a-z0-9-]*|[a-z]*\d+[a-z]+\d*)\b/gi;
  while ((m = codeRegex.exec(lower)) !== null) {
    const clean = m[0].replace(/-/g, '').toLowerCase();
    if (
      !storageSet.has(clean) &&
      !dimSet.has(clean) &&
      !unitSet.has(clean) &&
      !/^\d+(?:gb|tb|mm|ml|kg|oz|lb|g|l|pack|pcs|ct)$/.test(clean)
    ) {
      modelCodeSet.add(clean);
    }
  }

  // Explicit model generation numbers (e.g., "iphone 16" -> "16", "2nd gen" -> "gen2")
  const genSet = new Set<string>();
  const genOrdinal = lower.matchAll(/\b(\d)(?:st|nd|rd|th)\s+gen(?:eration)?\b|\bgen\s*(\d)\b/gi);
  for (const gm of genOrdinal) {
    const num = gm[1] || gm[2];
    if (num) genSet.add(`gen${num}`);
  }
  const phoneOrSeriesNum = lower.matchAll(/\b(?:iphone|ipad|galaxy|pixel|watch|series|hero|rockerz|airdopes)\s+(?:series\s+)?([a-z]?\d{1,3})\b/gi);
  for (const pm of phoneOrSeriesNum) {
    if (pm[1]) genSet.add(pm[1].toLowerCase());
  }

  const meaningfulTokens = normalizedText
    .split(/\s+/)
    .map((t) => t.replace(/[^a-z0-9]/g, ''))
    .filter((t) => t.length >= 2 && !SPEC_STOPWORDS.has(t));

  return {
    normalizedText,
    storageTokens: Array.from(storageSet),
    dimensionTokens: Array.from(dimSet),
    packCounts: Array.from(packSet),
    unitQuantities: Array.from(unitSet),
    modelTierTokens: Array.from(tierSet),
    modelCodes: Array.from(modelCodeSet),
    generationNumbers: Array.from(genSet),
    meaningfulTokens: Array.from(new Set(meaningfulTokens)),
    condition: detectConditionFromText(text),
  };
}

export function evaluateVariantAndConditionMatch(params: {
  targetSpecs: ParsedProductSpecs;
  targetName: string;
  targetBrand?: string;
  targetGtin?: string;
  candidateTitle?: string;
  candidateCondition: ProductCondition;
  candidatePriceType: MarketPriceType;
  candidateGtin?: string;
}): {
  variantMatch: 'exact' | 'compatible' | 'mismatch';
  reason?: string;
} {
  const {
    targetSpecs,
    targetName,
    targetBrand,
    targetGtin,
    candidateTitle,
    candidateCondition,
    candidatePriceType,
    candidateGtin,
  } = params;

  // 1. Strict GTIN comparison if both exist and are valid GS1
  if (targetGtin && candidateGtin) {
    const tClean = targetGtin.replace(/\D/g, '').padStart(14, '0');
    const cClean = candidateGtin.replace(/\D/g, '').padStart(14, '0');
    if (tClean !== cClean) {
      return {
        variantMatch: 'mismatch',
        reason: `GTIN mismatch (listing ${targetGtin} vs reference ${candidateGtin}).`,
      };
    }
  }

  const candidateSpecs = parseProductSpecs(candidateTitle || '');

  // 2. Title relevance overlap check when candidateTitle is present
  if (candidateTitle && candidateTitle.trim()) {
    const targetCoreTokens = new Set([
      ...targetSpecs.meaningfulTokens,
      ...parseProductSpecs(targetBrand || '').meaningfulTokens,
    ]);
    const overlap = candidateSpecs.meaningfulTokens.filter((t) => targetCoreTokens.has(t));
    if (targetCoreTokens.size > 0 && overlap.length === 0) {
      return {
        variantMatch: 'mismatch',
        reason: `Unrelated product title ("${candidateTitle}" does not match "${targetName}").`,
      };
    }
  }

  // 3. Storage capacity check (e.g. 128GB vs 512GB)
  if (targetSpecs.storageTokens.length > 0 && candidateSpecs.storageTokens.length > 0) {
    const storageOverlap = targetSpecs.storageTokens.some((s) => candidateSpecs.storageTokens.includes(s));
    if (!storageOverlap) {
      return {
        variantMatch: 'mismatch',
        reason: `Storage capacity mismatch (${targetSpecs.storageTokens.join('/')} vs ${candidateSpecs.storageTokens.join('/')}).`,
      };
    }
  }

  // 4. Dimension / watch / screen size check (e.g. 41mm vs 45mm)
  if (targetSpecs.dimensionTokens.length > 0 && candidateSpecs.dimensionTokens.length > 0) {
    const dimOverlap = targetSpecs.dimensionTokens.some((d) => candidateSpecs.dimensionTokens.includes(d));
    if (!dimOverlap) {
      return {
        variantMatch: 'mismatch',
        reason: `Size/dimension mismatch (${targetSpecs.dimensionTokens.join('/')} vs ${candidateSpecs.dimensionTokens.join('/')}).`,
      };
    }
  }

  // 5. Pack count / quantity check (e.g. 2-pack vs single)
  const targetPack = targetSpecs.packCounts[0];
  const candPack = candidateSpecs.packCounts[0];
  if (targetPack !== undefined && candPack !== undefined && targetPack !== candPack) {
    return {
      variantMatch: 'mismatch',
      reason: `Quantity/pack mismatch (${targetPack}-pack vs ${candPack}-pack).`,
    };
  }
  if (
    (targetPack !== undefined && targetPack > 1 && candPack === undefined) ||
    (candPack !== undefined && candPack > 1 && targetPack === undefined)
  ) {
    return {
      variantMatch: 'mismatch',
      reason: `Multi-pack vs single-unit mismatch (${targetPack ? `${targetPack}-pack` : 'single'} vs ${candPack ? `${candPack}-pack` : 'single'}).`,
    };
  }

  // 6. Volume / weight check (e.g. 100ml vs 250ml)
  if (targetSpecs.unitQuantities.length > 0 && candidateSpecs.unitQuantities.length > 0) {
    const unitOverlap = targetSpecs.unitQuantities.some((u) => candidateSpecs.unitQuantities.includes(u));
    if (!unitOverlap) {
      return {
        variantMatch: 'mismatch',
        reason: `Unit volume/weight mismatch (${targetSpecs.unitQuantities.join('/')} vs ${candidateSpecs.unitQuantities.join('/')}).`,
      };
    }
  }

  // 7. Model tier check (e.g. "iPhone 16 Pro Max" vs "iPhone 16 Pro" vs "iPhone 16")
  if (candidateTitle && candidateTitle.trim()) {
    const targetTiers = new Set(targetSpecs.modelTierTokens);
    const candTiers = new Set(candidateSpecs.modelTierTokens);
    if (targetTiers.size !== candTiers.size || !Array.from(targetTiers).every((t) => candTiers.has(t))) {
      return {
        variantMatch: 'mismatch',
        reason: `Model variant mismatch (${Array.from(targetTiers).join(' ') || 'standard'} vs ${Array.from(candTiers).join(' ') || 'standard'}).`,
      };
    }

    // Generation number mismatch (e.g. iPhone 15 vs iPhone 16, 1st gen vs 2nd gen)
    if (targetSpecs.generationNumbers.length > 0 && candidateSpecs.generationNumbers.length > 0) {
      const genOverlap = targetSpecs.generationNumbers.some((g) => candidateSpecs.generationNumbers.includes(g));
      if (!genOverlap) {
        return {
          variantMatch: 'mismatch',
          reason: `Model generation mismatch (${targetSpecs.generationNumbers.join('/')} vs ${candidateSpecs.generationNumbers.join('/')}).`,
        };
      }
    }

    // Explicit alphanumeric model codes (e.g. WH1000XM4 vs WH1000XM5)
    if (targetSpecs.modelCodes.length > 0 && candidateSpecs.modelCodes.length > 0) {
      const codeOverlap = targetSpecs.modelCodes.some((c) => candidateSpecs.modelCodes.includes(c));
      if (!codeOverlap) {
        return {
          variantMatch: 'mismatch',
          reason: `Model code mismatch (${targetSpecs.modelCodes.join('/')} vs ${candidateSpecs.modelCodes.join('/')}).`,
        };
      }
    }
  }

  // 8. Condition matching:
  // If listing is new/standard and candidate offer is used or refurbished -> exclude as mismatch
  // so used/refurbished markdowns never corrupt new-product market pricing.
  if (
    (targetSpecs.condition === 'new' || targetSpecs.condition === 'unknown') &&
    (candidateCondition === 'used' || candidateCondition === 'refurbished')
  ) {
    return {
      variantMatch: 'mismatch',
      reason: `Condition mismatch (reference quote is ${candidateCondition}, whereas listing is ${targetSpecs.condition === 'new' ? 'new' : 'not marked refurbished/used'}).`,
    };
  }

  // If listing is refurbished/used/clearance and quote is new MSRP/retail -> compatible reference baseline
  if (
    (targetSpecs.condition === 'refurbished' || targetSpecs.condition === 'used' || targetSpecs.condition === 'clearance') &&
    (candidateCondition === 'new' || candidateCondition === 'unknown')
  ) {
    return {
      variantMatch: 'compatible',
      reason: `Listing is ${targetSpecs.condition}; benchmark shows ${candidatePriceType === 'official_msrp' ? 'new official MSRP' : 'new retail price'} for context.`,
    };
  }

  return {
    variantMatch: 'exact',
    reason: 'Model, capacity, quantity, and condition match.',
  };
}

// ============================================================================
// 2. Live Exchange Rate Conversion (Verified Real API Only — Never Guessed)
// ============================================================================

async function fetchLiveFxRatesForBase(
  baseCurrency: string,
  timeoutMs: number,
  customFxFetchFn?: MarketPriceFetchFn
): Promise<{ rates: Record<string, number>; provider: string; retrievedAt: string } | null> {
  const base = baseCurrency.toUpperCase();
  const useCache = !customFxFetchFn;

  if (useCache) {
    const cached = fxRateCache.get(base);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.value;
    }
  }

  const doFetch = async (url: string) => {
    if (customFxFetchFn) {
      return customFxFetchFn(url, { Accept: 'application/json' });
    }
    return safeFetchPublicUrl(url, {
      timeoutMs: Math.min(timeoutMs, 4500),
      maxRedirects: 3,
      maxBytes: 250_000,
      headers: { Accept: 'application/json' },
    });
  };

  const providers: Array<{ name: string; url: string; parse: (json: any) => Record<string, number> | null }> = [
    {
      name: 'ExchangeRate-API (open.er-api.com)',
      url: `https://open.er-api.com/v6/latest/${encodeURIComponent(base)}`,
      parse: (j) => (j?.result === 'success' && j?.rates && typeof j.rates === 'object' ? j.rates : null),
    },
    {
      name: 'Frankfurter ECB FX API (api.frankfurter.app)',
      url: `https://api.frankfurter.app/latest?from=${encodeURIComponent(base)}`,
      parse: (j) => (j?.rates && typeof j.rates === 'object' ? { ...j.rates, [base]: 1 } : null),
    },
  ];

  for (const prov of providers) {
    try {
      const res = await doFetch(prov.url);
      if (res.statusCode >= 200 && res.statusCode < 300) {
        const parsed = JSON.parse(res.body);
        const rates = prov.parse(parsed);
        if (rates) {
          const entry = {
            rates,
            provider: prov.name,
            retrievedAt: new Date().toISOString(),
          };
          if (useCache) {
            fxRateCache.set(base, {
              expiresAt: Date.now() + FX_CACHE_TTL_MS,
              value: entry,
            });
          }
          return entry;
        }
      }
    } catch {
      // Try next FX provider
    }
  }

  return null;
}

// ============================================================================
// 3. Structured Price Extraction from Accessible Public Pages & Official APIs
// ============================================================================

interface RawCandidateOffer {
  sourceName: string;
  sourceCategory: MarketPriceQuote['sourceCategory'];
  sourceUrl?: string;
  price: number;
  currency: string;
  priceType: MarketPriceType;
  matchedTitle?: string;
  condition: ProductCondition;
  gtin?: string;
  retrievedAt: string;
  fromListingPageSelf?: boolean;
}

function collectProductAndGroupNodes(node: unknown, out: any[]): void {
  if (!node || typeof node !== 'object') return;
  if (Array.isArray(node)) {
    for (const item of node) collectProductAndGroupNodes(item, out);
    return;
  }
  const obj = node as Record<string, any>;
  const rawType = obj['@type'];
  const types = Array.isArray(rawType) ? rawType : [rawType];
  const isProd = types.some((t) => {
    if (typeof t !== 'string') return false;
    const clean = t.replace(/^https?:\/\/schema\.org\//i, '').toLowerCase();
    return clean === 'product' || clean === 'productgroup' || clean === 'individualproduct';
  });
  if (isProd) out.push(obj);
  if (Array.isArray(obj['@graph'])) collectProductAndGroupNodes(obj['@graph'], out);
  if (obj.mainEntity && typeof obj.mainEntity === 'object') collectProductAndGroupNodes(obj.mainEntity, out);
}

function extractGtinFromNode(node: any): string | undefined {
  if (!node || typeof node !== 'object') return undefined;
  for (const field of [node.gtin14, node.gtin13, node.gtin12, node.gtin8, node.gtin, node.upc, node.ean]) {
    if (typeof field === 'string' || typeof field === 'number') {
      const gs1 = validateGs1BarcodeFormat(String(field));
      if (gs1.isStandardLength && gs1.isValidChecksum) return gs1.cleaned;
    }
  }
  return undefined;
}

function inferOfficialDomainBrand(urlStr: string): string | undefined {
  try {
    const apex = getRegistrableDomain(new URL(urlStr).hostname);
    const officialMap: Record<string, string> = {
      'apple.com': 'Apple',
      'bose.com': 'Bose',
      'sony.com': 'Sony',
      'sony.co.in': 'Sony India',
      'samsung.com': 'Samsung',
      'nike.com': 'Nike',
      'adidas.com': 'Adidas',
      'adidas.co.in': 'Adidas India',
      'dell.com': 'Dell',
      'hp.com': 'HP',
      'lenovo.com': 'Lenovo',
      'dyson.com': 'Dyson',
      'dyson.in': 'Dyson India',
      'boat-lifestyle.com': 'boAt Official',
      'gonoise.com': 'Noise Official',
      'croma.com': 'Croma',
      'reliancedigital.in': 'Reliance Digital',
      'target.com': 'Target',
      'bestbuy.com': 'Best Buy',
    };
    return officialMap[apex];
  } catch {
    return undefined;
  }
}

export function extractStructuredPriceOffersFromHtml(params: {
  html: string;
  requestedUrl: string;
  finalUrl: string;
  statusCode: number;
  sourceLabel?: string;
  sourceCategory?: MarketPriceQuote['sourceCategory'];
  isListingUrl?: boolean;
}): {
  restricted: boolean;
  blockReason?: string;
  offers: RawCandidateOffer[];
} {
  const { html, requestedUrl, finalUrl, statusCode, sourceLabel, sourceCategory, isListingUrl } = params;
  const blockReason = detectAccessRestrictionPage(html, statusCode);
  if (blockReason) {
    return { restricted: true, blockReason, offers: [] };
  }

  const nowIso = new Date().toISOString();
  const pageUrl = sanitizeHttpUrl(finalUrl || requestedUrl) || requestedUrl;
  const officialBrandLabel = inferOfficialDomainBrand(pageUrl);
  const marketplaceInfo = detectMarketplaceFromUrl(pageUrl);
  const resolvedCategory: MarketPriceQuote['sourceCategory'] =
    sourceCategory || (officialBrandLabel ? 'official_manufacturer' : 'public_metadata');
  const resolvedSourceBase =
    sourceLabel ||
    (officialBrandLabel
      ? `Official Storefront (${officialBrandLabel})`
      : `Public Listing Metadata (${marketplaceInfo.name})`);

  const offers: RawCandidateOffer[] = [];
  const jsonLdRegex = /<script[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  const nodes: any[] = [];
  let match: RegExpExecArray | null;

  while ((match = jsonLdRegex.exec(html)) !== null) {
    try {
      const parsed = JSON.parse(match[1].trim());
      collectProductAndGroupNodes(parsed, nodes);
    } catch {
      // Ignore malformed JSON-LD blocks cleanly
    }
  }

  const processOfferObject = (
    offer: any,
    prodTitle: string | undefined,
    prodGtin: string | undefined
  ) => {
    if (!offer || typeof offer !== 'object') return;
    const offerUrl = sanitizeHttpUrl(offer.url) || pageUrl;
    const cond = mapSchemaCondition(offer.itemCondition, prodTitle || '');
    const sellerName =
      typeof offer.seller === 'string'
        ? decodeHtmlEntities(offer.seller)
        : typeof offer.seller?.name === 'string'
          ? decodeHtmlEntities(offer.seller.name)
          : undefined;

    // 1. Check explicit PriceSpecification entries (MSRP / ListPrice vs SalePrice)
    if (offer.priceSpecification) {
      const specs = Array.isArray(offer.priceSpecification)
        ? offer.priceSpecification
        : [offer.priceSpecification];
      for (const spec of specs) {
        if (!spec || typeof spec !== 'object') continue;
        const specPrice = parsePriceNumber(spec.price);
        const specCurrency = normalizeCurrencyCode(spec.priceCurrency || offer.priceCurrency);
        const rawSpecType = String(spec.priceType || '').toUpperCase();
        if (specPrice !== undefined && specCurrency) {
          const isMsrp = rawSpecType.includes('MSRP') || rawSpecType.includes('LISTPRICE');
          if (isMsrp) {
            offers.push({
              sourceName: isListingUrl && !officialBrandLabel
                ? `Declared MSRP (${marketplaceInfo.name})`
                : `${resolvedSourceBase} · Official MSRP`,
              sourceCategory: officialBrandLabel ? 'official_manufacturer' : resolvedCategory,
              sourceUrl: offerUrl,
              price: specPrice,
              currency: specCurrency,
              priceType: 'official_msrp',
              matchedTitle: prodTitle,
              condition: cond,
              gtin: prodGtin,
              retrievedAt: nowIso,
              fromListingPageSelf: Boolean(isListingUrl && !officialBrandLabel),
            });
          }
        }
      }
    }

    // 2. Main offer price or AggregateOffer price
    const directPrice = parsePriceNumber(offer.price ?? offer.lowPrice ?? offer.priceSpecification?.price);
    const directCurrency = normalizeCurrencyCode(
      offer.priceCurrency ?? offer.priceSpecification?.priceCurrency
    );
    if (directPrice !== undefined && directCurrency) {
      offers.push({
        sourceName: sellerName && !officialBrandLabel ? `${sellerName} (${marketplaceInfo.name})` : resolvedSourceBase,
        sourceCategory: resolvedCategory,
        sourceUrl: offerUrl,
        price: directPrice,
        currency: directCurrency,
        priceType: 'current_retail',
        matchedTitle: prodTitle,
        condition: cond,
        gtin: prodGtin,
        retrievedAt: nowIso,
        fromListingPageSelf: Boolean(isListingUrl && !officialBrandLabel),
      });
    }
  };

  for (const prod of nodes) {
    const baseTitle = typeof prod.name === 'string' ? decodeHtmlEntities(prod.name) : undefined;
    const baseGtin = extractGtinFromNode(prod);

    // Handle direct offers
    if (prod.offers) {
      const list = Array.isArray(prod.offers) ? prod.offers : [prod.offers];
      for (const o of list) processOfferObject(o, baseTitle, baseGtin);
    }

    // Handle Schema.org ProductGroup.hasVariant[] (e.g., Bose, electronics stores)
    if (Array.isArray(prod.hasVariant)) {
      for (const variant of prod.hasVariant) {
        if (!variant || typeof variant !== 'object') continue;
        const variantParts = [
          typeof variant.name === 'string' ? decodeHtmlEntities(variant.name) : baseTitle,
          typeof variant.color === 'string' ? decodeHtmlEntities(variant.color) : '',
          typeof variant.size === 'string' ? decodeHtmlEntities(variant.size) : '',
        ].filter(Boolean);
        const variantTitle = variantParts.join(' · ') || baseTitle;
        const variantGtin = extractGtinFromNode(variant) || baseGtin;
        if (variant.offers) {
          const vOffers = Array.isArray(variant.offers) ? variant.offers : [variant.offers];
          for (const vo of vOffers) processOfferObject(vo, variantTitle, variantGtin);
        }
      }
    }
  }

  // Fallback to Open Graph tags if JSON-LD had no offers
  if (offers.length === 0) {
    const ogPriceMatch = html.match(/<meta[^>]+(?:property|name)=["'](?:product:price:amount|og:price:amount)["'][^>]+content=["']([^"']+)["']/i)
      || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+(?:property|name)=["'](?:product:price:amount|og:price:amount)["']/i);
    const ogCurrMatch = html.match(/<meta[^>]+(?:property|name)=["'](?:product:price:currency|og:price:currency)["'][^>]+content=["']([^"']+)["']/i)
      || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+(?:property|name)=["'](?:product:price:currency|og:price:currency)["']/i);
    const ogTitleMatch = html.match(/<meta[^>]+property=["']og:title["'][^>]+content=["']([^"']+)["']/i);

    const ogPrice = ogPriceMatch ? parsePriceNumber(ogPriceMatch[1]) : undefined;
    const ogCurr = ogCurrMatch ? normalizeCurrencyCode(ogCurrMatch[1]) : undefined;
    const ogTitle = ogTitleMatch ? decodeHtmlEntities(ogTitleMatch[1]) : undefined;

    if (ogPrice !== undefined && ogCurr) {
      offers.push({
        sourceName: resolvedSourceBase,
        sourceCategory: resolvedCategory,
        sourceUrl: pageUrl,
        price: ogPrice,
        currency: ogCurr,
        priceType: 'current_retail',
        matchedTitle: ogTitle,
        condition: detectConditionFromText(ogTitle || ''),
        retrievedAt: nowIso,
        fromListingPageSelf: Boolean(isListingUrl && !officialBrandLabel),
      });
    }
  }

  return { restricted: false, offers };
}

// Build candidate verified official public endpoints for matching products (NO fabricated prices — always fetched live!)
interface OfficialCandidateEndpoint {
  sourceName: string;
  url: string;
  kind: 'html_jsonld' | 'shopify_suggest';
  currencyHint: string;
}

function buildOfficialBrandCandidates(
  input: ProductAnalysisInput,
  targetCurrency: string
): OfficialCandidateEndpoint[] {
  const combined = `${input.brand || ''} ${input.productName || ''}`.toLowerCase();
  const candidates: OfficialCandidateEndpoint[] = [];

  // Indian Market Priority Endpoints when targetCurrency === 'INR'
  if (targetCurrency === 'INR') {
    if (/\bboat\b/.test(combined) && input.productName) {
      const q = encodeURIComponent(input.productName.slice(0, 60));
      candidates.push({
        sourceName: 'Official Storefront (boAt India)',
        url: `https://www.boat-lifestyle.com/search/suggest.json?q=${q}&resources[type]=product&resources[limit]=4`,
        kind: 'shopify_suggest',
        currencyHint: 'INR',
      });
    }
    if (/\bnoise\b/.test(combined) && input.productName) {
      const q = encodeURIComponent(input.productName.slice(0, 60));
      candidates.push({
        sourceName: 'Official Storefront (Noise India)',
        url: `https://www.gonoise.com/search/suggest.json?q=${q}&resources[type]=product&resources[limit]=4`,
        kind: 'shopify_suggest',
        currencyHint: 'INR',
      });
    }
  }

  // Bose official US structured ProductGroup JSON-LD catalog (publicly accessible)
  if (/\bbose\b/.test(combined)) {
    if (/quietcomfort\s*ultra.*headphone/i.test(combined)) {
      candidates.push({
        sourceName: 'Official Storefront (Bose)',
        url: 'https://www.bose.com/p/headphones/bose-quietcomfort-ultra-headphones/QCUH-HEADPHONEARN.html',
        kind: 'html_jsonld',
        currencyHint: 'USD',
      });
    } else if (/quietcomfort\s*ultra.*earbud/i.test(combined)) {
      candidates.push({
        sourceName: 'Official Storefront (Bose)',
        url: 'https://www.bose.com/p/earbuds/bose-quietcomfort-ultra-earbuds/QCUE-HEADPHONEIN.html',
        kind: 'html_jsonld',
        currencyHint: 'USD',
      });
    }
  }

  return candidates;
}

async function queryShopifyOfficialSuggest(
  endpoint: OfficialCandidateEndpoint,
  timeoutMs: number,
  fetchFn: MarketPriceFetchFn
): Promise<RawCandidateOffer[]> {
  const res = await fetchFn(endpoint.url, { Accept: 'application/json' });
  if (res.statusCode < 200 || res.statusCode >= 300) return [];
  const data = JSON.parse(res.body);
  const products = data?.resources?.results?.products;
  if (!Array.isArray(products)) return [];
  const nowIso = new Date().toISOString();
  const baseOrigin = new URL(endpoint.url).origin;
  const out: RawCandidateOffer[] = [];

  for (const p of products.slice(0, 4)) {
    const price = parsePriceNumber(p.price);
    const compareAt = parsePriceNumber(p.compare_at_price_max || p.compare_at_price);
    const pUrl = p.url ? sanitizeHttpUrl(`${baseOrigin}${p.url}`) : endpoint.url;
    const title = typeof p.title === 'string' ? decodeHtmlEntities(p.title) : undefined;
    if (price !== undefined) {
      out.push({
        sourceName: endpoint.sourceName,
        sourceCategory: 'official_manufacturer',
        sourceUrl: pUrl,
        price,
        currency: endpoint.currencyHint,
        priceType: 'current_retail',
        matchedTitle: title,
        condition: detectConditionFromText(title || ''),
        retrievedAt: nowIso,
      });
    }
    if (compareAt !== undefined && (!price || compareAt > price)) {
      out.push({
        sourceName: `${endpoint.sourceName} · MRP`,
        sourceCategory: 'official_manufacturer',
        sourceUrl: pUrl,
        price: compareAt,
        currency: endpoint.currencyHint,
        priceType: 'official_msrp',
        matchedTitle: title,
        condition: 'new',
        retrievedAt: nowIso,
      });
    }
  }
  return out;
}

async function queryUpcItemDbOffers(
  gtin: string,
  timeoutMs: number,
  customFetchFn?: MarketPriceFetchFn
): Promise<{
  offers: RawCandidateOffer[];
  error?: { source: string; reason: string };
}> {
  const sourceLabel = 'UPCitemdb Merchant Offers';
  const cooldownUntil = sourceCooldowns.get(sourceLabel) || 0;
  if (!customFetchFn && Date.now() < cooldownUntil) {
    return {
      offers: [],
      error: { source: sourceLabel, reason: 'Temporarily skipped during HTTP 429 rate-limit cooldown' },
    };
  }

  const rawKey = (process.env.UPCITEMDB_API_KEY || '').trim();
  const apiKey = rawKey && !rawKey.includes('MY_UPCITEMDB_API_KEY') ? rawKey : '';
  const keyType = (process.env.UPCITEMDB_KEY_TYPE || '').trim() || '3scale';
  const trialEnabled = process.env.UPCITEMDB_TRIAL_ENABLED !== 'false';

  if (!apiKey && !trialEnabled) {
    return { offers: [] };
  }

  const endpoint = apiKey
    ? `https://api.upcitemdb.com/prod/v1/lookup?upc=${encodeURIComponent(gtin)}`
    : `https://api.upcitemdb.com/prod/trial/lookup?upc=${encodeURIComponent(gtin)}`;

  const headers: Record<string, string> = {
    Accept: 'application/json',
    'User-Agent': 'VerifyBeforeBuyAI/1.0',
  };
  if (apiKey) {
    headers['user_key'] = apiKey;
    headers['key_type'] = keyType;
  }

  try {
    const res = customFetchFn
      ? await customFetchFn(endpoint, headers)
      : await safeFetchPublicUrl(endpoint, {
          timeoutMs,
          maxRedirects: 2,
          maxBytes: 1_000_000,
          headers,
        });

    if (res.statusCode === 429) {
      if (!customFetchFn) {
        sourceCooldowns.set(sourceLabel, Date.now() + RATE_LIMIT_COOLDOWN_MS);
      }
      return {
        offers: [],
        error: { source: sourceLabel, reason: 'Rate limit exceeded (HTTP 429)' },
      };
    }

    if (res.statusCode < 200 || res.statusCode >= 300) {
      return {
        offers: [],
        error: { source: sourceLabel, reason: `HTTP ${res.statusCode}` },
      };
    }

    const payload = JSON.parse(res.body);
    const item = Array.isArray(payload?.items) ? payload.items[0] : undefined;
    if (!item) return { offers: [] };

    const itemTitle = typeof item.title === 'string' ? decodeHtmlEntities(item.title) : undefined;
    const itemGtin = validateGs1BarcodeFormat(String(item.upc || item.ean || gtin)).cleaned || gtin;
    const rawOffers = Array.isArray(item.offers) ? item.offers : [];
    const out: RawCandidateOffer[] = [];

    for (const o of rawOffers) {
      if (!o || typeof o !== 'object') continue;
      const price = parsePriceNumber(o.price);
      const currency = normalizeCurrencyCode(o.currency || 'USD') || 'USD';
      if (price === undefined) continue;
      const merchant = typeof o.merchant === 'string' && o.merchant.trim() ? o.merchant.trim() : 'Retailer';
      const link = sanitizeHttpUrl(o.link);
      const titleText = typeof o.title === 'string' && o.title.trim() ? decodeHtmlEntities(o.title) : itemTitle;
      const updatedIso =
        typeof o.updated_t === 'number' && o.updated_t > 0
          ? new Date(o.updated_t * 1000).toISOString()
          : new Date().toISOString();

      out.push({
        sourceName: `${merchant} (via UPCitemdb)`,
        sourceCategory: 'barcode_offers',
        sourceUrl: link,
        price,
        currency,
        priceType: 'current_retail',
        matchedTitle: titleText,
        condition: detectConditionFromText(`${o.condition || ''} ${titleText || ''}`),
        gtin: itemGtin,
        retrievedAt: updatedIso,
      });
    }

    // Include item-level official MSRP / highest recorded price ONLY if explicitly lower/higher is not guessed — UPCitemdb has `lowest_recorded_price` / `highest_recorded_price` as historical bounds
    const histHigh = parsePriceNumber(item.highest_recorded_price);
    if (histHigh !== undefined && out.length === 0) {
      out.push({
        sourceName: 'UPCitemdb Historical Price',
        sourceCategory: 'barcode_offers',
        sourceUrl: `https://www.upcitemdb.com/upc/${encodeURIComponent(itemGtin)}`,
        price: histHigh,
        currency: 'USD',
        priceType: 'historical_price',
        matchedTitle: itemTitle,
        condition: 'unknown',
        gtin: itemGtin,
        retrievedAt: new Date().toISOString(),
      });
    }

    return { offers: out };
  } catch (err: any) {
    if (err instanceof SsrfBlockedError) throw err;
    return {
      offers: [],
      error: {
        source: sourceLabel,
        reason: err instanceof FetchTimeoutError ? 'Request timed out' : err?.message || 'Lookup failed',
      },
    };
  }
}

// Optional Authorized Retailer APIs (ONLY called when optional API key env vars are explicitly configured)
async function queryOptionalAuthorizedRetailerApis(
  input: ProductAnalysisInput,
  targetCurrency: string,
  gtin: string | undefined,
  timeoutMs: number,
  customFetchFn?: MarketPriceFetchFn
): Promise<{
  queried: string[];
  offers: RawCandidateOffer[];
  errors: Array<{ source: string; reason: string }>;
}> {
  const queried: string[] = [];
  const offers: RawCandidateOffer[] = [];
  const errors: Array<{ source: string; reason: string }> = [];

  const doFetch = async (url: string, headers: Record<string, string> = {}) =>
    customFetchFn
      ? customFetchFn(url, headers)
      : safeFetchPublicUrl(url, { timeoutMs, maxRedirects: 2, maxBytes: 1_000_000, headers });

  // 1. Optional Best Buy Products API (USD)
  const bestBuyKey = (process.env.BESTBUY_API_KEY || '').trim();
  if (bestBuyKey && !bestBuyKey.includes('MY_BESTBUY_API_KEY')) {
    queried.push('Best Buy Official API');
    try {
      const query = gtin
        ? `upc=${encodeURIComponent(gtin)}`
        : `search=${encodeURIComponent((input.productName || '').slice(0, 60))}`;
      const url = `https://api.bestbuy.com/v1/products(${query})?apiKey=${encodeURIComponent(bestBuyKey)}&show=sku,upc,name,regularPrice,salePrice,url,condition&pageSize=3&format=json`;
      const res = await doFetch(url, { Accept: 'application/json' });
      if (res.statusCode >= 200 && res.statusCode < 300) {
        const data = JSON.parse(res.body);
        const items = Array.isArray(data?.products) ? data.products : [];
        const nowIso = new Date().toISOString();
        for (const p of items.slice(0, 2)) {
          const pUrl = sanitizeHttpUrl(p.url);
          const cond = detectConditionFromText(`${p.condition || ''} ${p.name || ''}`);
          const reg = parsePriceNumber(p.regularPrice);
          const sale = parsePriceNumber(p.salePrice);
          if (reg !== undefined) {
            offers.push({
              sourceName: 'Best Buy Official API (MSRP/Regular)',
              sourceCategory: 'authorized_retailer_api',
              sourceUrl: pUrl,
              price: reg,
              currency: 'USD',
              priceType: 'official_msrp',
              matchedTitle: p.name,
              condition: cond,
              gtin: typeof p.upc === 'string' ? p.upc : undefined,
              retrievedAt: nowIso,
            });
          }
          if (sale !== undefined && sale !== reg) {
            offers.push({
              sourceName: 'Best Buy Official API (Current Retail)',
              sourceCategory: 'authorized_retailer_api',
              sourceUrl: pUrl,
              price: sale,
              currency: 'USD',
              priceType: 'current_retail',
              matchedTitle: p.name,
              condition: cond,
              gtin: typeof p.upc === 'string' ? p.upc : undefined,
              retrievedAt: nowIso,
            });
          }
        }
      } else {
        errors.push({ source: 'Best Buy Official API', reason: `HTTP ${res.statusCode}` });
      }
    } catch (err: any) {
      errors.push({ source: 'Best Buy Official API', reason: err?.message || 'Request failed' });
    }
  }

  // 2. Optional eBay Browse API (supports EBAY_IN when currency is INR)
  const ebayToken = (process.env.EBAY_OAUTH_TOKEN || '').trim();
  if (ebayToken && !ebayToken.includes('MY_EBAY_OAUTH_TOKEN')) {
    queried.push('eBay Browse API');
    try {
      const marketplaceId = targetCurrency === 'INR' ? 'EBAY_IN' : 'EBAY_US';
      const queryParam = gtin
        ? `gtin=${encodeURIComponent(gtin)}`
        : `q=${encodeURIComponent((input.productName || '').slice(0, 80))}`;
      const url = `https://api.ebay.com/buy/browse/v1/item_summary/search?${queryParam}&limit=5`;
      const res = await doFetch(url, {
        Accept: 'application/json',
        Authorization: `Bearer ${ebayToken}`,
        'X-EBAY-C-MARKETPLACE-ID': marketplaceId,
      });
      if (res.statusCode >= 200 && res.statusCode < 300) {
        const data = JSON.parse(res.body);
        const items = Array.isArray(data?.itemSummaries) ? data.itemSummaries : [];
        const nowIso = new Date().toISOString();
        for (const it of items.slice(0, 4)) {
          const p = parsePriceNumber(it?.price?.value);
          const c = normalizeCurrencyCode(it?.price?.currency);
          if (p !== undefined && c) {
            offers.push({
              sourceName: `eBay Browse API (${it?.seller?.username || 'Merchant'})`,
              sourceCategory: 'authorized_retailer_api',
              sourceUrl: sanitizeHttpUrl(it?.itemWebUrl),
              price: p,
              currency: c,
              priceType: 'current_retail',
              matchedTitle: it?.title,
              condition: detectConditionFromText(`${it?.condition || ''} ${it?.title || ''}`),
              retrievedAt: nowIso,
            });
          }
        }
      } else {
        errors.push({ source: 'eBay Browse API', reason: `HTTP ${res.statusCode}` });
      }
    } catch (err: any) {
      errors.push({ source: 'eBay Browse API', reason: err?.message || 'Request failed' });
    }
  }

  return { queried, offers, errors };
}

// ============================================================================
// 4. Main Market Price Comparison Orchestrator
// ============================================================================

export async function compareMarketPrices(
  input: ProductAnalysisInput,
  options: MarketPriceComparisonOptions = {}
): Promise<MarketPriceComparisonResult> {
  const checkedAt = new Date().toISOString();
  const timeoutMs = options.timeoutMs ?? getDefaultMarketPriceTimeoutMs();
  const targetCurrency = (normalizeCurrencyCode(input.currency) || 'USD').toUpperCase();
  const indianMarketPrioritized = targetCurrency === 'INR';

  const targetSpecs = parseProductSpecs(
    `${input.productName || ''} ${input.productDescription || ''} ${input.sourcePlatform || ''}`
  );
  const inferredCondition = targetSpecs.condition;

  const gs1Check = input.productIdentifier ? validateGs1BarcodeFormat(input.productIdentifier) : null;
  const validGtin =
    gs1Check && gs1Check.isStandardLength && gs1Check.isValidChecksum ? gs1Check.cleaned : undefined;

  const normalizedUrl = (() => {
    if (!input.listingUrl || !input.listingUrl.trim()) return undefined;
    const check = validateWebsiteUrl(input.listingUrl);
    if (!check.valid || !check.normalizedUrl) return undefined;
    return check.normalizedUrl;
  })();

  const useCache = !options.bypassCache && !options.fetchFn && !options.fxFetchFn;
  const cacheKey = JSON.stringify({
    n: (input.productName || '').trim().toLowerCase(),
    b: (input.brand || '').trim().toLowerCase(),
    u: (normalizedUrl || '').toLowerCase(),
    g: validGtin || '',
    c: targetCurrency,
    lp: input.listedPrice ?? null,
    rp: input.referencePrice ?? null,
    rc: input.referenceCurrency || targetCurrency,
  });

  if (useCache) {
    const hit = priceComparisonCache.get(cacheKey);
    if (hit && hit.expiresAt > Date.now()) {
      return { ...hit.value, cached: true };
    }
  }

  const queriedSources: string[] = [];
  const sourceErrors: Array<{ source: string; reason: string }> = [];
  const rawOffers: RawCandidateOffer[] = [];

  const doFetch: MarketPriceFetchFn = options.fetchFn
    ? options.fetchFn
    : async (url, headers) =>
        safeFetchPublicUrl(url, {
          timeoutMs,
          maxRedirects: 5,
          maxBytes: 2_500_000,
          headers,
        });

  // Launch independent external price probes in parallel
  const tasks: Array<Promise<void>> = [];

  // Task A: Listing URL Structured Metadata (respects CAPTCHAs/403 cleanly)
  if (normalizedUrl) {
    const mp = detectMarketplaceFromUrl(normalizedUrl);
    const label = `Listing Metadata (${mp.name})`;
    queriedSources.push(label);
    tasks.push(
      (async () => {
        try {
          const fetched = await doFetch(normalizedUrl);
          const extracted = extractStructuredPriceOffersFromHtml({
            html: fetched.body,
            requestedUrl: normalizedUrl,
            finalUrl: fetched.finalUrl || normalizedUrl,
            statusCode: fetched.statusCode,
            isListingUrl: true,
          });
          if (extracted.restricted) {
            sourceErrors.push({
              source: label,
              reason: extracted.blockReason || 'Access restricted or anti-bot challenge presented.',
            });
          } else {
            // Only keep MSRP / official brand offers / distinct non-self prices from the listing URL
            for (const o of extracted.offers) {
              if (
                o.priceType === 'official_msrp' ||
                o.sourceCategory === 'official_manufacturer' ||
                (input.listedPrice !== undefined && Math.abs(o.price - input.listedPrice) > 0.01)
              ) {
                rawOffers.push(o);
              }
            }
          }
        } catch (err: any) {
          if (err instanceof SsrfBlockedError) throw err;
          sourceErrors.push({
            source: label,
            reason: err instanceof FetchTimeoutError ? 'Request timed out' : err?.message || 'Fetch unavailable',
          });
        }
      })()
    );
  }

  // Task B: Official Manufacturer / Brand Storefront Endpoints (India INR prioritized when targetCurrency === 'INR')
  const officialEndpoints = buildOfficialBrandCandidates(input, targetCurrency);
  for (const ep of officialEndpoints) {
    // Avoid refetching exact same URL as listingUrl
    if (normalizedUrl && normalizedUrl.toLowerCase() === ep.url.toLowerCase()) continue;
    queriedSources.push(ep.sourceName);
    tasks.push(
      (async () => {
        try {
          if (ep.kind === 'shopify_suggest') {
            const shopifyOffers = await queryShopifyOfficialSuggest(ep, timeoutMs, doFetch);
            rawOffers.push(...shopifyOffers);
          } else {
            const res = await doFetch(ep.url);
            const ext = extractStructuredPriceOffersFromHtml({
              html: res.body,
              requestedUrl: ep.url,
              finalUrl: res.finalUrl || ep.url,
              statusCode: res.statusCode,
              sourceLabel: ep.sourceName,
              sourceCategory: 'official_manufacturer',
              isListingUrl: false,
            });
            if (ext.restricted) {
              sourceErrors.push({ source: ep.sourceName, reason: ext.blockReason || 'Restricted' });
            } else {
              rawOffers.push(...ext.offers);
            }
          }
        } catch (err: any) {
          if (err instanceof SsrfBlockedError) throw err;
          sourceErrors.push({
            source: ep.sourceName,
            reason: err instanceof FetchTimeoutError ? 'Request timed out' : err?.message || 'Fetch unavailable',
          });
        }
      })()
    );
  }

  // Task C: GS1 Barcode Merchant Offers (UPCitemdb)
  if (validGtin) {
    queriedSources.push('UPCitemdb Merchant Offers');
    tasks.push(
      (async () => {
        const upcRes = await queryUpcItemDbOffers(validGtin, timeoutMs, options.fetchFn);
        rawOffers.push(...upcRes.offers);
        if (upcRes.error) sourceErrors.push(upcRes.error);
      })()
    );
  }

  // Task D: Optional Authorized Retailer APIs (strictly when env credentials exist)
  tasks.push(
    (async () => {
      const optRes = await queryOptionalAuthorizedRetailerApis(
        input,
        targetCurrency,
        validGtin,
        timeoutMs,
        options.fetchFn
      );
      queriedSources.push(...optRes.queried);
      rawOffers.push(...optRes.offers);
      sourceErrors.push(...optRes.errors);
    })()
  );

  await Promise.all(tasks);

  // Deduplicate identical raw offers (same sourceName + price + currency + priceType + matchedTitle)
  const dedupedRaw: RawCandidateOffer[] = [];
  const seenKeys = new Set<string>();
  for (const r of rawOffers) {
    const key = `${r.sourceName}|${r.currency}|${r.price}|${r.priceType}|${(r.matchedTitle || '').toLowerCase()}`;
    if (!seenKeys.has(key)) {
      seenKeys.add(key);
      dedupedRaw.push(r);
    }
  }

  // Sort native targetCurrency offers (e.g. INR when listing is INR) ahead of foreign offers
  dedupedRaw.sort((a, b) => {
    const aNative = a.currency === targetCurrency ? 0 : 1;
    const bNative = b.currency === targetCurrency ? 0 : 1;
    if (aNative !== bNative) return aNative - bNative;
    const aOfficial = a.priceType === 'official_msrp' ? 0 : 1;
    const bOfficial = b.priceType === 'official_msrp' ? 0 : 1;
    return aOfficial - bOfficial;
  });

  // Resolve currency conversion ONLY via verified live FX APIs when needed
  const foreignCurrencies = Array.from(
    new Set(dedupedRaw.map((o) => o.currency).filter((c) => c !== targetCurrency))
  );

  const fxRatesToTarget: Record<string, { rate: number; provider: string; retrievedAt: string }> = {};
  let fxUnavailableReason: string | undefined;

  for (const fromCurr of foreignCurrencies) {
    const fx = await fetchLiveFxRatesForBase(fromCurr, timeoutMs, options.fxFetchFn);
    const rate = fx?.rates?.[targetCurrency];
    if (fx && typeof rate === 'number' && Number.isFinite(rate) && rate > 0) {
      fxRatesToTarget[fromCurr] = {
        rate,
        provider: fx.provider,
        retrievedAt: fx.retrievedAt,
      };
    } else {
      fxUnavailableReason = `Live FX conversion rate unavailable for ${fromCurr} -> ${targetCurrency}; cross-currency offers were excluded.`;
    }
  }

  const quotes: MarketPriceQuote[] = [];
  const excludedMismatches: MarketPriceQuote[] = [];
  let quoteCounter = 1;

  for (const offer of dedupedRaw) {
    const variantEval = evaluateVariantAndConditionMatch({
      targetSpecs,
      targetName: input.productName || '',
      targetBrand: input.brand,
      targetGtin: validGtin,
      candidateTitle: offer.matchedTitle,
      candidateCondition: offer.condition,
      candidatePriceType: offer.priceType,
      candidateGtin: offer.gtin,
    });

    const needsFx = offer.currency !== targetCurrency;
    const fxInfo = needsFx ? fxRatesToTarget[offer.currency] : undefined;

    if (needsFx && !fxInfo) {
      excludedMismatches.push({
        id: `quote-${quoteCounter++}`,
        sourceName: offer.sourceName,
        sourceCategory: offer.sourceCategory,
        sourceUrl: offer.sourceUrl,
        price: offer.price,
        currency: offer.currency,
        priceType: offer.priceType,
        matchedTitle: offer.matchedTitle,
        condition: offer.condition,
        variantMatch: 'mismatch',
        variantMatchReason: `Currency mismatch (${offer.currency} vs ${targetCurrency}) without verified FX conversion rate.`,
        includedInStats: false,
        retrievedAt: offer.retrievedAt,
      });
      continue;
    }

    const convertedPrice = fxInfo ? roundMoney(offer.price * fxInfo.rate) : undefined;
    const quote: MarketPriceQuote = {
      id: `quote-${quoteCounter++}`,
      sourceName: offer.sourceName,
      sourceCategory: offer.sourceCategory,
      sourceUrl: offer.sourceUrl,
      price: offer.price,
      currency: offer.currency,
      convertedPrice,
      convertedCurrency: fxInfo ? targetCurrency : undefined,
      fxRateUsed: fxInfo ? Number(fxInfo.rate.toFixed(6)) : undefined,
      fxSource: fxInfo?.provider,
      priceType: offer.priceType,
      matchedTitle: offer.matchedTitle,
      condition: offer.condition,
      variantMatch: variantEval.variantMatch,
      variantMatchReason: variantEval.reason,
      includedInStats: variantEval.variantMatch !== 'mismatch',
      retrievedAt: offer.retrievedAt,
    };

    if (variantEval.variantMatch === 'mismatch') {
      excludedMismatches.push(quote);
    } else {
      quotes.push(quote);
    }
  }

  // Always preserve user-entered reference price clearly tagged as 'user_reference'
  let manualReferenceRetained = false;
  const userRefCurr = (normalizeCurrencyCode(input.referenceCurrency) || targetCurrency).toUpperCase();
  if (typeof input.referencePrice === 'number' && Number.isFinite(input.referencePrice) && input.referencePrice > 0) {
    const userCurrCompat = areCurrenciesCompatible(targetCurrency, userRefCurr);
    let userConverted: number | undefined;
    let userFxInfo: { rate: number; provider: string } | undefined;

    if (!userCurrCompat) {
      const fx = await fetchLiveFxRatesForBase(userRefCurr, timeoutMs, options.fxFetchFn);
      const r = fx?.rates?.[targetCurrency];
      if (fx && typeof r === 'number' && Number.isFinite(r) && r > 0) {
        userFxInfo = { rate: r, provider: fx.provider };
        userConverted = roundMoney(input.referencePrice * r);
      } else {
        fxUnavailableReason =
          fxUnavailableReason ||
          `Manual reference currency (${userRefCurr}) differs from listing currency (${targetCurrency}) and live FX conversion was unavailable.`;
      }
    }

    const userQuote: MarketPriceQuote = {
      id: `quote-user-ref`,
      sourceName: 'User-Entered Reference Price',
      sourceCategory: 'user_input',
      price: roundMoney(input.referencePrice),
      currency: userRefCurr,
      convertedPrice: userConverted,
      convertedCurrency: userFxInfo ? targetCurrency : undefined,
      fxRateUsed: userFxInfo ? Number(userFxInfo.rate.toFixed(6)) : undefined,
      fxSource: userFxInfo?.provider,
      priceType: 'user_reference',
      matchedTitle: input.productName,
      condition: inferredCondition,
      variantMatch: userCurrCompat || Boolean(userFxInfo) ? 'exact' : 'mismatch',
      variantMatchReason:
        userCurrCompat || Boolean(userFxInfo)
          ? 'Manually supplied by user for comparison.'
          : `Currency mismatch (${userRefCurr} vs ${targetCurrency}) without verified FX conversion.`,
      includedInStats: false, // Never mix user input into independent external min/max/median!
      retrievedAt: checkedAt,
    };

    if (userCurrCompat || userFxInfo) {
      quotes.push(userQuote);
      manualReferenceRetained = true;
    } else {
      excludedMismatches.push(userQuote);
    }
  }

  // Compute external comparable statistics
  const comparableExternalQuotes = quotes.filter(
    (q) => q.includedInStats && q.priceType !== 'user_reference'
  );
  const comparableValues = comparableExternalQuotes
    .map((q) => q.convertedPrice ?? q.price)
    .sort((a, b) => a - b);

  let stats: MarketPriceStats | undefined;
  const listedPrice =
    typeof input.listedPrice === 'number' && Number.isFinite(input.listedPrice) && input.listedPrice > 0
      ? roundMoney(input.listedPrice)
      : undefined;

  if (comparableValues.length > 0) {
    const minPrice = roundMoney(comparableValues[0]);
    const maxPrice = roundMoney(comparableValues[comparableValues.length - 1]);
    const medianPrice = medianOf(comparableValues);

    // Prefer native-currency official MSRP or external median
    const nativeMsrp = comparableExternalQuotes.find(
      (q) => q.priceType === 'official_msrp' && q.currency === targetCurrency
    );
    const anyMsrp = comparableExternalQuotes.find((q) => q.priceType === 'official_msrp');
    const msrpQuote = nativeMsrp || anyMsrp;
    const msrpVal = msrpQuote ? (msrpQuote.convertedPrice ?? msrpQuote.price) : undefined;

    let selectedReferencePrice = medianPrice;
    let selectedReferenceType: MarketPriceType =
      comparableExternalQuotes.length === 1
        ? comparableExternalQuotes[0].priceType
        : msrpQuote && comparableExternalQuotes.every((q) => q.priceType === 'official_msrp')
          ? 'official_msrp'
          : 'current_retail';
    let selectedReferenceLabel =
      comparableExternalQuotes.length >= 2
        ? `External Market Median (${comparableExternalQuotes.length} matched quotes)`
        : comparableExternalQuotes[0].sourceName;

    // If INR native quotes exist alongside FX-converted foreign quotes, prefer native INR median when >= 1 native quote exists and user prioritized INR
    if (indianMarketPrioritized) {
      const nativeInrVals = comparableExternalQuotes
        .filter((q) => q.currency === 'INR')
        .map((q) => q.price)
        .sort((a, b) => a - b);
      if (nativeInrVals.length > 0 && nativeInrVals.length < comparableExternalQuotes.length) {
        selectedReferencePrice = medianOf(nativeInrVals);
        selectedReferenceLabel = `Indian Market INR Median (${nativeInrVals.length} INR quote${nativeInrVals.length === 1 ? '' : 's'})`;
      }
    }

    const percentageDifference =
      listedPrice !== undefined && selectedReferencePrice > 0
        ? Number((((selectedReferencePrice - listedPrice) / selectedReferencePrice) * 100).toFixed(1))
        : undefined;

    const vsMsrpPercentageDifference =
      listedPrice !== undefined && msrpVal !== undefined && msrpVal > 0
        ? Number((((msrpVal - listedPrice) / msrpVal) * 100).toFixed(1))
        : undefined;

    stats = {
      currency: targetCurrency,
      minPrice,
      maxPrice,
      medianPrice,
      externalQuoteCount: comparableExternalQuotes.length,
      totalComparableCount: comparableExternalQuotes.length + (manualReferenceRetained ? 1 : 0),
      selectedReferencePrice,
      selectedReferenceType,
      selectedReferenceLabel,
      listedPrice,
      percentageDifference,
      vsMsrpPercentageDifference,
    };
  } else if (manualReferenceRetained) {
    const userQuote = quotes.find((q) => q.priceType === 'user_reference')!;
    const userRefVal = userQuote.convertedPrice ?? userQuote.price;
    const percentageDifference =
      listedPrice !== undefined && userRefVal > 0
        ? Number((((userRefVal - listedPrice) / userRefVal) * 100).toFixed(1))
        : undefined;

    stats = {
      currency: targetCurrency,
      externalQuoteCount: 0,
      totalComparableCount: 1,
      selectedReferencePrice: userRefVal,
      selectedReferenceType: 'user_reference',
      selectedReferenceLabel: 'User-Entered Reference Price (External Market Unavailable)',
      listedPrice,
      percentageDifference,
    };
  }

  const usedFxRates: Record<string, number> = {};
  for (const [k, v] of Object.entries(fxRatesToTarget)) {
    usedFxRates[k] = Number(v.rate.toFixed(6));
  }
  const firstFxEntry = Object.values(fxRatesToTarget)[0];

  const currencyConversion: CurrencyConversionSummary | undefined =
    foreignCurrencies.length > 0 || fxUnavailableReason
      ? {
          performed: Object.keys(usedFxRates).length > 0,
          fromCurrencies: foreignCurrencies,
          toCurrency: targetCurrency,
          provider: firstFxEntry?.provider,
          rates: Object.keys(usedFxRates).length > 0 ? usedFxRates : undefined,
          retrievedAt: firstFxEntry?.retrievedAt,
          unavailableReason: fxUnavailableReason,
        }
      : undefined;

  let status: MarketPriceComparisonStatus;
  let message: string;

  if (comparableExternalQuotes.length > 0) {
    status = 'verified_comparison';
    message = `Compared against ${comparableExternalQuotes.length} externally retrieved comparable market quote${
      comparableExternalQuotes.length === 1 ? '' : 's'
    } in ${targetCurrency}${
      excludedMismatches.length > 0
        ? ` (${excludedMismatches.length} mismatched variant/condition/currency offer${excludedMismatches.length === 1 ? '' : 's'} excluded)`
        : ''
    }.`;
  } else if (
    excludedMismatches.some((m) => m.variantMatchReason?.toLowerCase().includes('currency mismatch')) &&
    !manualReferenceRetained
  ) {
    status = 'currency_mismatch';
    message =
      fxUnavailableReason ||
      `External prices were found in foreign currencies, but cannot be compared against ${targetCurrency} without a verified live FX conversion rate.`;
  } else if (manualReferenceRetained) {
    status = 'partial_or_user_reference';
    message = `External market reference prices were unavailable${
      queriedSources.length > 0 ? ` across checked sources (${queriedSources.join(', ')})` : ''
    }. Retained your manually entered reference price for comparison.`;
  } else {
    status = 'unavailable';
    message =
      queriedSources.length > 0
        ? `No accessible external comparable prices could be retrieved from checked sources (${queriedSources.join(', ')}). Enter a manual Typical Market / MSRP Price to compare discounts.`
        : 'No listing URL, verified GS1 barcode, or official catalog match was available to fetch external market prices. Manual reference entry remains available.';
  }

  const result: MarketPriceComparisonResult = {
    status,
    message,
    targetCurrency,
    inferredCondition,
    indianMarketPrioritized,
    quotes,
    excludedMismatches,
    stats,
    currencyConversion,
    queriedSources,
    sourceErrors,
    manualReferenceRetained,
    checkedAt,
    cached: false,
  };

  if (useCache) {
    priceComparisonCache.set(cacheKey, {
      expiresAt: Date.now() + MARKET_PRICE_CACHE_TTL_MS,
      value: result,
    });
  }

  return result;
}
