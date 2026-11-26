/**
 * Server-Side Real-World Barcode Product Lookup Service
 *
 * Queries legitimate public product barcode databases AFTER strict GS1 Modulo-10 validation:
 *   1. Open Food Facts   (food & beverages)
 *   2. Open Beauty Facts (cosmetics, skincare, haircare)
 *   3. Open Products Facts (general consumer & household goods)
 *   4. UPCitemdb         (general consumer catalog; uses env UPCITEMDB_API_KEY when set, or trial tier)
 *
 * Security & Reliability:
 * - Strictly allowlisted fixed HTTPS endpoints (no user-supplied URLs, zero SSRF surface)
 * - GS1 length + Modulo-10 check-digit verification BEFORE any external network request
 * - Per-provider AbortController timeouts, HTTP 429 rate-limit cooldowns, and TTL in-memory cache
 * - Sanitizes returned image/source URLs (http/https only) and never fabricates missing product info
 */

import {
  BarcodeLookupResult,
  BarcodeProductInfo,
  BarcodeProviderError,
} from '../src/types/index.ts';
import {
  SYNTHETIC_DEMO_CATALOG,
  validateGs1BarcodeFormat,
} from '../src/lib/riskEngine/codeAnalyzer.ts';

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface BarcodeLookupOptions {
  timeoutMs?: number;
  bypassCache?: boolean;
  allowDemoFallback?: boolean;
  fetchFn?: FetchLike;
}

interface CacheEntry {
  expiresAt: number;
  result: BarcodeLookupResult;
}

const MAX_CACHE_ENTRIES = 500;
const FOUND_CACHE_TTL_MS = 15 * 60 * 1000; // 15 minutes
const NOT_FOUND_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const RATE_LIMIT_COOLDOWN_MS = 5 * 60 * 1000; // 5 minutes on HTTP 429

const lookupCache = new Map<string, CacheEntry>();
const providerCooldowns = new Map<string, number>();

const OPEN_FACTS_FIELDS =
  'code,product_name,product_name_en,brands,brand_owner,manufacturer,categories,countries,image_front_url,image_url,quantity';

export function clearBarcodeLookupCache(): void {
  lookupCache.clear();
  providerCooldowns.clear();
}

export const DEFAULT_BARCODE_LOOKUP_TIMEOUT_MS = 5000;

export function getDefaultTimeoutMs(): number {
  const envVal = Number(process.env.BARCODE_LOOKUP_TIMEOUT_MS);
  if (Number.isFinite(envVal) && envVal >= 500 && envVal <= 20_000) {
    return envVal;
  }
  return DEFAULT_BARCODE_LOOKUP_TIMEOUT_MS;
}

function sanitizeExternalHttpUrl(rawUrl: unknown): string | undefined {
  if (typeof rawUrl !== 'string') return undefined;
  const trimmed = rawUrl.trim();
  if (!trimmed) return undefined;
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol === 'https:' || parsed.protocol === 'http:') {
      return parsed.toString();
    }
  } catch {
    return undefined;
  }
  return undefined;
}

function cleanText(raw: unknown): string | undefined {
  if (typeof raw !== 'string') return undefined;
  const trimmed = raw.replace(/\s+/g, ' ').trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function formatOpenFactsCategories(raw: unknown): string | undefined {
  const text = cleanText(raw);
  if (!text) return undefined;
  const parts = text
    .split(',')
    .map((p) => p.replace(/^[a-z]{2}:/i, '').trim())
    .filter(Boolean);
  if (parts.length === 0) return undefined;
  return parts.slice(0, 4).join(', ');
}

function setCacheEntry(code: string, result: BarcodeLookupResult, ttlMs: number): void {
  if (lookupCache.size >= MAX_CACHE_ENTRIES) {
    const oldestKey = lookupCache.keys().next().value;
    if (oldestKey !== undefined) {
      lookupCache.delete(oldestKey);
    }
  }
  lookupCache.set(code, {
    expiresAt: Date.now() + ttlMs,
    result,
  });
}

interface ProviderAttemptResult {
  database: string;
  attempted: boolean;
  found: boolean;
  cleanNotFound: boolean;
  product?: BarcodeProductInfo;
  error?: BarcodeProviderError;
}

async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMs: number,
  fetchFn: FetchLike
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetchFn(url, {
      ...init,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
}

async function queryOpenFactsProvider(
  databaseName: 'Open Food Facts' | 'Open Beauty Facts' | 'Open Products Facts',
  apiHost: string,
  code: string,
  formatLabel: string | undefined,
  timeoutMs: number,
  fetchFn: FetchLike
): Promise<ProviderAttemptResult> {
  const cooldownUntil = providerCooldowns.get(databaseName) || 0;
  if (Date.now() < cooldownUntil) {
    return {
      database: databaseName,
      attempted: false,
      found: false,
      cleanNotFound: false,
      error: {
        database: databaseName,
        reason: 'Temporarily skipped during HTTP 429 rate-limit cooldown',
        rateLimited: true,
      },
    };
  }

  const endpoint = `${apiHost}/api/v2/product/${encodeURIComponent(code)}.json?fields=${OPEN_FACTS_FIELDS}`;

  try {
    const response = await fetchWithTimeout(
      endpoint,
      {
        method: 'GET',
        headers: {
          Accept: 'application/json',
          'User-Agent': 'VerifyBeforeBuyAI/1.0 (+https://verifybeforebuy.local)',
        },
      },
      timeoutMs,
      fetchFn
    );

    if (response.status === 429) {
      providerCooldowns.set(databaseName, Date.now() + RATE_LIMIT_COOLDOWN_MS);
      return {
        database: databaseName,
        attempted: true,
        found: false,
        cleanNotFound: false,
        error: {
          database: databaseName,
          reason: 'Rate limit exceeded (HTTP 429)',
          rateLimited: true,
        },
      };
    }

    if (response.status === 404) {
      return {
        database: databaseName,
        attempted: true,
        found: false,
        cleanNotFound: true,
      };
    }

    if (!response.ok) {
      return {
        database: databaseName,
        attempted: true,
        found: false,
        cleanNotFound: false,
        error: {
          database: databaseName,
          reason: `HTTP ${response.status}`,
        },
      };
    }

    const payload: any = await response.json();
    if (!payload || payload.status !== 1 || !payload.product) {
      return {
        database: databaseName,
        attempted: true,
        found: false,
        cleanNotFound: true,
      };
    }

    const p = payload.product;
    const productName = cleanText(p.product_name_en) || cleanText(p.product_name);
    const brand = cleanText(p.brands);
    const manufacturer = cleanText(p.manufacturer) || cleanText(p.brand_owner);

    // Require at least a product name or brand to avoid sparse empty stubs
    if (!productName && !brand) {
      return {
        database: databaseName,
        attempted: true,
        found: false,
        cleanNotFound: true,
      };
    }

    return {
      database: databaseName,
      attempted: true,
      found: true,
      cleanNotFound: false,
      product: {
        code,
        formatLabel,
        productName: productName || brand,
        brand,
        manufacturer,
        category: formatOpenFactsCategories(p.categories),
        imageUrl: sanitizeExternalHttpUrl(p.image_front_url) || sanitizeExternalHttpUrl(p.image_url),
        countries: cleanText(p.countries),
        quantity: cleanText(p.quantity),
        databaseSource: databaseName,
        sourceUrl: sanitizeExternalHttpUrl(`${apiHost}/product/${encodeURIComponent(code)}`),
      },
    };
  } catch (err: any) {
    const timedOut = err?.name === 'AbortError' || /timeout|aborted/i.test(err?.message || '');
    return {
      database: databaseName,
      attempted: true,
      found: false,
      cleanNotFound: false,
      error: {
        database: databaseName,
        reason: timedOut ? `Request timed out after ${timeoutMs}ms` : err?.message || 'Network request failed',
        timedOut,
      },
    };
  }
}

async function queryUpcItemDb(
  code: string,
  formatLabel: string | undefined,
  timeoutMs: number,
  fetchFn: FetchLike
): Promise<ProviderAttemptResult> {
  const databaseName = 'UPCitemdb';
  const rawApiKey = (process.env.UPCITEMDB_API_KEY || '').trim();
  const apiKey = rawApiKey && !rawApiKey.includes('MY_UPCITEMDB_API_KEY') ? rawApiKey : '';
  const keyType = (process.env.UPCITEMDB_KEY_TYPE || '').trim() || '3scale';
  const trialEnabled = process.env.UPCITEMDB_TRIAL_ENABLED !== 'false';

  if (!apiKey && !trialEnabled) {
    return {
      database: databaseName,
      attempted: false,
      found: false,
      cleanNotFound: false,
    };
  }

  const cooldownUntil = providerCooldowns.get(databaseName) || 0;
  if (Date.now() < cooldownUntil) {
    return {
      database: databaseName,
      attempted: false,
      found: false,
      cleanNotFound: false,
      error: {
        database: databaseName,
        reason: 'Rate-limit cooldown active after prior HTTP 429 response',
        rateLimited: true,
      },
    };
  }

  const isPaidKey = Boolean(apiKey);
  const endpoint = isPaidKey
    ? `https://api.upcitemdb.com/prod/v1/lookup?upc=${encodeURIComponent(code)}`
    : `https://api.upcitemdb.com/prod/trial/lookup?upc=${encodeURIComponent(code)}`;

  const headers: Record<string, string> = {
    Accept: 'application/json',
    'User-Agent': 'VerifyBeforeBuyAI/1.0',
  };
  if (isPaidKey) {
    headers['user_key'] = apiKey;
    headers['key_type'] = keyType;
  }

  try {
    const response = await fetchWithTimeout(
      endpoint,
      { method: 'GET', headers },
      timeoutMs,
      fetchFn
    );

    if (response.status === 429) {
      providerCooldowns.set(databaseName, Date.now() + RATE_LIMIT_COOLDOWN_MS);
      return {
        database: databaseName,
        attempted: true,
        found: false,
        cleanNotFound: false,
        error: {
          database: databaseName,
          reason: isPaidKey
            ? 'UPCitemdb API quota exceeded (HTTP 429)'
            : 'UPCitemdb public trial rate limit exceeded (HTTP 429)',
          rateLimited: true,
        },
      };
    }

    if (response.status === 404) {
      return {
        database: databaseName,
        attempted: true,
        found: false,
        cleanNotFound: true,
      };
    }

    const payload: any = await response.json().catch(() => null);
    if (!response.ok) {
      if (payload?.code === 'EXCEED_LIMIT') {
        providerCooldowns.set(databaseName, Date.now() + RATE_LIMIT_COOLDOWN_MS);
      }
      return {
        database: databaseName,
        attempted: true,
        found: false,
        cleanNotFound: false,
        error: {
          database: databaseName,
          reason:
            response.status === 401 || response.status === 403
              ? 'UPCitemdb API credentials rejected or unauthorized'
              : payload?.message || `HTTP ${response.status}`,
          rateLimited: payload?.code === 'EXCEED_LIMIT',
        },
      };
    }

    const item = Array.isArray(payload?.items) ? payload.items[0] : undefined;
    if (!item) {
      return {
        database: databaseName,
        attempted: true,
        found: false,
        cleanNotFound: true,
      };
    }

    const productName = cleanText(item.title);
    const brand = cleanText(item.brand);
    if (!productName && !brand) {
      return {
        database: databaseName,
        attempted: true,
        found: false,
        cleanNotFound: true,
      };
    }

    const firstImg = Array.isArray(item.images)
      ? item.images.map(sanitizeExternalHttpUrl).find(Boolean)
      : undefined;

    return {
      database: databaseName,
      attempted: true,
      found: true,
      cleanNotFound: false,
      product: {
        code,
        formatLabel,
        productName: productName || brand,
        brand,
        manufacturer: cleanText(item.model) ? `${brand || 'Manufacturer'} (Model: ${cleanText(item.model)})` : undefined,
        category: cleanText(item.category),
        imageUrl: firstImg,
        countries: undefined,
        quantity: cleanText(item.size),
        databaseSource: 'UPCitemdb',
      },
    };
  } catch (err: any) {
    const timedOut = err?.name === 'AbortError' || /timeout|aborted/i.test(err?.message || '');
    return {
      database: databaseName,
      attempted: true,
      found: false,
      cleanNotFound: false,
      error: {
        database: databaseName,
        reason: timedOut ? `Request timed out after ${timeoutMs}ms` : err?.message || 'Network request failed',
        timedOut,
      },
    };
  }
}

/**
 * Look up a retail barcode against real external product databases.
 * Enforces GS1 Modulo-10 check-digit verification BEFORE any network request.
 */
export async function lookupBarcodeProduct(
  rawCode: string,
  options: BarcodeLookupOptions = {}
): Promise<BarcodeLookupResult> {
  const gs1 = validateGs1BarcodeFormat(rawCode);
  const timeoutMs = options.timeoutMs ?? getDefaultTimeoutMs();
  const fetchFn: FetchLike = options.fetchFn ?? fetch;

  // 1. Validate GS1 format and Modulo-10 checksum strictly BEFORE external requests
  if (!gs1.isStandardLength || !gs1.isValidChecksum) {
    return {
      code: gs1.cleaned || (rawCode || '').trim(),
      gs1Valid: false,
      formatLabel: gs1.formatLabel,
      status: 'invalid_checksum',
      sourceType: 'none',
      found: false,
      message: !gs1.isStandardLength
        ? 'Barcode must be a valid 8, 12, 13, or 14-digit GS1 GTIN/UPC/EAN before querying external databases.'
        : `Barcode "${gs1.cleaned}" failed GS1 Modulo-10 check-digit validation. External databases were not queried.`,
      queriedDatabases: [],
      cached: false,
      fetchedAt: new Date().toISOString(),
    };
  }

  // 2. Check TTL in-memory cache
  if (!options.bypassCache) {
    const hit = lookupCache.get(gs1.cleaned);
    if (hit && hit.expiresAt > Date.now()) {
      return {
        ...hit.result,
        cached: true,
      };
    }
    if (hit) {
      lookupCache.delete(gs1.cleaned);
    }
  }

  // 3. Query Open Food Facts, Open Beauty Facts, and Open Products Facts in parallel
  const openFactsAttempts = await Promise.all([
    queryOpenFactsProvider('Open Food Facts', 'https://world.openfoodfacts.org', gs1.cleaned, gs1.formatLabel, timeoutMs, fetchFn),
    queryOpenFactsProvider('Open Beauty Facts', 'https://world.openbeautyfacts.org', gs1.cleaned, gs1.formatLabel, timeoutMs, fetchFn),
    queryOpenFactsProvider('Open Products Facts', 'https://world.openproductsfacts.org', gs1.cleaned, gs1.formatLabel, timeoutMs, fetchFn),
  ]);

  const attempts: ProviderAttemptResult[] = [...openFactsAttempts];
  const openFactsMatch = openFactsAttempts.find((a) => a.found && a.product);

  // 4. Fallback to UPCitemdb only when Open Facts family didn't match (preserves UPCitemdb quota)
  let upcItemDbAttempt: ProviderAttemptResult | undefined;
  if (!openFactsMatch) {
    upcItemDbAttempt = await queryUpcItemDb(gs1.cleaned, gs1.formatLabel, timeoutMs, fetchFn);
    if (upcItemDbAttempt.attempted || upcItemDbAttempt.error) {
      attempts.push(upcItemDbAttempt);
    }
  }

  const queriedDatabases = attempts.filter((a) => a.attempted).map((a) => a.database);
  const providerErrors = attempts
    .map((a) => a.error)
    .filter((e): e is BarcodeProviderError => Boolean(e));

  const winningAttempt = openFactsMatch || (upcItemDbAttempt?.found ? upcItemDbAttempt : undefined);

  if (winningAttempt?.product) {
    const result: BarcodeLookupResult = {
      code: gs1.cleaned,
      gs1Valid: true,
      formatLabel: gs1.formatLabel,
      status: 'found',
      sourceType: 'live_database',
      found: true,
      message: `Product record retrieved from ${winningAttempt.database}.`,
      product: winningAttempt.product,
      queriedDatabases,
      providerErrors: providerErrors.length > 0 ? providerErrors : undefined,
      cached: false,
      fetchedAt: new Date().toISOString(),
    };
    if (!options.bypassCache) {
      setCacheEntry(gs1.cleaned, result, FOUND_CACHE_TTL_MS);
    }
    return result;
  }

  // 5. Optional synthetic demo catalog fallback only when live DBs did not have a match
  const demoItem = options.allowDemoFallback !== false ? SYNTHETIC_DEMO_CATALOG[gs1.cleaned] : undefined;
  if (demoItem) {
    return {
      code: gs1.cleaned,
      gs1Valid: true,
      formatLabel: gs1.formatLabel,
      status: 'found',
      sourceType: 'synthetic_demo',
      found: true,
      message: 'Product not found in live databases; matched local synthetic demo catalog specimen.',
      product: {
        code: demoItem.code,
        formatLabel: gs1.formatLabel || demoItem.format,
        productName: demoItem.productName,
        brand: demoItem.brand,
        category: demoItem.category,
        databaseSource: 'Synthetic Demo Catalog',
      },
      queriedDatabases,
      providerErrors: providerErrors.length > 0 ? providerErrors : undefined,
      cached: false,
      fetchedAt: new Date().toISOString(),
    };
  }

  // 6. Distinguish clean "not found" vs total provider error/timeout
  const anyCleanNotFound = attempts.some((a) => a.cleanNotFound);
  if (anyCleanNotFound) {
    const result: BarcodeLookupResult = {
      code: gs1.cleaned,
      gs1Valid: true,
      formatLabel: gs1.formatLabel,
      status: 'not_found',
      sourceType: 'none',
      found: false,
      message: 'Product not found in available databases.',
      queriedDatabases,
      providerErrors: providerErrors.length > 0 ? providerErrors : undefined,
      cached: false,
      fetchedAt: new Date().toISOString(),
    };
    if (!options.bypassCache) {
      setCacheEntry(gs1.cleaned, result, NOT_FOUND_CACHE_TTL_MS);
    }
    return result;
  }

  // Do NOT cache transient errors/timeouts so immediate retry works
  return {
    code: gs1.cleaned,
    gs1Valid: true,
    formatLabel: gs1.formatLabel,
    status: 'error',
    sourceType: 'none',
    found: false,
    message: 'External product databases could not be reached or timed out. No product details were fabricated.',
    queriedDatabases,
    providerErrors,
    cached: false,
    fetchedAt: new Date().toISOString(),
  };
}
