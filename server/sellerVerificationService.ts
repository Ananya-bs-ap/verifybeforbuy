/**
 * VerifyBeforeBuy AI — Real Seller Verification Service
 *
 * Retrieves externally verifiable seller/merchant details from public structured metadata
 * (Schema.org Offer.seller, Organization, Store, MerchantReturnPolicy) or official storefront pages
 * via SSRF-hardened fetches, compares them with user-provided seller inputs, and reports
 * mismatches, low ratings, suspicious handles, and unavailable/restricted states transparently.
 *
 * Strictly enforces:
 * - Never fabricates seller details, ratings, account ages, or authorization status
 * - Never confuses product aggregate ratings with seller ratings
 * - Never bypasses marketplace CAPTCHAs, authentication, or anti-bot restrictions
 * - Never classifies a seller as fraudulent solely because information is unavailable
 */

import {
  AuthorizedSellerStatus,
  ProductAnalysisInput,
  ReturnPolicyStatus,
  SellerComparisonSummary,
  SellerRetrievedInfo,
  SellerVerificationResult,
  SellerVerificationStatus,
} from '../src/types/index.ts';
import { validateWebsiteUrl } from '../src/lib/urlValidator.ts';
import { normalizeReturnPolicyStatus } from '../src/lib/productValidator.ts';
import {
  detectMarketplaceFromUrl,
  ExtractedSellerMetadataResult,
  extractSellerMetadataFromHtml,
} from '../src/lib/productMetadataExtractor.ts';
import { getRegistrableDomain } from './domainVerificationService.ts';
import {
  FetchTimeoutError,
  FetchValidationError,
  safeFetchPublicUrl,
  SsrfBlockedError,
} from './ssrfFetch.ts';

const SELLER_CACHE_TTL_MS = 5 * 60 * 1000;

interface CachedSellerFetch {
  fetchedAt: string;
  finalUrl: string;
  extraction: ExtractedSellerMetadataResult;
  expiresAt: number;
}

const sellerFetchCache = new Map<string, CachedSellerFetch>();

export function clearSellerVerificationCache(): void {
  sellerFetchCache.clear();
}

export function getDefaultSellerVerifyTimeoutMs(): number {
  const raw = process.env.SELLER_VERIFY_TIMEOUT_MS;
  if (raw) {
    const parsed = Number(raw);
    if (Number.isFinite(parsed) && parsed >= 1000 && parsed <= 20_000) {
      return Math.round(parsed);
    }
  }
  return 6000;
}

// Verified primary official domains mapped cleanly to brands / first-party merchants
const OFFICIAL_BRAND_DOMAINS: Record<string, string[]> = {
  apple: ['apple.com'],
  sony: ['sony.com'],
  nike: ['nike.com'],
  adidas: ['adidas.com'],
  samsung: ['samsung.com'],
  bose: ['bose.com'],
  dyson: ['dyson.com'],
  dell: ['dell.com'],
  lenovo: ['lenovo.com'],
  hp: ['hp.com'],
  rolex: ['rolex.com'],
  sephora: ['sephora.com'],
  nordstrom: ['nordstrom.com'],
  costco: ['costco.com'],
  target: ['target.com'],
  walmart: ['walmart.com'],
  bestbuy: ['bestbuy.com'],
  'best buy': ['bestbuy.com'],
  amazon: ['amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'amazon.ca', 'amazon.co.jp'],
};

const FIRST_PARTY_RETAILER_DOMAINS: Record<string, string[]> = {
  'amazon.com': ['amazon', 'amazon.com', 'amazon services'],
  'target.com': ['target', 'target corporation'],
  'walmart.com': ['walmart', 'walmart.com'],
  'bestbuy.com': ['best buy', 'bestbuy', 'best buy co.'],
  'apple.com': ['apple', 'apple inc'],
  'sony.com': ['sony', 'sony electronics'],
  'nike.com': ['nike', 'nike.com'],
  'costco.com': ['costco', 'costco wholesale'],
  'nordstrom.com': ['nordstrom'],
  'sephora.com': ['sephora'],
};

const CORPORATE_STOPWORDS = new Set([
  'inc',
  'llc',
  'ltd',
  'corp',
  'corporation',
  'co',
  'company',
  'store',
  'shop',
  'official',
  'direct',
  'online',
  'com',
  'the',
]);

function normalizeSellerText(raw?: string): string {
  if (!raw) return '';
  return raw
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function tokenizeSellerIdentity(raw?: string): string[] {
  return normalizeSellerText(raw)
    .split(' ')
    .filter((tok) => tok.length >= 2 && !CORPORATE_STOPWORDS.has(tok));
}

function detectSuspiciousSellerHandleFlags(handle?: string): string[] {
  if (!handle || !handle.trim()) return [];
  const raw = handle.trim();
  const lower = raw.toLowerCase();
  const flags: string[] = [];

  const genericTokens = ['store123', 'deals-shop', 'deals_king', 'user99', 'discount_outlet', 'outlet-deals', 'cheap-luxury'];
  for (const tok of genericTokens) {
    if (lower.includes(tok)) {
      flags.push(`Generic or disposable seller handle token ("${tok}")`);
      break;
    }
  }

  if (/[_-]\d{3,}$/.test(lower) || /\buser\d+\b/.test(lower)) {
    flags.push(`Auto-generated numeric suffix in seller handle ("${raw}")`);
  }

  if (/seller\s*#?\d+/i.test(lower)) {
    flags.push(`Unbranded numeric seller identifier ("${raw}")`);
  }

  return flags;
}

function evaluateOfficialAuthorization(
  finalUrl: string,
  seller: SellerRetrievedInfo,
  enteredBrand?: string,
  extractedBrand?: string
): { status: AuthorizedSellerStatus; detail: string; isOfficialMerchantPage: boolean } {
  let apex = '';
  try {
    apex = getRegistrableDomain(new URL(finalUrl).hostname);
  } catch {
    return {
      status: 'unavailable',
      detail: 'Could not evaluate merchant domain for authorization.',
      isOfficialMerchantPage: false,
    };
  }

  const normalizedSeller = normalizeSellerText(seller.sellerName);
  const firstPartyAliases = FIRST_PARTY_RETAILER_DOMAINS[apex];

  // Case 1: Known first-party brand/retailer domain AND seller matches first-party operator (not a random 3rd-party)
  if (firstPartyAliases) {
    if (!normalizedSeller || firstPartyAliases.some((alias) => normalizedSeller.includes(normalizeSellerText(alias)))) {
      return {
        status: 'confirmed_official',
        detail: `Confirmed official first-party storefront domain (${apex}).`,
        isOfficialMerchantPage: true,
      };
    }
    return {
      status: 'third_party_unverified',
      detail: `Third-party seller ("${seller.sellerName}") on ${apex}; independent brand authorization could not be verified.`,
      isOfficialMerchantPage: false,
    };
  }

  // Case 2: Product brand matches official brand domain (e.g., Samsung on samsung.com)
  const brandCandidate = normalizeSellerText(extractedBrand || enteredBrand);
  if (brandCandidate) {
    for (const [brandKey, domains] of Object.entries(OFFICIAL_BRAND_DOMAINS)) {
      if (brandCandidate.includes(brandKey) && domains.includes(apex)) {
        if (!normalizedSeller || normalizedSeller.includes(brandKey)) {
          return {
            status: 'confirmed_official',
            detail: `Listing resides directly on verified official ${brandKey.toUpperCase()} domain (${apex}).`,
            isOfficialMerchantPage: true,
          };
        }
      }
    }
  }

  // Case 3: Seller profile URL is explicitly hosted on an official brand domain for that brand
  if (seller.sellerProfileUrl) {
    try {
      const profileApex = getRegistrableDomain(new URL(seller.sellerProfileUrl).hostname);
      if (brandCandidate) {
        for (const [brandKey, domains] of Object.entries(OFFICIAL_BRAND_DOMAINS)) {
          if (brandCandidate.includes(brandKey) && domains.includes(profileApex)) {
            return {
              status: 'confirmed_official',
              detail: `Seller profile links to verified official ${brandKey.toUpperCase()} domain (${profileApex}).`,
              isOfficialMerchantPage: true,
            };
          }
        }
      }
    } catch {
      // Ignore malformed profile URL
    }
  }

  if (seller.sellerName) {
    return {
      status: 'third_party_unverified',
      detail: `External seller ("${seller.sellerName}") on ${apex} has no confirmed official manufacturer authorization record.`,
      isOfficialMerchantPage: false,
    };
  }

  return {
    status: 'unavailable',
    detail: 'Seller identity and official brand authorization status are unavailable.',
    isOfficialMerchantPage: false,
  };
}

function compareSellerDetails(
  userProvided: SellerVerificationResult['userProvided'],
  retrieved: SellerRetrievedInfo,
  baseWarnings: string[]
): SellerComparisonSummary {
  const inconsistencies: string[] = [];
  const warnings = [...baseWarnings];
  const suspiciousHandleFlags = Array.from(
    new Set([
      ...detectSuspiciousSellerHandleFlags(retrieved.sellerName),
      ...detectSuspiciousSellerHandleFlags(userProvided.sellerName),
    ])
  );

  // 1. Seller Name Comparison
  let sellerNameMatch: SellerComparisonSummary['sellerNameMatch'] = 'not_comparable';
  const userClean = normalizeSellerText(userProvided.sellerName);
  const retrievedClean = normalizeSellerText(retrieved.sellerName);

  if (userClean && retrievedClean) {
    const userTokens = tokenizeSellerIdentity(userProvided.sellerName);
    const retrievedTokens = tokenizeSellerIdentity(retrieved.sellerName);
    const overlap = userTokens.some((t) => retrievedTokens.includes(t));
    const substringMatch =
      userClean === retrievedClean ||
      userClean.includes(retrievedClean) ||
      retrievedClean.includes(userClean);

    if (substringMatch || overlap) {
      sellerNameMatch = 'match';
    } else {
      sellerNameMatch = 'mismatch';
      inconsistencies.push(
        `Seller name mismatch: entered "${userProvided.sellerName}" conflicts with externally retrieved seller "${retrieved.sellerName}".`
      );
    }
  }

  // 2. Seller Rating Comparison & Low Rating Warning
  let ratingDiscrepancy: number | undefined;
  if (userProvided.sellerRating !== undefined && retrieved.sellerRating !== undefined) {
    ratingDiscrepancy = Number(Math.abs(userProvided.sellerRating - retrieved.sellerRating).toFixed(2));
    if (ratingDiscrepancy >= 0.8) {
      inconsistencies.push(
        `Seller rating discrepancy: entered ${userProvided.sellerRating}/5 vs. externally retrieved ${retrieved.sellerRating}/5.`
      );
    }
  }

  if (retrieved.sellerRating !== undefined && retrieved.sellerRating < 3.0) {
    warnings.push(
      `Externally retrieved seller rating is low (${retrieved.sellerRating}/5${
        retrieved.sellerRatingCount ? ` across ${retrieved.sellerRatingCount.toLocaleString()} ratings` : ''
      }).`
    );
  }

  // 3. Return Policy Consistency Check
  let returnPolicyMismatch = false;
  if (
    userProvided.returnPolicyStatus === 'available' &&
    retrieved.returnPolicyStatus === 'not_available'
  ) {
    returnPolicyMismatch = true;
    inconsistencies.push(
      'Return policy conflict: externally retrieved merchant metadata indicates no returns/final sale, whereas user input states returns are available.'
    );
  }

  return {
    sellerNameMatch,
    ratingDiscrepancy,
    returnPolicyMismatch,
    suspiciousHandleFlags,
    inconsistencies,
    warnings,
  };
}

export interface SellerVerificationOptions {
  timeoutMs?: number;
  bypassCache?: boolean;
  fetchFn?: (url: string) => Promise<{
    finalUrl: string;
    statusCode: number;
    contentType: string;
    body: string;
  }>;
}

/**
 * Retrieve and verify seller information for a product listing URL and/or manual seller fields.
 * Reuses SSRF protections and gracefully degrades when marketplace pages block access or omit seller metadata.
 */
export async function verifySellerInfo(
  input: Partial<ProductAnalysisInput>,
  options?: SellerVerificationOptions
): Promise<SellerVerificationResult> {
  const checkedAt = new Date().toISOString();
  const returnPolicyStatus: ReturnPolicyStatus = normalizeReturnPolicyStatus(input as ProductAnalysisInput);

  const userProvided: SellerVerificationResult['userProvided'] = {
    sellerName: typeof input.sellerName === 'string' && input.sellerName.trim() ? input.sellerName.trim() : undefined,
    sellerRating:
      typeof input.sellerRating === 'number' && Number.isFinite(input.sellerRating)
        ? input.sellerRating
        : undefined,
    returnPolicyStatus,
    brand: typeof input.brand === 'string' && input.brand.trim() ? input.brand.trim() : undefined,
    sourcePlatform:
      typeof input.sourcePlatform === 'string' && input.sourcePlatform.trim()
        ? input.sourcePlatform.trim()
        : undefined,
  };

  const emptyRetrieved: SellerRetrievedInfo = {
    authorizedSellerStatus: 'unavailable',
    returnPolicyStatus: 'unknown',
    fieldSources: {},
  };

  const rawUrl = typeof input.listingUrl === 'string' ? input.listingUrl.trim() : '';

  // Case A: No listing URL provided — cannot externally verify; keep user inputs unverified without fraud penalty
  if (!rawUrl) {
    const comparison = compareSellerDetails(userProvided, emptyRetrieved, []);
    const status: SellerVerificationStatus =
      comparison.suspiciousHandleFlags.length > 0 ? 'mismatch_or_warning' : 'unverified';

    return {
      status,
      source: 'none',
      message:
        'No listing URL was supplied for external seller verification. Any entered seller details are treated strictly as unverified user inputs.',
      userProvided,
      retrieved: emptyRetrieved,
      comparison,
      checkedAt,
      cached: false,
    };
  }

  const urlCheck = validateWebsiteUrl(rawUrl);
  if (!urlCheck.valid || !urlCheck.normalizedUrl) {
    throw new FetchValidationError(
      urlCheck.error || 'Invalid listing URL. Please enter a valid http:// or https:// web address.'
    );
  }

  const timeoutMs = options?.timeoutMs ?? getDefaultSellerVerifyTimeoutMs();
  const useCache = !options?.bypassCache && !options?.fetchFn;
  const cacheKey = urlCheck.normalizedUrl.toLowerCase();

  let extraction: ExtractedSellerMetadataResult;
  let finalUrl = urlCheck.normalizedUrl;
  let cached = false;

  const cachedEntry = useCache ? sellerFetchCache.get(cacheKey) : undefined;
  if (cachedEntry && cachedEntry.expiresAt > Date.now()) {
    extraction = cachedEntry.extraction;
    finalUrl = cachedEntry.finalUrl;
    cached = true;
  } else {
    try {
      const fetched = options?.fetchFn
        ? await options.fetchFn(urlCheck.normalizedUrl)
        : await safeFetchPublicUrl(urlCheck.normalizedUrl, {
            timeoutMs,
            maxRedirects: 5,
            maxBytes: 2_500_000,
          });

      finalUrl = fetched.finalUrl || urlCheck.normalizedUrl;

      if (
        fetched.contentType &&
        !fetched.contentType.includes('text/html') &&
        !fetched.contentType.includes('application/xhtml+xml') &&
        !fetched.contentType.includes('application/ld+json') &&
        !fetched.contentType.includes('application/json') &&
        !fetched.contentType.includes('text/plain')
      ) {
        const comparison = compareSellerDetails(userProvided, emptyRetrieved, []);
        return {
          status: 'unavailable',
          source: 'none',
          marketplace: detectMarketplaceFromUrl(finalUrl).name,
          statusCode: fetched.statusCode,
          message: `Unsupported response content type (${fetched.contentType}); external seller details unavailable.`,
          userProvided,
          retrieved: emptyRetrieved,
          comparison,
          checkedAt,
          cached: false,
        };
      }

      extraction = extractSellerMetadataFromHtml(
        fetched.body,
        urlCheck.normalizedUrl,
        finalUrl,
        fetched.statusCode
      );

      // If sellerProfileUrl was discovered on a distinct same-origin/public page and registration/rating details are still missing, enrich safely
      if (
        !extraction.accessRestricted &&
        extraction.seller.sellerProfileUrl &&
        extraction.seller.sellerProfileUrl !== finalUrl &&
        (!extraction.seller.businessRegistration ||
          extraction.seller.sellerAccountAgeDays === undefined ||
          extraction.seller.sellerRating === undefined)
      ) {
        try {
          const profileRes = options?.fetchFn
            ? await options.fetchFn(extraction.seller.sellerProfileUrl)
            : await safeFetchPublicUrl(extraction.seller.sellerProfileUrl, {
                timeoutMs: Math.min(timeoutMs, 4000),
                maxRedirects: 3,
                maxBytes: 1_500_000,
              });

          const profileExt = extractSellerMetadataFromHtml(
            profileRes.body,
            extraction.seller.sellerProfileUrl,
            profileRes.finalUrl || extraction.seller.sellerProfileUrl,
            profileRes.statusCode
          );

          if (!profileExt.accessRestricted) {
            if (!extraction.seller.businessRegistration && profileExt.seller.businessRegistration) {
              extraction.seller.businessRegistration = profileExt.seller.businessRegistration;
              extraction.seller.fieldSources.businessRegistration = `Seller profile (${profileExt.seller.fieldSources.businessRegistration || 'JSON-LD'})`;
            }
            if (!extraction.seller.foundingDate && profileExt.seller.foundingDate) {
              extraction.seller.foundingDate = profileExt.seller.foundingDate;
              extraction.seller.sellerAccountAgeDays = profileExt.seller.sellerAccountAgeDays;
              extraction.seller.fieldSources.sellerAccountAge = `Seller profile (${profileExt.seller.fieldSources.sellerAccountAge || 'JSON-LD'})`;
            }
            if (extraction.seller.sellerRating === undefined && profileExt.seller.sellerRating !== undefined) {
              extraction.seller.sellerRating = profileExt.seller.sellerRating;
              extraction.seller.sellerRatingCount = profileExt.seller.sellerRatingCount;
              extraction.seller.fieldSources.sellerRating = `Seller profile (${profileExt.seller.fieldSources.sellerRating || 'JSON-LD'})`;
            }
            if (
              extraction.seller.returnPolicyStatus === 'unknown' &&
              profileExt.seller.returnPolicyStatus !== 'unknown'
            ) {
              extraction.seller.returnPolicyStatus = profileExt.seller.returnPolicyStatus;
              extraction.seller.returnPolicySummary = profileExt.seller.returnPolicySummary;
              extraction.seller.fieldSources.returnPolicyStatus = `Seller profile (${profileExt.seller.fieldSources.returnPolicyStatus || 'JSON-LD'})`;
            }
          }
        } catch {
          // Never fail seller verification if secondary sellerProfileUrl enrichment fails or blocks
        }
      }

      if (useCache) {
        sellerFetchCache.set(cacheKey, {
          fetchedAt: checkedAt,
          finalUrl,
          extraction,
          expiresAt: Date.now() + SELLER_CACHE_TTL_MS,
        });
      }
    } catch (err: any) {
      if (err instanceof SsrfBlockedError) {
        throw err;
      }

      const marketplaceInfo = detectMarketplaceFromUrl(urlCheck.normalizedUrl);
      const isTimeout = err instanceof FetchTimeoutError || err?.name === 'AbortError';
      const comparison = compareSellerDetails(userProvided, emptyRetrieved, []);

      return {
        status: comparison.suspiciousHandleFlags.length > 0 ? 'mismatch_or_warning' : 'unavailable',
        source: 'none',
        marketplace: marketplaceInfo.name,
        requiresAuthorizedApi: marketplaceInfo.typicallyRequiresAuthorizedApi,
        message: isTimeout
          ? `Seller verification request timed out while contacting ${marketplaceInfo.name}. Unavailable seller details are not treated as fraud.`
          : `Could not retrieve external seller information (${err?.message || 'network unavailable'}). Unavailable seller details are not treated as fraud.`,
        userProvided,
        retrieved: emptyRetrieved,
        comparison,
        checkedAt,
        cached: false,
        error: err?.message || 'External seller fetch failed.',
      };
    }
  }

  // Case B: Marketplace / site returned HTTP 401/403/429/503 or CAPTCHA / anti-bot wall
  if (extraction.accessRestricted) {
    const comparison = compareSellerDetails(userProvided, emptyRetrieved, extraction.warnings);
    return {
      status: 'restricted',
      source: 'none',
      marketplace: extraction.marketplace,
      accessRestricted: true,
      requiresAuthorizedApi: extraction.requiresAuthorizedApi,
      statusCode: extraction.statusCode,
      message: `${extraction.blockReason || 'Marketplace access restricted.'}${
        extraction.requiresAuthorizedApi
          ? ` ${extraction.marketplace} restricts unauthenticated requests and requires an authorized marketplace API.`
          : ''
      } Unavailable seller information is not scored as fraud.`,
      userProvided,
      retrieved: emptyRetrieved,
      comparison,
      checkedAt,
      cached,
    };
  }

  // Case C: Evaluate official storefront / authorized seller status and clone seller object cleanly
  const retrieved: SellerRetrievedInfo = {
    ...extraction.seller,
    fieldSources: { ...extraction.seller.fieldSources },
  };

  const authEval = evaluateOfficialAuthorization(
    finalUrl,
    retrieved,
    userProvided.brand,
    extraction.extractedBrand
  );
  retrieved.authorizedSellerStatus = authEval.status;
  retrieved.authorizedSellerDetail = authEval.detail;
  if (authEval.status === 'confirmed_official') {
    retrieved.fieldSources.authorizedSellerStatus = 'Official storefront domain verification';
  }

  const retrievedFieldCount = Object.keys(retrieved.fieldSources).length;
  const comparison = compareSellerDetails(userProvided, retrieved, extraction.warnings);

  const hasNegativeFinding =
    comparison.sellerNameMatch === 'mismatch' ||
    comparison.returnPolicyMismatch ||
    (comparison.ratingDiscrepancy !== undefined && comparison.ratingDiscrepancy >= 0.8) ||
    comparison.suspiciousHandleFlags.length > 0 ||
    (retrieved.sellerRating !== undefined && retrieved.sellerRating < 3.0);

  let status: SellerVerificationStatus;
  let message: string;

  if (hasNegativeFinding) {
    status = 'mismatch_or_warning';
    message = `External seller verification surfaced ${
      comparison.inconsistencies.length > 0 ? 'inconsistencies with entered seller data' : 'seller risk warning(s)'
    }.`;
  } else if (retrievedFieldCount > 0) {
    status = 'verified';
    message = `Retrieved ${retrievedFieldCount} seller metadata attribute${retrievedFieldCount === 1 ? '' : 's'} from ${
      authEval.isOfficialMerchantPage ? `official ${extraction.marketplace} storefront` : extraction.marketplace
    }.`;
  } else {
    status = 'unverified';
    message = `Page was accessible (${extraction.marketplace}), but no public structured seller details were published.${
      extraction.requiresAuthorizedApi
        ? ` ${extraction.marketplace} typically exposes seller metrics only through authorized APIs.`
        : ''
    }`;
  }

  return {
    status,
    source: authEval.isOfficialMerchantPage
      ? 'official_merchant_page'
      : retrievedFieldCount > 0
        ? 'public_metadata'
        : 'none',
    marketplace: extraction.marketplace,
    accessRestricted: false,
    requiresAuthorizedApi: extraction.requiresAuthorizedApi,
    statusCode: extraction.statusCode,
    message,
    userProvided,
    retrieved,
    comparison,
    checkedAt,
    cached,
  };
}
