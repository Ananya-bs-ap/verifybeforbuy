/**
 * Structured Public Product Metadata Extractor
 *
 * Extracts Schema.org JSON-LD (Product, Offer, AggregateOffer, MerchantReturnPolicy),
 * Open Graph tags, and standard HTML meta tags without fabricating data or guessing
 * unverified MSRP, product-vs-seller ratings, or SKU-vs-GTIN identifiers.
 */

import {
  ExtractedProductDetails,
  ProductFetchDetailsResponse,
  ReturnPolicyStatus,
  SellerRetrievedInfo,
} from '../types/index.ts';
import { validateGs1BarcodeFormat } from './riskEngine/codeAnalyzer.ts';
import { validateWebsiteUrl } from './urlValidator.ts';

export function detectMarketplaceFromUrl(urlStr: string): {
  name: string;
  typicallyRequiresAuthorizedApi: boolean;
} {
  try {
    const host = new URL(urlStr).hostname.toLowerCase();
    if (host === 'amazon.com' || host.endsWith('.amazon.com') || /\bamazon\./.test(host) || host === 'a.co' || host === 'amzn.to') {
      return { name: 'Amazon', typicallyRequiresAuthorizedApi: true };
    }
    if (host === 'flipkart.com' || host.endsWith('.flipkart.com') || host === 'fkrt.it') {
      return { name: 'Flipkart', typicallyRequiresAuthorizedApi: true };
    }
    if (host === 'myntra.com' || host.endsWith('.myntra.com')) {
      return { name: 'Myntra', typicallyRequiresAuthorizedApi: true };
    }
    if (host === 'ebay.com' || host.endsWith('.ebay.com') || /\bebay\./.test(host)) {
      return { name: 'eBay', typicallyRequiresAuthorizedApi: true };
    }
    if (host === 'walmart.com' || host.endsWith('.walmart.com')) {
      return { name: 'Walmart', typicallyRequiresAuthorizedApi: true };
    }
    if (host === 'target.com' || host.endsWith('.target.com')) {
      return { name: 'Target', typicallyRequiresAuthorizedApi: false };
    }
    if (host === 'bestbuy.com' || host.endsWith('.bestbuy.com')) {
      return { name: 'Best Buy', typicallyRequiresAuthorizedApi: true };
    }
    return { name: host.replace(/^www\./, ''), typicallyRequiresAuthorizedApi: false };
  } catch {
    return { name: 'External Website', typicallyRequiresAuthorizedApi: false };
  }
}

function decodeEntitiesOnce(text: string): string {
  return text
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&nbsp;/gi, ' ')
    .replace(/&#(\d+);/g, (_m, dec) => {
      const code = Number(dec);
      return Number.isFinite(code) && code > 0 && code < 0x10ffff ? String.fromCodePoint(code) : '';
    })
    .replace(/&#x([0-9a-f]+);/gi, (_m, hex) => {
      const code = parseInt(hex, 16);
      return Number.isFinite(code) && code > 0 && code < 0x10ffff ? String.fromCodePoint(code) : '';
    });
}

export function decodeHtmlEntities(text: string): string {
  if (!text) return '';
  return decodeEntitiesOnce(decodeEntitiesOnce(text)).replace(/\s+/g, ' ').trim();
}

export function detectAccessRestrictionPage(html: string, statusCode: number): string | null {
  if (statusCode === 401 || statusCode === 403) {
    return `Website returned HTTP ${statusCode} (access denied or automated requests restricted).`;
  }
  if (statusCode === 429) {
    return 'Website returned HTTP 429 (rate limit exceeded).';
  }
  if (statusCode === 503) {
    return 'Website returned HTTP 503 (service unavailable or anti-bot challenge).';
  }

  const lower = html.toLowerCase();
  const titleMatch = lower.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const titleText = titleMatch ? titleMatch[1] : '';

  const blockPatterns = [
    'sorry! we just need to make sure you\'re not a robot',
    'enter the characters you see below',
    'type the characters you see in this image',
    'automated access to amazon data',
    'attention required! | cloudflare',
    'just a moment...',
    'checking your browser before accessing',
    'enable javascript and cookies to continue',
    'pardon our interruption',
    'verify you are human',
    'recaptcha/api.js',
    'px-captcha',
    'perimeterx',
    'access to this page has been denied',
    'site maintenance',
  ];

  const cleanTitle = titleText.trim();
  const isGenericSiteStub =
    (cleanTitle === 'amazon' || cleanTitle === 'amazon.com' || cleanTitle === 'site maintenance') &&
    !lower.includes('application/ld+json');

  if (
    isGenericSiteStub ||
    (blockPatterns.some((pat) => lower.includes(pat) || titleText.includes(pat)) &&
      !lower.includes('application/ld+json'))
  ) {
    return 'Website returned a CAPTCHA, maintenance placeholder, or anti-bot restriction page instead of product details.';
  }

  return null;
}

function parseAttributes(tag: string): Record<string, string> {
  const attrs: Record<string, string> = {};
  const attrRegex = /([a-zA-Z0-9:_-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/g;
  let match: RegExpExecArray | null;
  while ((match = attrRegex.exec(tag)) !== null) {
    const key = match[1].toLowerCase();
    const val = match[2] ?? match[3] ?? match[4] ?? '';
    attrs[key] = decodeHtmlEntities(val);
  }
  return attrs;
}

function extractMetaTags(html: string): Map<string, string> {
  const map = new Map<string, string>();
  const metaRegex = /<meta\b[^>]*>/gi;
  let match: RegExpExecArray | null;
  while ((match = metaRegex.exec(html)) !== null) {
    const attrs = parseAttributes(match[0]);
    const key = (attrs.property || attrs.name || attrs.itemprop || '').toLowerCase().trim();
    const content = (attrs.content || '').trim();
    if (key && content && !map.has(key)) {
      map.set(key, content);
    }
  }
  return map;
}

function parseNumericPrice(val: unknown): number | undefined {
  if (typeof val === 'number') {
    return Number.isFinite(val) && val > 0 ? val : undefined;
  }
  if (typeof val === 'string') {
    const cleaned = val.replace(/[^0-9.,]/g, '');
    if (!cleaned) return undefined;
    // Handle comma thousands separator vs decimal comma cleanly
    const normalized =
      cleaned.includes(',') && cleaned.includes('.')
        ? cleaned.replace(/,/g, '')
        : cleaned.includes(',') && /,\d{2}$/.test(cleaned)
          ? cleaned.replace(',', '.')
          : cleaned.replace(/,/g, '');
    const num = Number(normalized);
    return Number.isFinite(num) && num > 0 ? num : undefined;
  }
  return undefined;
}

function normalizeCurrency(val: unknown): string | undefined {
  if (typeof val !== 'string') return undefined;
  const trimmed = val.trim().toUpperCase();
  if (/^[A-Z]{3}$/.test(trimmed)) return trimmed;
  if (trimmed === '$') return 'USD';
  if (trimmed === '₹' || trimmed === 'RS' || trimmed === 'RS.') return 'INR';
  if (trimmed === '€') return 'EUR';
  if (trimmed === '£') return 'GBP';
  return undefined;
}

function isProductType(nodeType: unknown): boolean {
  const types = Array.isArray(nodeType) ? nodeType : [nodeType];
  return types.some((t) => {
    if (typeof t !== 'string') return false;
    const clean = t.replace(/^https?:\/\/schema\.org\//i, '').toLowerCase();
    return clean === 'product' || clean === 'productgroup' || clean === 'individualproduct';
  });
}

function collectProductNodes(node: unknown, out: any[]): void {
  if (!node || typeof node !== 'object') return;
  if (Array.isArray(node)) {
    for (const item of node) collectProductNodes(item, out);
    return;
  }
  const obj = node as Record<string, any>;
  if (isProductType(obj['@type'])) {
    out.push(obj);
  }
  if (Array.isArray(obj['@graph'])) {
    collectProductNodes(obj['@graph'], out);
  }
  if (obj.mainEntity && typeof obj.mainEntity === 'object') {
    collectProductNodes(obj.mainEntity, out);
  }
}

function extractReturnStatusFromPolicy(policyNode: any): ReturnPolicyStatus {
  if (!policyNode) return 'unknown';
  const policies = Array.isArray(policyNode) ? policyNode : [policyNode];
  for (const p of policies) {
    if (!p || typeof p !== 'object') continue;
    const cat = String(p.returnPolicyCategory || p.merchantReturnDays || '').toLowerCase();
    if (cat.includes('notpermitted') || cat.includes('no_returns') || p.merchantReturnDays === 0) {
      return 'not_available';
    }
    if (
      cat.includes('finitereturnwindow') ||
      cat.includes('unlimitedwindow') ||
      (typeof p.merchantReturnDays === 'number' && p.merchantReturnDays > 0)
    ) {
      return 'available';
    }
  }
  return 'unknown';
}

export function extractProductMetadataFromHtml(
  html: string,
  requestedUrl: string,
  finalUrl: string,
  statusCode = 200
): ProductFetchDetailsResponse {
  const marketplaceInfo = detectMarketplaceFromUrl(finalUrl || requestedUrl);
  const blockReason = detectAccessRestrictionPage(html, statusCode);

  if (blockReason) {
    return {
      success: false,
      url: requestedUrl,
      finalUrl,
      marketplace: marketplaceInfo.name,
      accessRestricted: true,
      requiresAuthorizedApi: marketplaceInfo.typicallyRequiresAuthorizedApi,
      statusCode,
      message: `${blockReason}${
        marketplaceInfo.typicallyRequiresAuthorizedApi
          ? ` ${marketplaceInfo.name} restricts unauthenticated scraping and typically requires an authorized marketplace API.`
          : ''
      } You can still fill out the fields manually below.`,
      fieldSources: {},
      warnings: [blockReason],
    };
  }

  const extracted: ExtractedProductDetails = {
    returnPolicyStatus: 'unknown',
    sourcePlatform: marketplaceInfo.name,
  };
  const fieldSources: Record<string, string> = {};
  const warnings: string[] = [];

  // 1. Parse Schema.org JSON-LD blocks
  const jsonLdRegex = /<script[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  const productNodes: any[] = [];
  let scriptMatch: RegExpExecArray | null;
  while ((scriptMatch = jsonLdRegex.exec(html)) !== null) {
    const rawJson = scriptMatch[1].trim();
    if (!rawJson) continue;
    try {
      const parsed = JSON.parse(rawJson);
      collectProductNodes(parsed, productNodes);
    } catch {
      // Ignore malformed JSON-LD blocks cleanly
    }
  }

  for (const prod of productNodes) {
    if (!extracted.productName && typeof prod.name === 'string' && prod.name.trim()) {
      extracted.productName = decodeHtmlEntities(prod.name);
      fieldSources.productName = 'Schema.org Product JSON-LD';
    }

    if (!extracted.brand) {
      const rawBrand =
        typeof prod.brand === 'string'
          ? prod.brand
          : prod.brand?.name || prod.manufacturer?.name;
      if (typeof rawBrand === 'string' && rawBrand.trim()) {
        extracted.brand = decodeHtmlEntities(rawBrand);
        fieldSources.brand = 'Schema.org Product JSON-LD';
      }
    }

    if (!extracted.productDescription && typeof prod.description === 'string' && prod.description.trim()) {
      extracted.productDescription = decodeHtmlEntities(prod.description).slice(0, 1500);
      fieldSources.productDescription = 'Schema.org Product JSON-LD';
    }

    // Rule 10: Strictly accept numeric GTIN / UPC / EAN (never SKU or ASIN)
    if (!extracted.productIdentifier) {
      const gtinCandidates = [prod.gtin14, prod.gtin13, prod.gtin12, prod.gtin8, prod.gtin, prod.upc, prod.ean];
      for (const candidate of gtinCandidates) {
        if (typeof candidate === 'string' || typeof candidate === 'number') {
          const gs1 = validateGs1BarcodeFormat(String(candidate));
          if (gs1.isStandardLength) {
            extracted.productIdentifier = gs1.cleaned;
            fieldSources.productIdentifier = 'Schema.org Product JSON-LD (GTIN/UPC/EAN)';
            break;
          }
        }
      }
      if (!extracted.productIdentifier && (prod.sku || prod.mpn || prod.productID)) {
        warnings.push(
          'Found merchant SKU/MPN/ID in page metadata, which was intentionally not placed into the UPC/GTIN barcode field.'
        );
      }
    }

    // Rule 9: Never confuse Product aggregateRating with Seller Rating
    if (prod.aggregateRating && !prod.offers?.seller?.aggregateRating) {
      const pRating = parseNumericPrice(prod.aggregateRating.ratingValue);
      if (pRating !== undefined) {
        warnings.push(
          `Found product review rating (${pRating}/5) in page metadata; left Seller Rating empty because product ratings are not seller ratings.`
        );
      }
    }

    // Extract Offer / AggregateOffer details
    const rawOffers = prod.offers || prod.hasVariant?.[0]?.offers;
    const offerList = Array.isArray(rawOffers) ? rawOffers : rawOffers ? [rawOffers] : [];
    for (const offer of offerList) {
      if (!offer || typeof offer !== 'object') continue;

      if (extracted.listedPrice === undefined) {
        const directPrice = parseNumericPrice(
          offer.price ?? offer.lowPrice ?? offer.priceSpecification?.price
        );
        const directCurrency = normalizeCurrency(
          offer.priceCurrency ?? offer.priceSpecification?.priceCurrency
        );
        if (directPrice !== undefined) {
          extracted.listedPrice = directPrice;
          fieldSources.listedPrice = 'Schema.org Offer JSON-LD';
          if (directCurrency) {
            extracted.currency = directCurrency;
            fieldSources.currency = 'Schema.org Offer JSON-LD';
          }
        }
      }

      // Rule 11 & 12: Only accept referencePrice if explicitly marked MSRP and same currency
      if (extracted.referencePrice === undefined && offer.priceSpecification) {
        const specs = Array.isArray(offer.priceSpecification)
          ? offer.priceSpecification
          : [offer.priceSpecification];
        for (const spec of specs) {
          const priceType = String(spec?.priceType || '').toUpperCase();
          if (priceType.includes('MSRP')) {
            const msrpVal = parseNumericPrice(spec.price);
            const msrpCurr = normalizeCurrency(spec.priceCurrency);
            if (
              msrpVal !== undefined &&
              (!extracted.currency || !msrpCurr || extracted.currency === msrpCurr)
            ) {
              extracted.referencePrice = msrpVal;
              extracted.referenceCurrency = msrpCurr || extracted.currency;
              fieldSources.referencePrice = 'Schema.org MSRP PriceSpecification';
              break;
            }
          }
        }
      }
      if (offer.highPrice && extracted.referencePrice === undefined) {
        warnings.push(
          'Crossed-out or highPrice value in listing offer was not treated as verified MSRP.'
        );
      }

      // Seller info strictly from offer.seller
      if (offer.seller && typeof offer.seller === 'object') {
        if (!extracted.sellerName && typeof offer.seller.name === 'string' && offer.seller.name.trim()) {
          extracted.sellerName = decodeHtmlEntities(offer.seller.name);
          fieldSources.sellerName = 'Schema.org Offer.seller JSON-LD';
        }
        if (extracted.sellerRating === undefined && offer.seller.aggregateRating) {
          const sRating = parseNumericPrice(offer.seller.aggregateRating.ratingValue);
          const bestScale = parseNumericPrice(offer.seller.aggregateRating.bestRating) ?? 5;
          if (sRating !== undefined && bestScale > 0) {
            const normalized5 = Number(((sRating / bestScale) * 5).toFixed(2));
            if (normalized5 >= 0 && normalized5 <= 5) {
              extracted.sellerRating = normalized5;
              fieldSources.sellerRating = 'Schema.org Offer.seller.aggregateRating JSON-LD';
            }
          }
        }
      }

      if (extracted.returnPolicyStatus === 'unknown' && offer.hasMerchantReturnPolicy) {
        const policyStatus = extractReturnStatusFromPolicy(offer.hasMerchantReturnPolicy);
        if (policyStatus !== 'unknown') {
          extracted.returnPolicyStatus = policyStatus;
          fieldSources.returnPolicyStatus = 'Schema.org MerchantReturnPolicy JSON-LD';
        }
      }
    }
  }

  // 2. Fallback to Open Graph & standard HTML meta tags (only fill still-missing fields)
  const meta = extractMetaTags(html);

  const isPlaceholderText = (val: string) => {
    const clean = val.trim().toLowerCase();
    return (
      clean === 'amazon' ||
      clean === 'amazon.com' ||
      clean === 'flipkart' ||
      clean === 'myntra' ||
      clean === 'ebay' ||
      clean === 'site maintenance' ||
      clean === 'access denied' ||
      clean === 'robot check'
    );
  };

  if (!extracted.productName) {
    const ogTitle = meta.get('og:title') || meta.get('twitter:title');
    if (ogTitle && !isPlaceholderText(ogTitle)) {
      extracted.productName = ogTitle;
      fieldSources.productName = 'Open Graph metadata (og:title)';
    } else {
      const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
      const rawTitle = titleMatch ? decodeHtmlEntities(titleMatch[1]) : '';
      if (rawTitle && rawTitle.length > 2 && !isPlaceholderText(rawTitle)) {
        extracted.productName = rawTitle;
        fieldSources.productName = 'HTML <title> tag';
      }
    }
  }

  if (!extracted.productDescription) {
    const ogDesc = meta.get('og:description') || meta.get('description') || meta.get('twitter:description');
    if (ogDesc && !isPlaceholderText(ogDesc)) {
      extracted.productDescription = ogDesc.slice(0, 1500);
      fieldSources.productDescription = meta.get('og:description')
        ? 'Open Graph metadata (og:description)'
        : 'HTML meta description';
    }
  }

  if (!extracted.brand) {
    const ogBrand = meta.get('product:brand') || meta.get('og:brand') || meta.get('brand');
    if (ogBrand) {
      extracted.brand = ogBrand;
      fieldSources.brand = 'Open Graph / Meta brand tag';
    }
  }

  if (extracted.listedPrice === undefined) {
    const ogPrice = parseNumericPrice(
      meta.get('product:price:amount') ||
        meta.get('og:price:amount') ||
        meta.get('twitter:data1')
    );
    const ogCurrency = normalizeCurrency(
      meta.get('product:price:currency') || meta.get('og:price:currency')
    );
    if (ogPrice !== undefined) {
      extracted.listedPrice = ogPrice;
      fieldSources.listedPrice = meta.get('product:price:amount')
        ? 'Open Graph product:price:amount'
        : 'Open Graph / Meta price tag';
      if (ogCurrency) {
        extracted.currency = ogCurrency;
        fieldSources.currency = 'Open Graph price currency';
      }
    }
  }

  if (!extracted.productIdentifier) {
    const metaGtin = meta.get('product:upc') || meta.get('product:ean') || meta.get('product:gtin');
    if (metaGtin) {
      const gs1 = validateGs1BarcodeFormat(metaGtin);
      if (gs1.isStandardLength) {
        extracted.productIdentifier = gs1.cleaned;
        fieldSources.productIdentifier = 'Open Graph GS1 tag';
      }
    }
  }

  const retrievedCount = Object.keys(fieldSources).length;
  if (retrievedCount === 0) {
    return {
      success: false,
      url: requestedUrl,
      finalUrl,
      marketplace: marketplaceInfo.name,
      requiresAuthorizedApi: marketplaceInfo.typicallyRequiresAuthorizedApi,
      statusCode,
      message: `No public Schema.org Product or Open Graph product metadata was found on this page.${
        marketplaceInfo.typicallyRequiresAuthorizedApi
          ? ` ${marketplaceInfo.name} typically requires an authorized marketplace API for full product details.`
          : ''
      } Please enter the listing details manually.`,
      fieldSources,
      warnings,
    };
  }

  return {
    success: true,
    url: requestedUrl,
    finalUrl,
    marketplace: marketplaceInfo.name,
    requiresAuthorizedApi: marketplaceInfo.typicallyRequiresAuthorizedApi && retrievedCount < 3,
    statusCode,
    message: `Retrieved ${retrievedCount} public metadata field${retrievedCount === 1 ? '' : 's'} from ${marketplaceInfo.name}. Review and edit before running risk assessment.`,
    extracted,
    fieldSources,
    warnings,
  };
}

function isOrganizationOrStoreType(nodeType: unknown): boolean {
  const types = Array.isArray(nodeType) ? nodeType : [nodeType];
  return types.some((t) => {
    if (typeof t !== 'string') return false;
    const clean = t.replace(/^https?:\/\/schema\.org\//i, '').toLowerCase();
    return (
      clean === 'organization' ||
      clean === 'localbusiness' ||
      clean === 'onlinestore' ||
      clean === 'store' ||
      clean === 'corporation'
    );
  });
}

function collectSellerNodes(node: unknown, out: any[]): void {
  if (!node || typeof node !== 'object') return;
  if (Array.isArray(node)) {
    for (const item of node) collectSellerNodes(item, out);
    return;
  }
  const obj = node as Record<string, any>;
  if (isOrganizationOrStoreType(obj['@type'])) {
    out.push(obj);
  }
  if (Array.isArray(obj['@graph'])) {
    collectSellerNodes(obj['@graph'], out);
  }
  if (obj.publisher && typeof obj.publisher === 'object') {
    collectSellerNodes(obj.publisher, out);
  }
  if (obj.mainEntity && typeof obj.mainEntity === 'object') {
    collectSellerNodes(obj.mainEntity, out);
  }
}

function formatReturnPolicySummary(policyNode: any): string | undefined {
  if (!policyNode) return undefined;
  const policies = Array.isArray(policyNode) ? policyNode : [policyNode];
  for (const p of policies) {
    if (!p || typeof p !== 'object') continue;
    const cat = String(p.returnPolicyCategory || '').toLowerCase();
    if (cat.includes('notpermitted') || cat.includes('no_returns') || p.merchantReturnDays === 0) {
      return 'No returns / Final sale (MerchantReturnPolicy)';
    }
    if (typeof p.merchantReturnDays === 'number' && p.merchantReturnDays > 0) {
      return `${p.merchantReturnDays}-day return window`;
    }
    if (cat.includes('finitereturnwindow') || cat.includes('unlimitedwindow')) {
      return 'Returns accepted (MerchantReturnPolicy)';
    }
  }
  return undefined;
}

function formatBusinessRegistration(node: Record<string, any>): string | undefined {
  const parts: string[] = [];
  if (typeof node.legalName === 'string' && node.legalName.trim()) {
    parts.push(`Legal Name: ${decodeHtmlEntities(node.legalName)}`);
  }
  if (typeof node.taxID === 'string' && node.taxID.trim()) {
    parts.push(`Tax ID: ${decodeHtmlEntities(node.taxID)}`);
  }
  if (typeof node.vatID === 'string' && node.vatID.trim()) {
    parts.push(`VAT ID: ${decodeHtmlEntities(node.vatID)}`);
  }
  if (typeof node.duns === 'string' && node.duns.trim()) {
    parts.push(`DUNS: ${decodeHtmlEntities(node.duns)}`);
  }
  if (typeof node.leiCode === 'string' && node.leiCode.trim()) {
    parts.push(`LEI: ${decodeHtmlEntities(node.leiCode)}`);
  }
  if (typeof node.address === 'string' && node.address.trim()) {
    parts.push(`Address: ${decodeHtmlEntities(node.address)}`);
  } else if (node.address && typeof node.address === 'object') {
    const addrParts = [
      node.address.streetAddress,
      node.address.addressLocality,
      node.address.addressRegion,
      node.address.addressCountry,
    ]
      .filter((x) => typeof x === 'string' && x.trim())
      .map((x) => decodeHtmlEntities(String(x)));
    if (addrParts.length > 0) {
      parts.push(`Location: ${addrParts.join(', ')}`);
    }
  }
  return parts.length > 0 ? parts.join(' · ') : undefined;
}

export interface ExtractedSellerMetadataResult {
  accessRestricted: boolean;
  requiresAuthorizedApi: boolean;
  marketplace: string;
  statusCode: number;
  blockReason?: string;
  extractedBrand?: string;
  seller: SellerRetrievedInfo;
  warnings: string[];
}

/**
 * Extracts strictly seller/merchant metadata from public HTML & Schema.org JSON-LD.
 * Enforces anti-confusion rules: Product.aggregateRating is NEVER copied into Seller Rating.
 */
export function extractSellerMetadataFromHtml(
  html: string,
  requestedUrl: string,
  finalUrl: string,
  statusCode = 200
): ExtractedSellerMetadataResult {
  const marketplaceInfo = detectMarketplaceFromUrl(finalUrl || requestedUrl);
  const blockReason = detectAccessRestrictionPage(html, statusCode);

  const emptySeller: SellerRetrievedInfo = {
    authorizedSellerStatus: 'unavailable',
    returnPolicyStatus: 'unknown',
    sourceUrl: finalUrl || requestedUrl,
    fieldSources: {},
  };

  if (blockReason) {
    return {
      accessRestricted: true,
      requiresAuthorizedApi: marketplaceInfo.typicallyRequiresAuthorizedApi,
      marketplace: marketplaceInfo.name,
      statusCode,
      blockReason,
      seller: emptySeller,
      warnings: [blockReason],
    };
  }

  const seller: SellerRetrievedInfo = {
    authorizedSellerStatus: 'unavailable',
    returnPolicyStatus: 'unknown',
    sourceUrl: finalUrl || requestedUrl,
    fieldSources: {},
  };
  const warnings: string[] = [];
  let extractedBrand: string | undefined;

  const jsonLdRegex = /<script[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  const productNodes: any[] = [];
  const orgNodes: any[] = [];
  let scriptMatch: RegExpExecArray | null;

  while ((scriptMatch = jsonLdRegex.exec(html)) !== null) {
    const rawJson = scriptMatch[1].trim();
    if (!rawJson) continue;
    try {
      const parsed = JSON.parse(rawJson);
      collectProductNodes(parsed, productNodes);
      collectSellerNodes(parsed, orgNodes);
    } catch {
      // Ignore malformed JSON-LD blocks safely
    }
  }

  const applySellerObject = (node: any, sourceLabel: string) => {
    if (!node || typeof node !== 'object') return;

    if (!seller.sellerName && typeof node.name === 'string' && node.name.trim()) {
      seller.sellerName = decodeHtmlEntities(node.name);
      seller.fieldSources.sellerName = sourceLabel;
    }

    if (!seller.sellerProfileUrl) {
      const rawProfile = typeof node.url === 'string' ? node.url : typeof node['@id'] === 'string' ? node['@id'] : undefined;
      if (rawProfile && /^https?:\/\//i.test(rawProfile.trim())) {
        const urlCheck = validateWebsiteUrl(rawProfile.trim());
        if (urlCheck.valid && urlCheck.normalizedUrl) {
          seller.sellerProfileUrl = urlCheck.normalizedUrl;
          seller.fieldSources.sellerProfileUrl = sourceLabel;
        }
      }
    }

    if (seller.sellerRating === undefined && node.aggregateRating && typeof node.aggregateRating === 'object') {
      const sRating = parseNumericPrice(node.aggregateRating.ratingValue);
      const bestScale = parseNumericPrice(node.aggregateRating.bestRating) ?? 5;
      if (sRating !== undefined && bestScale > 0) {
        const normalized5 = Number(((sRating / bestScale) * 5).toFixed(2));
        if (normalized5 >= 0 && normalized5 <= 5) {
          seller.sellerRating = normalized5;
          seller.fieldSources.sellerRating = `${sourceLabel}.aggregateRating`;
        }
      }
      const rCount = parseNumericPrice(node.aggregateRating.ratingCount ?? node.aggregateRating.reviewCount);
      if (rCount !== undefined) {
        seller.sellerRatingCount = Math.round(rCount);
        seller.fieldSources.sellerRatingCount = `${sourceLabel}.aggregateRating`;
      }
    }

    if (!seller.foundingDate && typeof node.foundingDate === 'string' && !Number.isNaN(Date.parse(node.foundingDate))) {
      const iso = new Date(node.foundingDate).toISOString();
      seller.foundingDate = iso;
      seller.sellerAccountAgeDays = Math.max(0, Math.floor((Date.now() - Date.parse(iso)) / 86_400_000));
      seller.fieldSources.sellerAccountAge = `${sourceLabel}.foundingDate`;
    }

    if (!seller.businessRegistration) {
      const bizReg = formatBusinessRegistration(node);
      if (bizReg) {
        seller.businessRegistration = bizReg;
        seller.fieldSources.businessRegistration = sourceLabel;
      }
    }

    if (seller.returnPolicyStatus === 'unknown' && node.hasMerchantReturnPolicy) {
      const rpStatus = extractReturnStatusFromPolicy(node.hasMerchantReturnPolicy);
      if (rpStatus !== 'unknown') {
        seller.returnPolicyStatus = rpStatus;
        seller.returnPolicySummary = formatReturnPolicySummary(node.hasMerchantReturnPolicy);
        seller.fieldSources.returnPolicyStatus = `${sourceLabel}.hasMerchantReturnPolicy`;
      }
    }
  };

  // 1. Prioritize Offer.seller from Product JSON-LD
  for (const prod of productNodes) {
    if (!extractedBrand) {
      const rawBrand =
        typeof prod.brand === 'string' ? prod.brand : prod.brand?.name || prod.manufacturer?.name;
      if (typeof rawBrand === 'string' && rawBrand.trim()) {
        extractedBrand = decodeHtmlEntities(rawBrand);
      }
    }

    if (prod.aggregateRating && !prod.offers?.seller?.aggregateRating) {
      const pRating = parseNumericPrice(prod.aggregateRating.ratingValue);
      if (pRating !== undefined) {
        warnings.push(
          `Product aggregateRating (${pRating}/5) was intentionally excluded from Seller Rating.`
        );
      }
    }

    const rawOffers = prod.offers || prod.hasVariant?.[0]?.offers;
    const offerList = Array.isArray(rawOffers) ? rawOffers : rawOffers ? [rawOffers] : [];
    for (const offer of offerList) {
      if (!offer || typeof offer !== 'object') continue;
      if (offer.seller && typeof offer.seller === 'object') {
        applySellerObject(offer.seller, 'Schema.org Offer.seller JSON-LD');
      }
      if (seller.returnPolicyStatus === 'unknown' && offer.hasMerchantReturnPolicy) {
        const rpStatus = extractReturnStatusFromPolicy(offer.hasMerchantReturnPolicy);
        if (rpStatus !== 'unknown') {
          seller.returnPolicyStatus = rpStatus;
          seller.returnPolicySummary = formatReturnPolicySummary(offer.hasMerchantReturnPolicy);
          seller.fieldSources.returnPolicyStatus = 'Schema.org Offer.hasMerchantReturnPolicy';
        }
      }
    }
  }

  // 2. Inspect Organization / Store / OnlineStore JSON-LD nodes (e.g. official merchant page)
  for (const org of orgNodes) {
    applySellerObject(org, 'Schema.org Organization/Store JSON-LD');
  }

  // 3. Fallback seller name only from Open Graph site_name if no structured seller node existed
  if (!seller.sellerName) {
    const meta = extractMetaTags(html);
    const ogSite = meta.get('og:site_name');
    if (ogSite && ogSite.trim().length > 1) {
      // On large multi-vendor marketplaces, site_name is the marketplace itself, not the 3rd-party seller
      if (!marketplaceInfo.typicallyRequiresAuthorizedApi) {
        seller.sellerName = ogSite.trim();
        seller.fieldSources.sellerName = 'Open Graph og:site_name (merchant site)';
      } else {
        warnings.push(
          `Only marketplace name ("${ogSite.trim()}") was visible in HTML metadata; individual third-party seller identity was not disclosed.`
        );
      }
    }
  }

  return {
    accessRestricted: false,
    requiresAuthorizedApi: marketplaceInfo.typicallyRequiresAuthorizedApi && Object.keys(seller.fieldSources).length === 0,
    marketplace: marketplaceInfo.name,
    statusCode,
    extractedBrand,
    seller,
    warnings,
  };
}
