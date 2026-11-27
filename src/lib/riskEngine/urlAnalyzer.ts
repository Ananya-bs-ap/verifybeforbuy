/**
 * URL Risk Analyzer
 * 
 * Inspects URL structure for phishing, brand impersonation, deceptive prefixes,
 * suspicious TLDs, and technical anomalies.
 * Strictly adheres to rule: HTTPS does not guarantee legitimacy; and do not
 * claim domain age without an external WHOIS data source.
 */

import { RiskIndicator, PositiveSignal } from '../../types';
import {
  getRegistrableDomain,
  isValidDomainName,
  isValidIpv4,
  isValidIpv6,
} from '../urlValidator';

interface AnalyzedUrlResult {
  indicators: RiskIndicator[];
  positiveSignals: PositiveSignal[];
  evidenceWeight: number; // contribution to coverage
  unverifiedAspects: string[];
}

export const COMMON_TARGETED_BRANDS = [
  'amazon', 'apple', 'paypal', 'nike', 'rolex', 'sephora', 'target',
  'walmart', 'bestbuy', 'ebay', 'gucci', 'louisvuitton', 'chanel',
  'nordstrom', 'costco', 'aliexpress', 'zara', 'adidas', 'samsung',
] as const;

const HIGH_ABUSE_TLDS = new Set([
  'top', 'xyz', 'click', 'buzz', 'work', 'rest', 'fit', 'surf', 'gq', 'cf', 'ml', 'tk', 'loan', 'racing',
]);

/**
 * Verified official primary & regional domains per brand.
 * Only exact registrable-domain matches against this map are recognized as official
 * (never substring matches), and official recognition never bypasses TLS/RDAP/redirect/threat checks.
 */
export const OFFICIAL_BRAND_DOMAINS: Record<string, readonly string[]> = {
  amazon: [
    'amazon.com',
    'amazon.in',
    'amazon.co.uk',
    'amazon.de',
    'amazon.co.jp',
    'amazon.ca',
    'amazon.fr',
    'amazon.it',
    'amazon.es',
    'amazon.nl',
    'amazon.se',
    'amazon.pl',
    'amazon.sg',
    'amazon.ae',
    'amazon.sa',
    'amazon.eg',
    'amazon.com.au',
    'amazon.com.br',
    'amazon.com.mx',
    'amazon.com.tr',
    'amazon.com.be',
  ],
  apple: [
    'apple.com',
    'apple.co.uk',
    'apple.in',
    'apple.de',
    'apple.ca',
    'apple.fr',
    'apple.co.jp',
    'apple.com.au',
  ],
  paypal: [
    'paypal.com',
    'paypal.co.uk',
    'paypal.in',
    'paypal.de',
    'paypal.ca',
    'paypal.fr',
    'paypal.it',
    'paypal.es',
    'paypal.nl',
    'paypal.com.au',
    'paypal.com.br',
    'paypal.com.mx',
    'paypal.co.jp',
    'paypal.me',
  ],
  nike: [
    'nike.com',
    'nike.co.uk',
    'nike.in',
    'nike.de',
    'nike.ca',
    'nike.fr',
    'nike.jp',
  ],
  rolex: ['rolex.com'],
  sephora: [
    'sephora.com',
    'sephora.in',
    'sephora.fr',
    'sephora.co.uk',
    'sephora.ca',
    'sephora.de',
    'sephora.it',
    'sephora.es',
    'sephora.com.au',
    'sephora.sg',
    'sephora.com.br',
    'sephora.com.mx',
  ],
  target: ['target.com', 'target.com.au'],
  walmart: ['walmart.com', 'walmart.ca', 'walmart.com.mx', 'walmart.cl'],
  bestbuy: ['bestbuy.com', 'bestbuy.ca'],
  ebay: [
    'ebay.com',
    'ebay.in',
    'ebay.co.uk',
    'ebay.de',
    'ebay.ca',
    'ebay.fr',
    'ebay.it',
    'ebay.es',
    'ebay.com.au',
    'ebay.nl',
    'ebay.at',
    'ebay.ch',
    'ebay.ie',
    'ebay.pl',
    'ebay.com.sg',
    'ebay.com.my',
    'ebay.com.hk',
  ],
  gucci: ['gucci.com'],
  louisvuitton: ['louisvuitton.com'],
  chanel: ['chanel.com'],
  nordstrom: ['nordstrom.com', 'nordstromrack.com'],
  costco: [
    'costco.com',
    'costco.ca',
    'costco.co.uk',
    'costco.com.mx',
    'costco.co.jp',
    'costco.com.au',
    'costco.co.kr',
    'costco.com.tw',
  ],
  aliexpress: ['aliexpress.com', 'aliexpress.us', 'aliexpress.ru'],
  zara: ['zara.com'],
  adidas: [
    'adidas.com',
    'adidas.co.in',
    'adidas.co.uk',
    'adidas.de',
    'adidas.ca',
    'adidas.fr',
    'adidas.it',
    'adidas.es',
    'adidas.nl',
    'adidas.com.au',
    'adidas.jp',
    'adidas.co.kr',
    'adidas.com.br',
    'adidas.com.sg',
  ],
  samsung: ['samsung.com', 'samsung.in', 'samsung.co.uk', 'samsung.de', 'samsung.ca'],
  etsy: ['etsy.com'],
  shopify: [
    'shopify.com',
    'shopify.in',
    'shopify.ca',
    'shopify.co.uk',
    'shopify.de',
    'shopify.com.au',
  ],
};

export const TRUSTED_DOMAINS = new Set<string>(
  Object.values(OFFICIAL_BRAND_DOMAINS).flat()
);

const BRAND_COMPOUND_AFFIXES = [
  'login', 'signin', 'verify', 'secure', 'security', 'account', 'update',
  'support', 'service', 'help', 'billing', 'pay', 'shop', 'store', 'deal',
  'deals', 'outlet', 'official', 'promo', 'sale', 'auth', 'portal', 'club',
  'vip', 'discount', 'cheap', 'buy', 'order', 'track', 'claim', 'reward',
  'gift', 'card', 'wallet', 'id', 'mail', 'my', 'get', 'real', 'true',
  'usa', 'uk', 'india',
];

const SECURITY_IMPERSONATION_AFFIXES = new Set([
  'login', 'signin', 'verify', 'secure', 'security', 'account', 'update',
  'support', 'billing', 'auth', 'portal', 'wallet', 'claim', 'reward', 'official',
]);

interface BrandBoundaryMatch {
  matched: boolean;
  exactLabelMatch: boolean;
  hasSecurityAffix: boolean;
}

/**
 * Matches a brand or lookalike term strictly on domain label, hyphen/digit token,
 * or known phishing/commercial compound affix boundaries (avoiding false positives
 * on unrelated dictionary words such as "thebay.com" or "pineapple.com").
 */
function matchesBrandWithBoundary(
  hostname: string,
  registrableDomain: string,
  term: string
): BrandBoundaryMatch {
  const hostLabels = hostname.split('.').filter(Boolean);
  const registrableParts = registrableDomain.split('.').filter(Boolean);
  const registrableSld = registrableParts[0] || '';
  const subdomainLabels = hostLabels.slice(0, Math.max(0, hostLabels.length - registrableParts.length));
  const nonTldLabels = [...subdomainLabels, registrableSld].filter(Boolean);

  if (registrableSld === term || subdomainLabels.includes(term)) {
    const otherTokens = nonTldLabels.flatMap((lbl) => lbl.split(/[-_\d]+/).filter(Boolean));
    const hasSecurityAffix = otherTokens.some((tok) => SECURITY_IMPERSONATION_AFFIXES.has(tok));
    return { matched: true, exactLabelMatch: true, hasSecurityAffix };
  }

  for (const label of nonTldLabels) {
    const tokens = label.split(/[-_\d]+/).filter(Boolean);
    if (tokens.includes(term)) {
      const hasSecurityAffix = tokens.some((tok) => SECURITY_IMPERSONATION_AFFIXES.has(tok));
      return { matched: true, exactLabelMatch: false, hasSecurityAffix };
    }

    const idx = label.indexOf(term);
    if (idx !== -1) {
      const before = label.slice(0, idx);
      const after = label.slice(idx + term.length);
      const beforeOk =
        before === '' ||
        BRAND_COMPOUND_AFFIXES.some((affix) => before === affix || before.endsWith(`-${affix}`));
      const afterOk =
        after === '' ||
        BRAND_COMPOUND_AFFIXES.some((affix) => after === affix || after.startsWith(`${affix}-`));

      if (beforeOk && afterOk && (before !== '' || after !== '')) {
        const hasSecurityAffix = Array.from(SECURITY_IMPERSONATION_AFFIXES).some(
          (affix) => before.includes(affix) || after.includes(affix)
        );
        return { matched: true, exactLabelMatch: false, hasSecurityAffix };
      }
    }
  }

  return { matched: false, exactLabelMatch: false, hasSecurityAffix: false };
}

function buildLeetVariations(brand: string): string[] {
  const variations = new Set<string>([
    brand.replace(/o/g, '0'),
    brand.replace(/l/g, '1'),
    brand.replace(/e/g, '3'),
    brand.replace(/i/g, '1'),
    brand.replace(/a/g, '4'),
  ]);

  const subs: Record<string, string> = { o: '0', l: '1', e: '3', i: '1', a: '4' };
  for (let i = 0; i < brand.length; i++) {
    const replacement = subs[brand[i]];
    if (replacement) {
      variations.add(`${brand.slice(0, i)}${replacement}${brand.slice(i + 1)}`);
    }
  }

  variations.delete(brand);
  return Array.from(variations).filter((v) => v.length >= 4);
}

export function analyzeUrlStructure(rawUrl: string): AnalyzedUrlResult {
  const indicators: RiskIndicator[] = [];
  const positiveSignals: PositiveSignal[] = [];
  const unverifiedAspects: string[] = [
    'Domain age & WHOIS registration history (requires external registry lookup)',
    'Merchant legal entity registration & physical business address',
    'Actual TLS certificate issuance chain (requires active server probe)',
  ];

  const evidenceWeight = 20; // Base evidence for syntactic URL analysis

  // 1. Basic sanitization and explicit protocol tracking
  let trimmed = rawUrl.trim();
  const hasAnyScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed);
  const hadExplicitHttpScheme = /^https?:\/\//i.test(trimmed);

  if (!trimmed || /\s/.test(trimmed)) {
    indicators.push({
      id: 'invalid-url-format',
      name: 'Invalid URL Structure',
      category: 'technical',
      severity: 'high',
      scoreImpact: 60,
      isObserved: true,
      description: 'The input is empty or contains whitespace and is not a valid web address.',
      remedyOrPrecaution: 'Enter a complete domain or web URL such as https://example.com.',
    });
    return { indicators, positiveSignals, evidenceWeight: 10, unverifiedAspects };
  }

  if (!hasAnyScheme) {
    trimmed = 'https://' + trimmed;
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    indicators.push({
      id: 'invalid-url-format',
      name: 'Malformed URL Syntax',
      category: 'technical',
      severity: 'high',
      scoreImpact: 60,
      isObserved: true,
      description: 'The supplied text is not a valid RFC-compliant web address.',
      remedyOrPrecaution: 'Verify the full address from your browser address bar or message source.',
    });
    return { indicators, positiveSignals, evidenceWeight: 10, unverifiedAspects };
  }

  // Check unsafe schemes
  const protocol = parsed.protocol.toLowerCase();
  if (protocol !== 'http:' && protocol !== 'https:') {
    indicators.push({
      id: 'unsafe-protocol',
      name: 'Non-Standard Web Scheme',
      category: 'technical',
      severity: 'high',
      scoreImpact: 80,
      isObserved: true,
      description: `Protocol "${protocol}" can be used for local script execution or credential harvesting.`,
      remedyOrPrecaution: 'Never navigate to non-http/https links from unverified sources.',
    });
    return { indicators, positiveSignals, evidenceWeight: 40, unverifiedAspects };
  }

  const hostname = parsed.hostname.toLowerCase();
  const pathname = parsed.pathname.toLowerCase();

  // Enforce valid domain structure (reject bare words like "isjbfwe" without a valid TLD or IP)
  const validHost = isValidIpv4(hostname) || isValidIpv6(hostname) || isValidDomainName(hostname);
  if (!validHost) {
    indicators.push({
      id: 'invalid-url-format',
      name: 'Invalid URL / Missing Domain Extension',
      category: 'technical',
      severity: 'high',
      scoreImpact: 60,
      isObserved: true,
      description: `"${rawUrl.trim()}" does not have a valid domain extension (TLD) or IP host structure.`,
      remedyOrPrecaution: 'Enter a complete website address such as https://example.com or example.com.',
    });
    return { indicators, positiveSignals, evidenceWeight: 15, unverifiedAspects };
  }

  // 2. Protocol Check (HTTP vs HTTPS)
  if (protocol === 'http:') {
    indicators.push({
      id: 'insecure-http',
      name: 'Unencrypted Connection (HTTP)',
      category: 'technical',
      severity: 'medium',
      scoreImpact: 25,
      isObserved: true,
      description: 'The connection is unencrypted. Payment details and credentials can be intercepted by third parties.',
      remedyOrPrecaution: 'Never submit credit card details, passwords, or personal data on unencrypted HTTP pages.',
    });
  } else if (hadExplicitHttpScheme) {
    positiveSignals.push({
      id: 'https-enabled',
      name: 'Standard HTTPS Encryption',
      description: 'The website specifies TLS encryption. (Note: HTTPS encrypts transit but does not prove merchant legitimacy).',
      isVerified: true,
      scoreDeduction: 5,
    });
  }

  // 3. Userinfo in URL (e.g. https://google.com@evil.com)
  if (parsed.username || parsed.password) {
    indicators.push({
      id: 'userinfo-obfuscation',
      name: 'Credential Masking / Deceptive Authority',
      category: 'url',
      severity: 'high',
      scoreImpact: 45,
      isObserved: true,
      description: 'The URL embeds authority user credentials (username@hostname), a classic trick to make an address appear as another site.',
      remedyOrPrecaution: 'Do not visit this URL. It is actively masking the real destination host.',
    });
  }

  // 4. IP Address Hostname
  const isIpv4 = isValidIpv4(hostname);
  const isIpv6 = isValidIpv6(hostname);
  if (isIpv4 || isIpv6) {
    indicators.push({
      id: 'ip-address-host',
      name: 'Raw IP Address Hostname',
      category: 'technical',
      severity: 'high',
      scoreImpact: 40,
      isObserved: true,
      description: 'Legitimate retail businesses use registered domain names, whereas phishing and disposable scam shops frequently use raw IP addresses.',
      remedyOrPrecaution: 'Avoid purchasing from raw IP addresses.',
    });
  }

  // 5. Non-standard shopping port
  if (parsed.port && parsed.port !== '80' && parsed.port !== '443') {
    indicators.push({
      id: 'unusual-port',
      name: 'Non-Standard Web Port',
      category: 'technical',
      severity: 'medium',
      scoreImpact: 20,
      isObserved: true,
      description: `URL points to port :${parsed.port}. Most genuine commercial stores operate on standard ports 80/443.`,
      remedyOrPrecaution: 'Check whether this is an internal staging server or rogue endpoint.',
    });
  }

  // 6. Suspicious TLD
  const parts = hostname.split('.');
  const tld = parts.length > 1 ? parts[parts.length - 1] : '';
  if (HIGH_ABUSE_TLDS.has(tld)) {
    indicators.push({
      id: 'high-abuse-tld',
      name: `Unusual / High-Abuse Top-Level Domain (.${tld})`,
      category: 'url',
      severity: 'medium',
      scoreImpact: 25,
      isObserved: true,
      description: `The .${tld} top-level domain has historically high correlation with disposable affiliate redirects and temporary storefronts.`,
      remedyOrPrecaution: 'Verify the merchant company registration and confirm they have an official main domain.',
    });
  }

  // 7. Excessive Subdomains
  if (parts.length > 4) {
    indicators.push({
      id: 'excessive-subdomains',
      name: 'Deep Subdomain Nesting',
      category: 'url',
      severity: 'low',
      scoreImpact: 15,
      isObserved: true,
      description: `Domain has ${parts.length - 2} levels of subdomains (${hostname}), frequently used to bury suspicious domains behind familiar keywords.`,
      remedyOrPrecaution: 'Check the registrable root domain before the path to identify who actually owns the site.',
    });
  }

  // 8. Hyphen Stuffing
  const hyphenMatches = hostname.match(/-/g);
  if (hyphenMatches && hyphenMatches.length >= 3) {
    indicators.push({
      id: 'hyphen-stuffing',
      name: 'Multiple Hyphen Delimiters in Domain',
      category: 'url',
      severity: 'medium',
      scoreImpact: 20,
      isObserved: true,
      description: `Hostname contains ${hyphenMatches.length} hyphens (e.g. "${hostname}"). Scam shops often chain keywords like official-brand-outlet-sale.`,
      remedyOrPrecaution: 'Look up the brand’s authentic domain via an independent search engine rather than clicking multi-hyphen links.',
    });
  }

  // 9. Punycode / Internationalized Domain Name (IDN) Homograph
  if (hostname.includes('xn--')) {
    indicators.push({
      id: 'punycode-homograph',
      name: 'Punycode / Homograph Character Encoding',
      category: 'url',
      severity: 'high',
      scoreImpact: 35,
      isObserved: true,
      description: 'Domain uses Punycode (xn--), which can substitute Cyrillic, Greek, or Latin lookalike letters to impersonate legitimate brand spellings.',
      remedyOrPrecaution: 'Inspect the decoded ASCII characters carefully to ensure the domain is not mimicking a major retailer.',
    });
  }

  // 10. Official Domain & Brand Typosquatting / Impersonation Check
  const registrableDomain = getRegistrableDomain(hostname);

  if (TRUSTED_DOMAINS.has(registrableDomain)) {
    positiveSignals.push({
      id: 'recognized-official-domain',
      name: 'Recognized Official Brand Domain',
      description: `The registrable domain "${registrableDomain}" matches a verified official global or regional domain. (Note: Domain recognition never bypasses TLS, redirect, or threat-feed checks).`,
      isVerified: true,
      scoreDeduction: 20,
    });
  } else {
    // Check if a famous brand name is embedded at a domain/token/compound boundary
    for (const brand of COMMON_TARGETED_BRANDS) {
      const brandMatch = matchesBrandWithBoundary(hostname, registrableDomain, brand);
      if (brandMatch.matched) {
        const isHighSeverity = brandMatch.exactLabelMatch || brandMatch.hasSecurityAffix;
        const severity = isHighSeverity ? 'high' : 'medium';
        const impact = brandMatch.exactLabelMatch ? 40 : brandMatch.hasSecurityAffix ? 35 : 28;
        const officialExamples = (OFFICIAL_BRAND_DOMAINS[brand] || []).slice(0, 3).join(', ');

        indicators.push({
          id: `brand-impersonation-${brand}`,
          name: `Unverified Brand Keyword in Domain ("${brand}")`,
          category: 'url',
          severity,
          scoreImpact: impact,
          isObserved: true,
          description: `The hostname contains the brand name "${brand}", but the registrable domain is "${registrableDomain}" rather than an official verified domain${officialExamples ? ` (such as ${officialExamples})` : ''}.`,
          remedyOrPrecaution: `Search for ${brand}'s official website directly and navigate through their verified domain.`,
        });
        break;
      }

      // Check common leetspeak substitutions (e.g. amaz0n, paypa1, ro1ex) with boundary awareness
      const leetVariations = buildLeetVariations(brand);
      const foundLeet = leetVariations.find(
        (variant) => matchesBrandWithBoundary(hostname, registrableDomain, variant).matched
      );
      if (foundLeet) {
        indicators.push({
          id: `typosquatting-leet-${brand}`,
          name: `Potential Typosquatting of Brand "${brand}"`,
          category: 'url',
          severity: 'high',
          scoreImpact: 45,
          isObserved: true,
          description: `Detected character substitution "${foundLeet}" mimicking the brand "${brand}" on domain "${registrableDomain}". This is a common phishing and counterfeit storefront tactic.`,
          remedyOrPrecaution: 'Do not enter payment information. Inspect the domain spelling closely.',
        });
        break;
      }
    }
  }

  // 11. Suspicious Path keywords (e.g., /login/update-billing, /claim-free-gift)
  const suspiciousPathTokens = ['update-billing', 'verify-account', 'free-gift-card', 'claim-reward', 'login-confirm'];
  for (const token of suspiciousPathTokens) {
    if (pathname.includes(token)) {
      indicators.push({
        id: `suspicious-path-${token}`,
        name: 'Urgent Account Action in URL Path',
        category: 'content',
        severity: 'medium',
        scoreImpact: 20,
        isObserved: true,
        description: `Path contains "${token}", a signature commonly seen in credential harvesting and prize scam redirects.`,
        remedyOrPrecaution: 'Verify your account status by logging in directly from the official mobile app or verified homepage.',
      });
      break;
    }
  }

  return {
    indicators,
    positiveSignals,
    evidenceWeight,
    unverifiedAspects,
  };
}
