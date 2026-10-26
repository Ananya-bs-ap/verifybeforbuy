/**
 * URL Risk Analyzer
 * 
 * Inspects URL structure for phishing, brand impersonation, deceptive prefixes,
 * suspicious TLDs, and technical anomalies.
 * Strictly adheres to rule: HTTPS does not guarantee legitimacy; and do not
 * claim domain age without an external WHOIS data source.
 */

import { RiskIndicator, PositiveSignal } from '../../types';

interface AnalyzedUrlResult {
  indicators: RiskIndicator[];
  positiveSignals: PositiveSignal[];
  evidenceWeight: number; // contribution to coverage
  unverifiedAspects: string[];
}

const COMMON_TARGETED_BRANDS = [
  'amazon', 'apple', 'paypal', 'nike', 'rolex', 'sephora', 'target',
  'walmart', 'bestbuy', 'ebay', 'gucci', 'louisvuitton', 'chanel',
  'nordstrom', 'costco', 'aliexpress', 'zara', 'adidas', 'samsung'
];

const HIGH_ABUSE_TLDS = new Set([
  'top', 'xyz', 'click', 'buzz', 'work', 'rest', 'fit', 'surf', 'gq', 'cf', 'ml', 'tk', 'loan', 'racing'
]);

const TRUSTED_DOMAINS = new Set([
  'amazon.com', 'apple.com', 'paypal.com', 'nike.com', 'target.com',
  'walmart.com', 'bestbuy.com', 'ebay.com', 'nordstrom.com', 'costco.com',
  'samsung.com', 'adidas.com', 'zara.com', 'etsy.com', 'shopify.com'
]);

export function analyzeUrlStructure(rawUrl: string): AnalyzedUrlResult {
  const indicators: RiskIndicator[] = [];
  const positiveSignals: PositiveSignal[] = [];
  const unverifiedAspects: string[] = [
    'Domain age & WHOIS registration history (requires external registry lookup)',
    'Merchant legal entity registration & physical business address',
    'Actual TLS certificate issuance chain (requires active server probe)',
  ];

  let evidenceWeight = 30; // Base evidence for syntactic URL analysis

  // 1. Basic sanitization and protocol check
  let trimmed = rawUrl.trim();
  if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) {
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
      scoreImpact: 50,
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
  } else {
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
  const isIpv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  const isIpv6 = hostname.startsWith('[') && hostname.endsWith(']');
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
      remedyOrPrecaution: 'Check the root domain (the last two segments before the path) to identify who actually owns the site.',
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

  // 10. Brand Typosquatting / Impersonation Check
  const rootDomain = parts.slice(-2).join('.');
  const secondLevelDomain = parts.length >= 2 ? parts[parts.length - 2] : '';

  if (TRUSTED_DOMAINS.has(rootDomain)) {
    positiveSignals.push({
      id: 'recognized-official-domain',
      name: 'Recognized Official Brand Domain',
      description: `The root domain "${rootDomain}" matches a recognized global consumer platform.`,
      isVerified: true,
      scoreDeduction: 20,
    });
    evidenceWeight += 30;
  } else {
    // Check if a famous brand name is embedded in a lookalike fashion
    for (const brand of COMMON_TARGETED_BRANDS) {
      const containsBrand = hostname.includes(brand);
      if (containsBrand && !TRUSTED_DOMAINS.has(rootDomain)) {
        // Flag brand in subdomain or root SLD that isn't the official domain
        const isExactSld = secondLevelDomain === brand;
        const severity = isExactSld ? 'high' : 'medium';
        const impact = isExactSld ? 40 : 25;

        indicators.push({
          id: `brand-impersonation-${brand}`,
          name: `Unverified Brand Keyword in Domain ("${brand}")`,
          category: 'url',
          severity,
          scoreImpact: impact,
          isObserved: true,
          description: `The URL contains the brand name "${brand}", but the apex domain is "${rootDomain}" rather than the brand's verified primary domain.`,
          remedyOrPrecaution: `Search for ${brand}'s official website directly and navigate through their verified primary site.`,
        });
        break;
      }

      // Check common leetspeak substitutions (e.g. amaz0n, paypa1, ro1ex)
      const leetVariations = [
        brand.replace(/o/g, '0'),
        brand.replace(/l/g, '1'),
        brand.replace(/e/g, '3'),
        brand.replace(/i/g, '1'),
        brand.replace(/a/g, '4'),
      ].filter(v => v !== brand);

      const foundLeet = leetVariations.find(v => hostname.includes(v));
      if (foundLeet && !hostname.includes(brand)) {
        indicators.push({
          id: `typosquatting-leet-${brand}`,
          name: `Potential Typosquatting of Brand "${brand}"`,
          category: 'url',
          severity: 'high',
          scoreImpact: 45,
          isObserved: true,
          description: `Detected character substitution "${foundLeet}" mimicking the brand "${brand}". This is a common phishing and counterfeit storefront tactic.`,
          remedyOrPrecaution: 'Do not enter payment information. Inspect the spelling closely.',
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
    evidenceWeight: Math.min(evidenceWeight + (indicators.length > 0 ? 20 : 10), 100),
    unverifiedAspects,
  };
}
