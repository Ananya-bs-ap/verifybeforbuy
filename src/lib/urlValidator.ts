/**
 * Shared URL Structure Validation Helper
 * Rejects empty input, single-word gibberish (e.g. "kajsbdche", "hello123", "abc", "www"),
 * incomplete URLs ("https://"), unsupported protocols ("ftp://example.com"),
 * spaces, and malformed hostnames before ML prediction or risk scoring.
 */

export interface UrlValidationResult {
  valid: boolean;
  normalizedUrl?: string;
  hostname?: string;
  hadExplicitScheme: boolean;
  error?: string;
}

const BASE_INVALID_MSG = 'Invalid URL. Please enter a valid website address.';

export function isValidIpv4(host: string): boolean {
  const match = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!match) return false;
  return match.slice(1).every((oct) => {
    const n = Number(oct);
    return n >= 0 && n <= 255 && String(n) === oct;
  });
}

export function isValidIpv6(host: string): boolean {
  return host.startsWith('[') && host.endsWith(']') && host.length > 3 && host.includes(':');
}

export function isValidDomainName(hostname: string): boolean {
  const host = hostname.toLowerCase();
  if (!host || host.length > 253) return false;
  if (host.startsWith('.') || host.endsWith('.') || host.includes('..')) return false;

  const labels = host.split('.');
  // Must have at least 2 labels (e.g., example.com) so bare words like "kajsbdche" or "www" fail
  if (labels.length < 2) return false;

  const labelRegex = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
  for (const label of labels) {
    if (!labelRegex.test(label)) return false;
  }

  // Final TLD label must be >= 2 chars alphabetic or punycode (xn--...)
  const tld = labels[labels.length - 1];
  const validTld = /^[a-z]{2,24}$/.test(tld) || /^xn--[a-z0-9-]{2,}$/.test(tld);
  return validTld;
}

export function validateWebsiteUrl(rawInput: string): UrlValidationResult {
  const trimmed = (rawInput || '').trim();

  if (!trimmed) {
    return {
      valid: false,
      hadExplicitScheme: false,
      error: `${BASE_INVALID_MSG} The URL field cannot be empty.`,
    };
  }

  if (/\s/.test(trimmed)) {
    return {
      valid: false,
      hadExplicitScheme: false,
      error: `${BASE_INVALID_MSG} Remove any spaces from the address (example: https://example.com).`,
    };
  }

  // Detect any explicit scheme (e.g. http:, https:, ftp:, javascript:, etc.)
  const schemeMatch = trimmed.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):(.*)$/);
  const hadExplicitScheme = Boolean(schemeMatch);

  if (schemeMatch) {
    const scheme = schemeMatch[1].toLowerCase();
    if (scheme !== 'http' && scheme !== 'https') {
      return {
        valid: false,
        hadExplicitScheme: true,
        error: `${BASE_INVALID_MSG} Unsupported protocol "${scheme}:". Only http:// and https:// links are allowed.`,
      };
    }
    if (!trimmed.toLowerCase().startsWith('http://') && !trimmed.toLowerCase().startsWith('https://')) {
      return {
        valid: false,
        hadExplicitScheme: true,
        error: `${BASE_INVALID_MSG} Use the full format starting with http:// or https:// (example: https://example.com).`,
      };
    }
    const afterProto = trimmed.slice(scheme.length + 3);
    if (!afterProto || afterProto.startsWith('/')) {
      return {
        valid: false,
        hadExplicitScheme: true,
        error: `${BASE_INVALID_MSG} The address is missing a domain name after ${scheme}://.`,
      };
    }
  } else {
    // Without an explicit scheme, reject email-like strings or bare '@' prefixes
    if (trimmed.includes('@') && !trimmed.includes('/')) {
      return {
        valid: false,
        hadExplicitScheme: false,
        error: `${BASE_INVALID_MSG} Enter a website domain rather than an email address or handle.`,
      };
    }
  }

  const candidate = hadExplicitScheme ? trimmed : `https://${trimmed}`;
  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    return {
      valid: false,
      hadExplicitScheme,
      error: `${BASE_INVALID_MSG} Include a valid domain name such as https://example.com or example.com.`,
    };
  }

  // Verify characters before path don't contain malformed empty authority (e.g. https://@example.com)
  if (candidate.includes('@') && !parsed.username && !parsed.password) {
    return {
      valid: false,
      hadExplicitScheme,
      error: `${BASE_INVALID_MSG} Malformed authority characters detected in the URL.`,
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  if (!hostname) {
    return {
      valid: false,
      hadExplicitScheme,
      error: `${BASE_INVALID_MSG} A hostname is required (example: https://example.com).`,
    };
  }

  const validHost = isValidIpv4(hostname) || isValidIpv6(hostname) || isValidDomainName(hostname);
  if (!validHost) {
    return {
      valid: false,
      hadExplicitScheme,
      error: `${BASE_INVALID_MSG} Include a valid domain name and extension (example: https://example.com or google.com).`,
    };
  }

  return {
    valid: true,
    normalizedUrl: candidate,
    hostname,
    hadExplicitScheme,
  };
}
