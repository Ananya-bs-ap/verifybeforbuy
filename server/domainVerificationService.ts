/**
 * VerifyBeforeBuy AI — Live Domain Verification Service
 *
 * Performs real-time, SSRF-hardened domain inspection:
 * 1. DNS resolution & public IP pinning (anti-DNS-rebinding)
 * 2. Real SSL/TLS certificate chain, hostname identity, and expiration check
 * 3. HTTP -> HTTPS upgrade & multi-hop redirect chain inspection
 * 4. Authoritative RDAP registration date & domain age lookup via IANA bootstrap
 * 5. Threat intelligence feed checks (OpenPhish public feed + optional Safe Browsing / URLhaus)
 *
 * Strictly enforces:
 * - Never fabricates domain age, certificate metadata, or threat matches
 * - Handles timeouts, 429 rate limits, and missing external credentials gracefully
 */

import net from 'node:net';
import tls from 'node:tls';
import {
  DnsVerificationInfo,
  DomainVerificationResult,
  RdapVerificationInfo,
  RedirectHopInfo,
  RedirectVerificationInfo,
  ThreatIntelMatch,
  ThreatIntelProviderStatus,
  ThreatIntelVerificationInfo,
  TlsVerificationInfo,
} from '../src/types/index.ts';
import { getRegistrableDomain, validateWebsiteUrl } from '../src/lib/urlValidator.ts';
import { analyzeUrlStructure } from '../src/lib/riskEngine/urlAnalyzer.ts';
import {
  createPinnedLookup,
  DnsResolutionError,
  executePinnedSingleRequest,
  FetchTimeoutError,
  PinnedHttpHopResponse,
  PinnedPublicHost,
  resolveAndPinPublicHost,
  safeFetchPublicUrl,
  SsrfBlockedError,
} from './ssrfFetch.ts';

const IANA_RDAP_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';
const OPENPHISH_FEED_URL = 'https://openphish.com/feed.txt';

const RDAP_BOOTSTRAP_TTL_MS = 24 * 60 * 60 * 1000;
const OPENPHISH_CACHE_TTL_MS = 30 * 60 * 1000;
const DOMAIN_RESULT_CACHE_TTL_MS = 5 * 60 * 1000;

// Fallback authoritative RDAP endpoints for common TLDs if IANA bootstrap fetch is unreachable
const SEEDED_RDAP_SERVERS: Record<string, string> = {
  com: 'https://rdap.verisign.com/com/v1/',
  net: 'https://rdap.verisign.com/net/v1/',
  org: 'https://rdap.publicinterestregistry.org/rdap/',
  info: 'https://rdap.identitydigital.services/rdap/',
  biz: 'https://rdap.nic.biz/',
  xyz: 'https://rdap.centralnic.com/xyz/',
  click: 'https://rdap.nic.click/',
  top: 'https://rdap.zdnsgtld.com/top/',
  shop: 'https://rdap.gmoregistry.net/rdap/',
  io: 'https://rdap.nic.io/',
  app: 'https://rdap.nic.google/',
  dev: 'https://rdap.nic.google/',
  page: 'https://rdap.nic.google/',
  store: 'https://rdap.centralnic.com/store/',
  online: 'https://rdap.centralnic.com/online/',
  site: 'https://rdap.centralnic.com/site/',
  club: 'https://rdap.nic.club/',
  vip: 'https://rdap.nic.vip/',
  uk: 'https://rdap.nominet.uk/uk/',
  ca: 'https://rdap.ca.fury.ca/rdap/',
  au: 'https://rdap.audns.net.au/rdap/',
  in: 'https://rdap.registry.in/',
  fr: 'https://rdap.nic.fr/',
  nl: 'https://rdap.sidn.nl/',
  br: 'https://rdap.registro.br/',
  jp: 'https://rdap.jprs.jp/',
};

export { getRegistrableDomain };

// Shared multi-tenant hosting suffixes where one bad user URL must not taint the entire parent domain
const SHARED_HOSTING_SUFFIXES = new Set([
  'github.io',
  'gitlab.io',
  'sites.google.com',
  'docs.google.com',
  'drive.google.com',
  'herokuapp.com',
  'vercel.app',
  'netlify.app',
  'pages.dev',
  'blogspot.com',
  'wordpress.com',
  'weebly.com',
  'wixsite.com',
  'web.app',
  'firebaseapp.com',
  'azurewebsites.net',
  's3.amazonaws.com',
]);

const URL_SHORTENER_DOMAINS = new Set([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'ow.ly',
  'is.gd',
  'buff.ly',
  'cutt.ly',
  'rb.gy',
  'tiny.cc',
]);

export interface TlsProbeOutput {
  authorized: boolean;
  authorizationError?: string;
  hostnameMatches: boolean;
  hostnameError?: string;
  validFrom?: string;
  validTo?: string;
  subjectCN?: string;
  issuer?: string;
  protocol?: string;
}

export interface DomainVerificationOptions {
  timeoutMs?: number;
  maxRedirects?: number;
  bypassCache?: boolean;
  lookupFn?: (hostname: string) => Promise<Array<{ address: string; family: number }>>;
  httpRequestFn?: (
    parsedUrl: URL,
    pinned: PinnedPublicHost
  ) => Promise<PinnedHttpHopResponse>;
  tlsProbeFn?: (
    hostname: string,
    port: number,
    pinned: PinnedPublicHost
  ) => Promise<TlsProbeOutput>;
  fetchFn?: (
    url: string,
    init?: { headers?: Record<string, string>; method?: string; body?: string; timeoutMs?: number }
  ) => Promise<{ ok: boolean; status: number; text: () => Promise<string>; json: () => Promise<any> }>;
}

interface RdapBootstrapCache {
  tldMap: Record<string, string>;
  expiresAt: number;
}

interface OpenPhishCache {
  exactUrls: Set<string>;
  hostnames: Set<string>;
  expiresAt: number;
}

const domainResultCache = new Map<string, { value: DomainVerificationResult; expiresAt: number }>();
let rdapBootstrapCache: RdapBootstrapCache | null = null;
let openPhishCache: OpenPhishCache | null = null;

export function clearDomainVerificationCache(): void {
  domainResultCache.clear();
  rdapBootstrapCache = null;
  openPhishCache = null;
}

export function getDefaultDomainVerifyTimeoutMs(): number {
  const raw = process.env.DOMAIN_VERIFY_TIMEOUT_MS;
  if (raw) {
    const parsed = Number(raw);
    if (Number.isFinite(parsed) && parsed >= 1000 && parsed <= 20_000) {
      return Math.round(parsed);
    }
  }
  return 5000;
}

function getTld(apexDomain: string): string {
  const parts = apexDomain.split('.');
  return parts.length > 1 ? parts[parts.length - 1].toLowerCase() : '';
}

function normalizeUrlForThreatMatch(rawUrl: string): string {
  try {
    const parsed = new URL(rawUrl.trim());
    const cleanHost = parsed.hostname.toLowerCase().replace(/^www\./, '');
    const cleanPath = parsed.pathname.replace(/\/+$/, '') || '/';
    return `${cleanHost}${cleanPath}${parsed.search}`.toLowerCase();
  } catch {
    return rawUrl.trim().toLowerCase();
  }
}

async function defaultSsrfFetchJsonOrText(
  url: string,
  init?: { headers?: Record<string, string>; method?: string; body?: string; timeoutMs?: number }
): Promise<{ ok: boolean; status: number; text: () => Promise<string>; json: () => Promise<any> }> {
  const timeoutMs = init?.timeoutMs ?? getDefaultDomainVerifyTimeoutMs();

  if (init?.method === 'POST') {
    const parsed = new URL(url);
    const pinned = await resolveAndPinPublicHost(parsed.hostname);
    const res = await executePinnedSingleRequest(parsed, pinned, {
      method: 'POST',
      headers: init.headers,
      body: init.body,
      timeoutMs,
      maxBytes: 1_500_000,
      readBody: true,
    });
    return {
      ok: res.statusCode >= 200 && res.statusCode < 300,
      status: res.statusCode,
      text: async () => res.body,
      json: async () => JSON.parse(res.body),
    };
  }

  const fetched = await safeFetchPublicUrl(url, {
    timeoutMs,
    maxRedirects: 4,
    maxBytes: 2_500_000,
    headers: init?.headers,
  });

  return {
    ok: fetched.statusCode >= 200 && fetched.statusCode < 300,
    status: fetched.statusCode,
    text: async () => fetched.body,
    json: async () => JSON.parse(fetched.body),
  };
}

/**
 * Default live TLS certificate inspection using a pinned IP socket (prevents DNS rebinding).
 */
async function defaultPinnedTlsProbe(
  hostname: string,
  port: number,
  pinned: PinnedPublicHost,
  timeoutMs: number
): Promise<TlsProbeOutput> {
  return new Promise<TlsProbeOutput>((resolve, reject) => {
    let settled = false;
    const socket = tls.connect({
      host: pinned.ip,
      port,
      servername: hostname,
      rejectUnauthorized: false,
      lookup: createPinnedLookup(pinned) as any,
    });

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(new FetchTimeoutError(`TLS handshake timed out while checking ${hostname}.`));
    }, timeoutMs);

    socket.once('secureConnect', () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);

      try {
        const peerCert = socket.getPeerCertificate(false);
        const protocol = socket.getProtocol() || undefined;
        const authorized = socket.authorized;
        const authorizationError = socket.authorizationError
          ? String(socket.authorizationError)
          : undefined;

        let hostnameMatches = false;
        let hostnameError: string | undefined;
        if (peerCert && Object.keys(peerCert).length > 0) {
          const identityCheck = tls.checkServerIdentity(hostname, peerCert as any);
          if (!identityCheck) {
            hostnameMatches = true;
          } else {
            hostnameMatches = false;
            hostnameError = identityCheck.message;
          }
        }

        const subjectCN =
          peerCert?.subject && typeof peerCert.subject.CN === 'string'
            ? peerCert.subject.CN
            : undefined;
        const issuer =
          peerCert?.issuer &&
          (typeof peerCert.issuer.O === 'string'
            ? peerCert.issuer.O
            : typeof peerCert.issuer.CN === 'string'
              ? peerCert.issuer.CN
              : undefined);

        const validFrom =
          peerCert?.valid_from && !Number.isNaN(Date.parse(peerCert.valid_from))
            ? new Date(peerCert.valid_from).toISOString()
            : undefined;
        const validTo =
          peerCert?.valid_to && !Number.isNaN(Date.parse(peerCert.valid_to))
            ? new Date(peerCert.valid_to).toISOString()
            : undefined;

        socket.end();
        socket.destroy();

        resolve({
          authorized,
          authorizationError,
          hostnameMatches,
          hostnameError,
          validFrom,
          validTo,
          subjectCN,
          issuer,
          protocol,
        });
      } catch (err: any) {
        socket.destroy();
        reject(err);
      }
    });

    socket.once('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      reject(err);
    });
  });
}

async function checkTlsCertificate(
  targetUrl: URL,
  pinned: PinnedPublicHost,
  timeoutMs: number,
  tlsProbeFn?: DomainVerificationOptions['tlsProbeFn']
): Promise<TlsVerificationInfo> {
  if (targetUrl.protocol !== 'https:') {
    return {
      status: 'unavailable',
      checked: false,
      applicable: false,
      error: 'Site did not serve over HTTPS.',
    };
  }

  const port = targetUrl.port ? Number(targetUrl.port) : 443;

  try {
    const probe = tlsProbeFn
      ? await tlsProbeFn(targetUrl.hostname, port, pinned)
      : await defaultPinnedTlsProbe(targetUrl.hostname, port, pinned, timeoutMs);

    const nowMs = Date.now();
    const validToMs = probe.validTo ? Date.parse(probe.validTo) : NaN;
    const validFromMs = probe.validFrom ? Date.parse(probe.validFrom) : NaN;

    const isExpired = Number.isFinite(validToMs) ? validToMs < nowMs : false;
    const isNotYetValid = Number.isFinite(validFromMs) ? validFromMs > nowMs : false;
    const daysRemaining = Number.isFinite(validToMs)
      ? Math.floor((validToMs - nowMs) / 86_400_000)
      : undefined;

    const isTrusted = Boolean(probe.authorized && probe.hostnameMatches);
    const combinedAuthError = !probe.hostnameMatches
      ? probe.hostnameError || 'Certificate hostname mismatch'
      : probe.authorizationError;

    const isValidCert = isTrusted && !isExpired && !isNotYetValid;

    return {
      status: isValidCert ? 'verified' : 'suspicious',
      checked: true,
      applicable: true,
      isTrusted,
      isExpired,
      isNotYetValid,
      authorizationError: combinedAuthError,
      validFrom: probe.validFrom,
      validTo: probe.validTo,
      daysRemaining,
      subjectCN: probe.subjectCN,
      issuer: probe.issuer,
      protocol: probe.protocol,
    };
  } catch (err: any) {
    return {
      status: 'unavailable',
      checked: false,
      applicable: true,
      error: err?.message || 'TLS certificate inspection could not complete.',
    };
  }
}

function evaluateDestinationSuspicion(fromUrl: URL, toUrl: URL): { crossDomain: boolean; reason?: string } {
  const fromApex = getRegistrableDomain(fromUrl.hostname);
  const toApex = getRegistrableDomain(toUrl.hostname);
  const crossDomain = fromApex !== toApex;

  if (fromUrl.protocol === 'https:' && toUrl.protocol === 'http:') {
    return { crossDomain, reason: 'Downgrades encrypted HTTPS connection to plain HTTP' };
  }

  if (crossDomain) {
    const destAnalysis = analyzeUrlStructure(toUrl.toString());
    const highRiskFlag = destAnalysis.indicators.find((i) =>
      ['high-abuse-tld', 'ip-address-host', 'punycode-homograph', 'userinfo-obfuscation'].includes(i.id) ||
      i.id.startsWith('brand-impersonation-') ||
      i.id.startsWith('typosquatting-leet-')
    );
    if (highRiskFlag) {
      return {
        crossDomain: true,
        reason: `Cross-domain redirect target triggers "${highRiskFlag.name}" (${toApex})`,
      };
    }
    if (URL_SHORTENER_DOMAINS.has(toApex)) {
      return {
        crossDomain: true,
        reason: `Redirects through link shortener (${toApex})`,
      };
    }
  }

  return { crossDomain };
}

async function checkRedirects(
  initialParsedUrl: URL,
  initialPinned: PinnedPublicHost,
  timeoutMs: number,
  maxRedirects: number,
  options?: DomainVerificationOptions
): Promise<{
  redirects: RedirectVerificationInfo;
  finalParsedUrl: URL;
  finalPinned: PinnedPublicHost;
}> {
  let currentParsed = initialParsedUrl;
  let currentPinned = initialPinned;

  const hops: RedirectHopInfo[] = [];
  let httpToHttpsUpgrade = false;
  let crossDomainRedirect = false;
  let downgradeHttpsToHttp = false;
  let suspiciousDestination = false;
  const suspiciousReasons: string[] = [];
  let finalStatusCode: number | undefined;
  let chainError: string | undefined;

  for (let hop = 0; hop <= maxRedirects; hop++) {
    let response: PinnedHttpHopResponse;
    try {
      response = options?.httpRequestFn
        ? await options.httpRequestFn(currentParsed, currentPinned)
        : await executePinnedSingleRequest(currentParsed, currentPinned, {
            method: 'GET',
            timeoutMs,
            readBody: false,
            headers: {
              'User-Agent':
                'Mozilla/5.0 (compatible; VerifyBeforeBuy-DomainVerifier/1.0; +https://verifybeforebuy.local)',
              Accept: 'text/html,application/xhtml+xml,*/*;q=0.8',
            },
          });
    } catch (err: any) {
      chainError = err?.message || 'HTTP probe timed out or connection refused.';
      break;
    }

    finalStatusCode = response.statusCode;

    if (response.statusCode < 300 || response.statusCode >= 400) {
      break;
    }

    const rawLocation = response.headers.location;
    const location = Array.isArray(rawLocation) ? rawLocation[0] : rawLocation;
    if (!location) {
      chainError = `Received redirect status HTTP ${response.statusCode} without a Location header.`;
      break;
    }

    if (hop === maxRedirects) {
      suspiciousDestination = true;
      suspiciousReasons.push(`Redirect chain exceeded ${maxRedirects} hops.`);
      chainError = `Too many redirects (exceeded ${maxRedirects} hops).`;
      break;
    }

    let nextUrlStr: string;
    let nextParsed: URL;
    try {
      nextParsed = new URL(location, currentParsed.toString());
      nextUrlStr = nextParsed.toString();
    } catch {
      suspiciousDestination = true;
      suspiciousReasons.push('Redirect Location header contained a malformed URL.');
      break;
    }

    if (nextParsed.protocol !== 'http:' && nextParsed.protocol !== 'https:') {
      hops.push({
        fromUrl: currentParsed.toString(),
        toUrl: nextUrlStr,
        statusCode: response.statusCode,
        httpToHttpsUpgrade: false,
        crossDomain: true,
        blockedBySsrf: true,
        reason: `Blocked redirect to unsafe scheme "${nextParsed.protocol}"`,
      });
      suspiciousDestination = true;
      suspiciousReasons.push(`Attempted redirect to non-web scheme "${nextParsed.protocol}".`);
      break;
    }

    const urlCheck = validateWebsiteUrl(nextUrlStr);
    if (!urlCheck.valid || !urlCheck.hostname) {
      suspiciousDestination = true;
      suspiciousReasons.push('Redirect destination has an invalid hostname.');
      break;
    }

    let nextPinned: PinnedPublicHost;
    try {
      nextPinned = await resolveAndPinPublicHost(nextParsed.hostname, options?.lookupFn);
    } catch (err: any) {
      if (err instanceof SsrfBlockedError) {
        hops.push({
          fromUrl: currentParsed.toString(),
          toUrl: nextUrlStr,
          statusCode: response.statusCode,
          httpToHttpsUpgrade: false,
          crossDomain: true,
          blockedBySsrf: true,
          reason: err.message,
        });
        suspiciousDestination = true;
        suspiciousReasons.push(`Blocked redirect to private/internal address (${nextParsed.hostname}).`);
        break;
      }
      chainError = err?.message || `Redirect destination "${nextParsed.hostname}" failed DNS resolution.`;
      suspiciousDestination = true;
      suspiciousReasons.push(`Redirects to unresolvable domain "${nextParsed.hostname}".`);
      break;
    }

    const fromApex = getRegistrableDomain(currentParsed.hostname);
    const toApex = getRegistrableDomain(nextParsed.hostname);
    const isSameApexUpgrade =
      currentParsed.protocol === 'http:' &&
      nextParsed.protocol === 'https:' &&
      fromApex === toApex;

    if (isSameApexUpgrade) {
      httpToHttpsUpgrade = true;
    }

    const isDowngrade = currentParsed.protocol === 'https:' && nextParsed.protocol === 'http:';
    if (isDowngrade) {
      downgradeHttpsToHttp = true;
    }

    const destCheck = evaluateDestinationSuspicion(currentParsed, nextParsed);
    if (destCheck.crossDomain) {
      crossDomainRedirect = true;
    }
    if (destCheck.reason) {
      suspiciousDestination = true;
      suspiciousReasons.push(destCheck.reason);
    }

    hops.push({
      fromUrl: currentParsed.toString(),
      toUrl: nextUrlStr,
      statusCode: response.statusCode,
      httpToHttpsUpgrade: isSameApexUpgrade,
      crossDomain: destCheck.crossDomain,
      reason: destCheck.reason,
    });

    currentParsed = nextParsed;
    currentPinned = nextPinned;
  }

  if (hops.length >= 3 && crossDomainRedirect) {
    suspiciousDestination = true;
    suspiciousReasons.push(`Long multi-hop cross-domain redirect chain (${hops.length} hops).`);
  }

  const status: RedirectVerificationInfo['status'] = suspiciousDestination || downgradeHttpsToHttp
    ? 'suspicious'
    : finalStatusCode !== undefined
      ? 'verified'
      : 'unavailable';

  return {
    redirects: {
      status,
      initialUrl: initialParsedUrl.toString(),
      finalUrl: currentParsed.toString(),
      finalStatusCode,
      hopCount: hops.length,
      httpToHttpsUpgrade,
      crossDomainRedirect,
      downgradeHttpsToHttp,
      suspiciousDestination,
      suspiciousReasons: Array.from(new Set(suspiciousReasons)),
      hops,
      error: chainError,
    },
    finalParsedUrl: currentParsed,
    finalPinned: currentPinned,
  };
}

async function getRdapBaseUrlForTld(
  tld: string,
  fetchFn: NonNullable<DomainVerificationOptions['fetchFn']>,
  timeoutMs: number
): Promise<string | undefined> {
  if (!tld) return undefined;

  if (!rdapBootstrapCache || rdapBootstrapCache.expiresAt <= Date.now()) {
    try {
      const res = await fetchFn(IANA_RDAP_BOOTSTRAP_URL, {
        headers: { Accept: 'application/json' },
        timeoutMs,
      });
      if (res.ok) {
        const data = await res.json();
        const tldMap: Record<string, string> = {};
        if (Array.isArray(data?.services)) {
          for (const entry of data.services) {
            if (!Array.isArray(entry) || entry.length < 2) continue;
            const [tlds, urls] = entry;
            if (!Array.isArray(tlds) || !Array.isArray(urls) || urls.length === 0) continue;
            const base = String(urls[0]).trim();
            if (!base.startsWith('https://')) continue;
            for (const rawTld of tlds) {
              tldMap[String(rawTld).toLowerCase()] = base.endsWith('/') ? base : `${base}/`;
            }
          }
        }
        if (Object.keys(tldMap).length > 0) {
          rdapBootstrapCache = {
            tldMap,
            expiresAt: Date.now() + RDAP_BOOTSTRAP_TTL_MS,
          };
        }
      }
    } catch {
      // Fall back silently to seeded RDAP table
    }
  }

  return rdapBootstrapCache?.tldMap[tld] || SEEDED_RDAP_SERVERS[tld];
}

function extractRegistrarFromRdapEntities(entities: any): string | undefined {
  if (!Array.isArray(entities)) return undefined;
  for (const entity of entities) {
    const roles: string[] = Array.isArray(entity?.roles) ? entity.roles : [];
    if (roles.some((r) => String(r).toLowerCase() === 'registrar')) {
      const vcard = entity?.vcardArray;
      if (Array.isArray(vcard) && Array.isArray(vcard[1])) {
        for (const prop of vcard[1]) {
          if (Array.isArray(prop) && prop[0] === 'fn' && typeof prop[3] === 'string' && prop[3].trim()) {
            return prop[3].trim();
          }
        }
      }
      if (typeof entity?.handle === 'string' && entity.handle.trim()) {
        return entity.handle.trim();
      }
    }
    if (Array.isArray(entity?.entities)) {
      const nested = extractRegistrarFromRdapEntities(entity.entities);
      if (nested) return nested;
    }
  }
  return undefined;
}

async function checkRdapRegistration(
  hostname: string,
  timeoutMs: number,
  fetchFn: NonNullable<DomainVerificationOptions['fetchFn']>
): Promise<RdapVerificationInfo> {
  if (net.isIP(hostname.replace(/^\[|\]$/g, '')) !== 0) {
    return {
      status: 'unavailable',
      error: 'RDAP domain registration lookup is not applicable for raw IP addresses.',
    };
  }

  const apexDomain = getRegistrableDomain(hostname);
  const tld = getTld(apexDomain);

  const rdapBase = await getRdapBaseUrlForTld(tld, fetchFn, timeoutMs);
  if (!rdapBase) {
    return {
      status: 'unavailable',
      apexDomain,
      error: `No authoritative public RDAP server found in IANA registry for .${tld || 'unknown'}.`,
    };
  }

  const queryUrl = `${rdapBase}domain/${encodeURIComponent(apexDomain)}`;

  try {
    const res = await fetchFn(queryUrl, {
      headers: {
        Accept: 'application/rdap+json, application/json',
        'User-Agent': 'VerifyBeforeBuy-DomainVerifier/1.0',
      },
      timeoutMs,
    });

    if (res.status === 429) {
      return {
        status: 'unavailable',
        apexDomain,
        rdapServer: rdapBase,
        error: 'RDAP registry rate-limited the request (HTTP 429).',
      };
    }

    if (res.status === 404) {
      return {
        status: 'unavailable',
        apexDomain,
        rdapServer: rdapBase,
        error: 'Domain registration record not found in authoritative RDAP service.',
      };
    }

    if (!res.ok) {
      return {
        status: 'unavailable',
        apexDomain,
        rdapServer: rdapBase,
        error: `RDAP registry returned HTTP ${res.status}.`,
      };
    }

    const data = await res.json();
    let registrationDate: string | undefined;
    let expirationDate: string | undefined;

    if (Array.isArray(data?.events)) {
      for (const ev of data.events) {
        const action = String(ev?.eventAction || '').toLowerCase();
        const rawDate = ev?.eventDate;
        if (typeof rawDate !== 'string' || Number.isNaN(Date.parse(rawDate))) continue;
        const iso = new Date(rawDate).toISOString();
        if (action === 'registration' && !registrationDate) {
          registrationDate = iso;
        } else if (action === 'expiration' && !expirationDate) {
          expirationDate = iso;
        }
      }
    }

    const registrar = extractRegistrarFromRdapEntities(data?.entities);

    if (!registrationDate) {
      return {
        status: 'unavailable',
        apexDomain,
        rdapServer: rdapBase,
        expirationDate,
        registrar,
        error: 'RDAP record did not disclose a domain registration timestamp.',
      };
    }

    const regMs = Date.parse(registrationDate);
    const domainAgeDays = Math.max(0, Math.floor((Date.now() - regMs) / 86_400_000));

    return {
      status: domainAgeDays < 180 ? 'suspicious' : 'verified',
      apexDomain,
      rdapServer: rdapBase,
      registrationDate,
      expirationDate,
      domainAgeDays,
      registrar,
    };
  } catch (err: any) {
    return {
      status: 'unavailable',
      apexDomain,
      rdapServer: rdapBase,
      error: err?.message || 'RDAP lookup timed out or failed.',
    };
  }
}

async function checkThreatIntel(
  normalizedUrl: string,
  hostname: string,
  timeoutMs: number,
  fetchFn: NonNullable<DomainVerificationOptions['fetchFn']>,
  bypassCache?: boolean
): Promise<ThreatIntelVerificationInfo> {
  const matches: ThreatIntelMatch[] = [];
  const providers: ThreatIntelProviderStatus[] = [];

  // 1. OpenPhish public feed (unauthenticated HTTP 200)
  try {
    let openPhishFetchFailed = false;
    if (bypassCache || !openPhishCache || openPhishCache.expiresAt <= Date.now()) {
      const feedRes = await fetchFn(OPENPHISH_FEED_URL, {
        headers: { Accept: 'text/plain' },
        timeoutMs,
      });

      if (feedRes.status === 429) {
        openPhishFetchFailed = true;
        providers.push({
          provider: 'OpenPhish Community Feed',
          checked: false,
          status: 'unavailable',
          detail: 'Rate limited (HTTP 429)',
        });
      } else if (!feedRes.ok) {
        openPhishFetchFailed = true;
        providers.push({
          provider: 'OpenPhish Community Feed',
          checked: false,
          status: 'unavailable',
          detail: `Feed unavailable (HTTP ${feedRes.status})`,
        });
      } else {
        const text = await feedRes.text();
        const exactUrls = new Set<string>();
        const hostnames = new Set<string>();

        for (const rawLine of text.split(/\r?\n/)) {
          const line = rawLine.trim();
          if (!line || !line.startsWith('http')) continue;
          exactUrls.add(normalizeUrlForThreatMatch(line));
          try {
            const u = new URL(line);
            const cleanHost = u.hostname.toLowerCase().replace(/^www\./, '');
            if (cleanHost) hostnames.add(cleanHost);
          } catch {
            // Skip malformed feed line
          }
        }

        openPhishCache = {
          exactUrls,
          hostnames,
          expiresAt: Date.now() + OPENPHISH_CACHE_TTL_MS,
        };
      }
    }

    if (!openPhishFetchFailed && openPhishCache) {
      const normalizedTarget = normalizeUrlForThreatMatch(normalizedUrl);
      const cleanHost = hostname.toLowerCase().replace(/^www\./, '');
      const apex = getRegistrableDomain(cleanHost);
      const isSharedHost = SHARED_HOSTING_SUFFIXES.has(apex) || SHARED_HOSTING_SUFFIXES.has(cleanHost);

      const exactHit = openPhishCache.exactUrls.has(normalizedTarget);
      const hostHit = !isSharedHost && openPhishCache.hostnames.has(cleanHost);

      if (exactHit || hostHit) {
        matches.push({
          provider: 'OpenPhish Community Feed',
          threatType: 'phishing',
          reference: exactHit ? 'Exact URL match in active phishing feed' : 'Hostname listed in active phishing feed',
        });
        providers.push({
          provider: 'OpenPhish Community Feed',
          checked: true,
          status: 'flagged',
          detail: exactHit ? 'Matched phishing URL' : 'Matched phishing hostname',
        });
      } else {
        providers.push({
          provider: 'OpenPhish Community Feed',
          checked: true,
          status: 'clean',
          detail: `Screened against ${openPhishCache.exactUrls.size.toLocaleString()} active phishing URLs`,
        });
      }
    }
  } catch (err: any) {
    providers.push({
      provider: 'OpenPhish Community Feed',
      checked: false,
      status: 'unavailable',
      detail: err?.message || 'Feed request timed out',
    });
  }

  // 2. Optional Google Safe Browsing API (only if user configured an optional key)
  const safeBrowsingKey = process.env.SAFE_BROWSING_API_KEY || process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  if (safeBrowsingKey && safeBrowsingKey.trim().length > 8) {
    try {
      const sbRes = await fetchFn(
        `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(safeBrowsingKey.trim())}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            client: { clientId: 'verifybeforebuy-ai', clientVersion: '1.0.0' },
            threatInfo: {
              threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
              platformTypes: ['ANY_PLATFORM'],
              threatEntryTypes: ['URL'],
              threatEntries: [{ url: normalizedUrl }],
            },
          }),
          timeoutMs,
        }
      );

      if (sbRes.ok) {
        const payload = await sbRes.json();
        const foundMatches = Array.isArray(payload?.matches) ? payload.matches : [];
        if (foundMatches.length > 0) {
          matches.push({
            provider: 'Google Safe Browsing',
            threatType: String(foundMatches[0]?.threatType || 'SOCIAL_ENGINEERING'),
            reference: 'Listed in Google Safe Browsing Lookup API',
          });
          providers.push({
            provider: 'Google Safe Browsing',
            checked: true,
            status: 'flagged',
            detail: `Flagged (${foundMatches[0]?.threatType || 'threat match'})`,
          });
        } else {
          providers.push({
            provider: 'Google Safe Browsing',
            checked: true,
            status: 'clean',
            detail: 'No Safe Browsing match',
          });
        }
      } else {
        providers.push({
          provider: 'Google Safe Browsing',
          checked: false,
          status: 'unavailable',
          detail: `Returned HTTP ${sbRes.status}`,
        });
      }
    } catch (err: any) {
      providers.push({
        provider: 'Google Safe Browsing',
        checked: false,
        status: 'unavailable',
        detail: err?.message || 'Lookup failed',
      });
    }
  } else {
    providers.push({
      provider: 'Google Safe Browsing',
      checked: false,
      status: 'unavailable',
      detail: 'Optional SAFE_BROWSING_API_KEY not configured',
    });
  }

  // 3. Optional Abuse.ch URLhaus API (only if optional Auth-Key is configured)
  const urlhausKey = process.env.URLHAUS_AUTH_KEY;
  if (urlhausKey && urlhausKey.trim().length > 4) {
    try {
      const uhRes = await fetchFn('https://urlhaus-api.abuse.ch/v1/host/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Auth-Key': urlhausKey.trim(),
        },
        body: `host=${encodeURIComponent(hostname)}`,
        timeoutMs,
      });

      if (uhRes.ok) {
        const uhJson = await uhRes.json();
        if (uhJson?.query_status === 'ok' && Array.isArray(uhJson?.urls) && uhJson.urls.length > 0) {
          matches.push({
            provider: 'Abuse.ch URLhaus',
            threatType: 'malware/phishing host',
            reference: `${uhJson.urls.length} reported malicious URLs on host`,
          });
          providers.push({
            provider: 'Abuse.ch URLhaus',
            checked: true,
            status: 'flagged',
            detail: `${uhJson.urls.length} listed URLs`,
          });
        } else {
          providers.push({
            provider: 'Abuse.ch URLhaus',
            checked: true,
            status: 'clean',
            detail: 'Host not listed',
          });
        }
      } else {
        providers.push({
          provider: 'Abuse.ch URLhaus',
          checked: false,
          status: 'unavailable',
          detail: `Returned HTTP ${uhRes.status}`,
        });
      }
    } catch (err: any) {
      providers.push({
        provider: 'Abuse.ch URLhaus',
        checked: false,
        status: 'unavailable',
        detail: err?.message || 'Lookup failed',
      });
    }
  } else {
    providers.push({
      provider: 'Abuse.ch URLhaus',
      checked: false,
      status: 'unavailable',
      detail: 'Optional URLHAUS_AUTH_KEY not configured',
    });
  }

  const anyChecked = providers.some((p) => p.checked);
  const listed = matches.length > 0;

  return {
    status: listed ? 'suspicious' : anyChecked ? 'verified' : 'unavailable',
    listed,
    matches,
    providers,
  };
}

/**
 * Perform full SSRF-hardened real-time domain verification for a validated website URL.
 */
export async function verifyWebsiteDomain(
  rawUrl: string,
  options?: DomainVerificationOptions
): Promise<DomainVerificationResult> {
  const validation = validateWebsiteUrl(rawUrl);
  if (!validation.valid || !validation.normalizedUrl || !validation.hostname) {
    throw new Error(validation.error || 'Invalid website URL.');
  }

  const parsedInitial = new URL(validation.normalizedUrl);
  const hostname = parsedInitial.hostname.toLowerCase();
  const apexDomain = getRegistrableDomain(hostname);

  const hasCustomHooks = Boolean(
    options?.lookupFn || options?.httpRequestFn || options?.tlsProbeFn || options?.fetchFn
  );
  const cacheKey = validation.normalizedUrl.toLowerCase();

  if (!options?.bypassCache && !hasCustomHooks) {
    const cached = domainResultCache.get(cacheKey);
    if (cached && cached.expiresAt > Date.now()) {
      return { ...cached.value, cached: true };
    }
  }

  const timeoutMs = options?.timeoutMs ?? getDefaultDomainVerifyTimeoutMs();
  const maxRedirects = options?.maxRedirects ?? 5;
  const fetchFn = options?.fetchFn ?? defaultSsrfFetchJsonOrText;

  // Step 1: DNS Resolution & IP Pinning (SSRF errors propagate to block private/loopback/rebinding hosts)
  let pinnedInitial: PinnedPublicHost | null = null;
  let dnsInfo: DnsVerificationInfo;

  try {
    pinnedInitial = await resolveAndPinPublicHost(hostname, options?.lookupFn);
    dnsInfo = {
      status: 'verified',
      hostname,
      exists: true,
      resolvedIps: pinnedInitial.allIps,
    };
  } catch (err: any) {
    if (err instanceof SsrfBlockedError) {
      throw err;
    }

    const errCode = err instanceof DnsResolutionError ? err.code : err?.code || 'ENOTFOUND';
    const isTransientTimeout = errCode === 'EAI_AGAIN' || errCode === 'ETIMEDOUT' || errCode === 'ECONNREFUSED';

    dnsInfo = {
      status: isTransientTimeout ? 'unavailable' : 'suspicious',
      hostname,
      exists: false,
      resolvedIps: [],
      error: err?.message || `Domain "${hostname}" could not be resolved in DNS.`,
    };
  }

  // Run RDAP and Threat Intel concurrently even if DNS failed (e.g. unregistered domain confirmation)
  const rdapPromise = checkRdapRegistration(hostname, timeoutMs, fetchFn);
  const threatPromise = checkThreatIntel(
    validation.normalizedUrl,
    hostname,
    timeoutMs,
    fetchFn,
    options?.bypassCache || hasCustomHooks
  );

  let redirectsInfo: RedirectVerificationInfo;
  let tlsInfo: TlsVerificationInfo;

  if (pinnedInitial) {
    const redirectResult = await checkRedirects(
      parsedInitial,
      pinnedInitial,
      timeoutMs,
      maxRedirects,
      options
    );
    redirectsInfo = redirectResult.redirects;

    // Inspect real TLS certificate on HTTPS initial URL or HTTPS upgraded destination
    const tlsTargetUrl =
      parsedInitial.protocol === 'https:'
        ? parsedInitial
        : redirectResult.finalParsedUrl.protocol === 'https:'
          ? redirectResult.finalParsedUrl
          : parsedInitial;
    const tlsTargetPinned =
      tlsTargetUrl === parsedInitial ? pinnedInitial : redirectResult.finalPinned;

    tlsInfo = await checkTlsCertificate(
      tlsTargetUrl,
      tlsTargetPinned,
      timeoutMs,
      options?.tlsProbeFn
    );
  } else {
    redirectsInfo = {
      status: 'unavailable',
      initialUrl: validation.normalizedUrl,
      finalUrl: validation.normalizedUrl,
      hopCount: 0,
      httpToHttpsUpgrade: false,
      crossDomainRedirect: false,
      downgradeHttpsToHttp: false,
      suspiciousDestination: false,
      suspiciousReasons: [],
      hops: [],
      error: 'Skipped live HTTP redirect check because DNS resolution failed.',
    };
    tlsInfo = {
      status: 'unavailable',
      checked: false,
      applicable: parsedInitial.protocol === 'https:',
      error: 'Skipped TLS certificate verification because DNS resolution failed.',
    };
  }

  const [rdapInfo, threatIntelInfo] = await Promise.all([rdapPromise, threatPromise]);

  const result: DomainVerificationResult = {
    hostname,
    apexDomain,
    checkedAt: new Date().toISOString(),
    dns: dnsInfo,
    tls: tlsInfo,
    rdap: rdapInfo,
    redirects: redirectsInfo,
    threatIntel: threatIntelInfo,
    cached: false,
  };

  if (!options?.bypassCache && !hasCustomHooks) {
    domainResultCache.set(cacheKey, {
      value: result,
      expiresAt: Date.now() + DOMAIN_RESULT_CACHE_TTL_MS,
    });
  }

  return result;
}
