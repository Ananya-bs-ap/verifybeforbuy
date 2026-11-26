/**
 * Hardened Outbound HTTP/HTTPS Fetcher & DNS-Pinning Guard with SSRF Protection
 *
 * Enforces:
 * - Strict HTTP/HTTPS scheme & URL validation
 * - Single-resolution DNS check blocking loopback, private RFC1918, link-local/metadata,
 *   carrier-grade NAT, unspecified, and private IPv4-mapped IPv6 addresses
 * - Socket-level IP pinning (prevents DNS rebinding TOCTOU between validation and connect)
 * - Manual redirect validation across every redirect hop
 * - Request timeout & maximum response byte cap
 */

import dns from 'node:dns/promises';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { validateWebsiteUrl } from '../src/lib/urlValidator.ts';

export class SsrfBlockedError extends Error {
  public readonly statusCode = 403;
  constructor(message: string) {
    super(message);
    this.name = 'SsrfBlockedError';
  }
}

export class FetchValidationError extends Error {
  public readonly statusCode = 400;
  constructor(message: string) {
    super(message);
    this.name = 'FetchValidationError';
  }
}

export class FetchTimeoutError extends Error {
  public readonly statusCode = 504;
  constructor(message: string) {
    super(message);
    this.name = 'FetchTimeoutError';
  }
}

export class DnsResolutionError extends Error {
  public readonly code: string;
  constructor(message: string, code = 'ENOTFOUND') {
    super(message);
    this.name = 'DnsResolutionError';
    this.code = code;
  }
}

export interface PinnedPublicHost {
  hostname: string;
  ip: string;
  family: 4 | 6;
  allIps: string[];
}

function ipv4ToInt(ip: string): number {
  const parts = ip.split('.').map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function inIpv4Cidr(ipInt: number, base: string, prefixBits: number): boolean {
  const baseInt = ipv4ToInt(base);
  const mask = prefixBits === 0 ? 0 : (0xffffffff << (32 - prefixBits)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}

export function isPrivateOrReservedIp(rawIp: string): boolean {
  const ip = rawIp.trim().toLowerCase().replace(/^\[|\]$/g, '');
  const ipVersion = net.isIP(ip);

  if (ipVersion === 4) {
    const ipInt = ipv4ToInt(ip);
    const blockedCidrs: Array<[string, number]> = [
      ['0.0.0.0', 8],       // "This" network
      ['10.0.0.0', 8],      // RFC1918 Private
      ['100.64.0.0', 10],   // Carrier-Grade NAT (RFC6598)
      ['127.0.0.0', 8],     // Loopback
      ['169.254.0.0', 16],  // Link-local / Cloud Metadata (169.254.169.254)
      ['172.16.0.0', 12],   // RFC1918 Private
      ['192.0.0.0', 24],    // IETF Protocol Assignments
      ['192.0.2.0', 24],    // TEST-NET-1
      ['192.168.0.0', 16],  // RFC1918 Private
      ['198.18.0.0', 15],   // Benchmarking
      ['198.51.100.0', 24], // TEST-NET-2
      ['203.0.113.0', 24],  // TEST-NET-3
      ['224.0.0.0', 4],     // Multicast
      ['240.0.0.0', 4],     // Reserved / Broadcast
    ];
    return blockedCidrs.some(([base, bits]) => inIpv4Cidr(ipInt, base, bits));
  }

  if (ipVersion === 6) {
    const noZone = ip.split('%')[0];
    if (noZone === '::' || noZone === '::1') return true;

    // Unwrap IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1 or ::ffff:7f00:1)
    if (noZone.startsWith('::ffff:')) {
      const tail = noZone.slice('::ffff:'.length);
      if (net.isIPv4(tail)) {
        return isPrivateOrReservedIp(tail);
      }
      const hexPair = tail.match(/^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
      if (hexPair) {
        const hi = parseInt(hexPair[1], 16);
        const lo = parseInt(hexPair[2], 16);
        const mappedIpv4 = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
        return isPrivateOrReservedIp(mappedIpv4);
      }
      return true;
    }

    // Unique local IPv6 (fc00::/7), link-local (fe80::/10), multicast (ff00::/8)
    const firstHextet = parseInt(noZone.split(':')[0] || '0', 16);
    if ((firstHextet & 0xfe00) === 0xfc00) return true; // fc00::/7
    if ((firstHextet & 0xffc0) === 0xfe80) return true; // fe80::/10
    if ((firstHextet & 0xff00) === 0xff00) return true; // ff00::/8

    return false;
  }

  return true; // Unknown IP family blocked by default
}

/**
 * Resolves a hostname once, blocks any private/loopback/reserved IPs,
 * and returns a pinned public IP + address family to prevent DNS rebinding (TOCTOU).
 */
export async function resolveAndPinPublicHost(
  rawHostname: string,
  lookupFn?: (hostname: string) => Promise<Array<{ address: string; family: number }>>
): Promise<PinnedPublicHost> {
  const host = rawHostname.trim().toLowerCase().replace(/^\[|\]$/g, '');

  if (
    !host ||
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host.endsWith('.internal') ||
    host.endsWith('.local')
  ) {
    throw new SsrfBlockedError('Security restriction: Local or internal hostnames cannot be fetched.');
  }

  const ipVersion = net.isIP(host);
  if (ipVersion !== 0) {
    if (isPrivateOrReservedIp(host)) {
      throw new SsrfBlockedError(
        'Security restriction: Private, loopback, link-local, or reserved IP addresses cannot be fetched.'
      );
    }
    return {
      hostname: host,
      ip: host,
      family: ipVersion === 6 ? 6 : 4,
      allIps: [host],
    };
  }

  let resolved: Array<{ address: string; family: number }>;
  try {
    resolved = lookupFn
      ? await lookupFn(host)
      : await dns.lookup(host, { all: true });
  } catch (err: any) {
    throw new DnsResolutionError(
      `Could not resolve domain "${host}" in DNS.`,
      err?.code || 'ENOTFOUND'
    );
  }

  if (!resolved || resolved.length === 0) {
    throw new DnsResolutionError(`No public DNS records found for "${host}".`, 'ENODATA');
  }

  for (const record of resolved) {
    if (isPrivateOrReservedIp(record.address)) {
      throw new SsrfBlockedError(
        'Security restriction: Destination hostname resolved to a private, loopback, or metadata IP address.'
      );
    }
  }

  // Prefer IPv4 first for reliable outbound compatibility, falling back to first validated public record
  const preferred = resolved.find((r) => r.family === 4) || resolved[0];
  const uniqueIps = Array.from(new Set(resolved.map((r) => r.address)));

  return {
    hostname: host,
    ip: preferred.address,
    family: preferred.family === 6 ? 6 : 4,
    allIps: uniqueIps,
  };
}

export async function assertHostnameResolvesPublic(rawHostname: string): Promise<void> {
  await resolveAndPinPublicHost(rawHostname);
}

/**
 * Node http/https lookup callback that always returns the already-validated pinned IP,
 * defending against DNS rebinding between validation and socket connection.
 */
export function createPinnedLookup(pinned: PinnedPublicHost) {
  return (_hostname: string, options: any, callback: any) => {
    const cb = typeof options === 'function' ? options : callback;
    const wantsAll = typeof options === 'object' && options !== null && Boolean(options.all);
    if (wantsAll) {
      cb(null, [{ address: pinned.ip, family: pinned.family }]);
    } else {
      cb(null, pinned.ip, pinned.family);
    }
  };
}

export interface PinnedHttpHopResponse {
  statusCode: number;
  headers: http.IncomingHttpHeaders;
  body: string;
}

/**
 * Single HTTP/HTTPS request executed against an already-pinned public IP (no redirects followed).
 */
export async function executePinnedSingleRequest(
  parsedUrl: URL,
  pinned: PinnedPublicHost,
  options?: {
    method?: 'GET' | 'HEAD' | 'POST';
    headers?: Record<string, string>;
    body?: string;
    timeoutMs?: number;
    maxBytes?: number;
    readBody?: boolean;
  }
): Promise<PinnedHttpHopResponse> {
  const method = options?.method ?? 'GET';
  const timeoutMs = options?.timeoutMs ?? 8000;
  const maxBytes = options?.maxBytes ?? 2_500_000;
  const readBody = options?.readBody !== false;

  const isHttps = parsedUrl.protocol === 'https:';
  const defaultPort = isHttps ? 443 : 80;
  const port = parsedUrl.port ? Number(parsedUrl.port) : defaultPort;
  const pathWithQuery = `${parsedUrl.pathname || '/'}${parsedUrl.search || ''}`;

  return new Promise<PinnedHttpHopResponse>((resolve, reject) => {
    let settled = false;
    const finishErr = (err: Error) => {
      if (settled) return;
      settled = true;
      reject(err);
    };

    const transport = isHttps ? https : http;
    const reqOptions: https.RequestOptions = {
      protocol: parsedUrl.protocol,
      hostname: parsedUrl.hostname,
      port,
      path: pathWithQuery,
      method,
      headers: {
        Host: parsedUrl.host,
        ...(options?.headers || {}),
      },
      lookup: createPinnedLookup(pinned) as any,
      ...(isHttps ? { servername: parsedUrl.hostname } : {}),
    };

    const req = transport.request(reqOptions, (res) => {
      const statusCode = res.statusCode ?? 0;

      if (!readBody || (statusCode >= 300 && statusCode < 400)) {
        res.destroy();
        if (!settled) {
          settled = true;
          resolve({ statusCode, headers: res.headers, body: '' });
        }
        return;
      }

      const chunks: Buffer[] = [];
      let totalBytes = 0;
      let truncated = false;

      res.on('data', (chunk: Buffer) => {
        if (settled || truncated) return;
        const remaining = maxBytes - totalBytes;
        if (remaining <= 0) {
          truncated = true;
          res.destroy();
          return;
        }
        const slice = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk;
        chunks.push(slice);
        totalBytes += slice.length;
        if (totalBytes >= maxBytes) {
          truncated = true;
          res.destroy();
        }
      });

      const finalize = () => {
        if (settled) return;
        settled = true;
        resolve({
          statusCode,
          headers: res.headers,
          body: Buffer.concat(chunks).toString('utf-8'),
        });
      };

      res.on('end', finalize);
      res.on('close', () => {
        if (truncated && !settled) finalize();
      });
      res.on('error', (err) => finishErr(err));
    });

    req.setTimeout(timeoutMs, () => {
      req.destroy(
        new FetchTimeoutError(
          `Request timed out after ${Math.round(timeoutMs / 1000)}s while contacting ${parsedUrl.hostname}.`
        )
      );
    });

    req.on('error', (err: any) => {
      if (err instanceof FetchTimeoutError) {
        finishErr(err);
      } else {
        finishErr(new Error(`Could not connect to ${parsedUrl.hostname}: ${err?.message || 'Network error'}`));
      }
    });

    if (options?.body) {
      req.write(options.body);
    }
    req.end();
  });
}

export interface SafeFetchResult {
  finalUrl: string;
  statusCode: number;
  contentType: string;
  body: string;
}

export async function safeFetchPublicUrl(
  initialUrl: string,
  options?: {
    timeoutMs?: number;
    maxRedirects?: number;
    maxBytes?: number;
    headers?: Record<string, string>;
  }
): Promise<SafeFetchResult> {
  const timeoutMs = options?.timeoutMs ?? 10_000;
  const maxRedirects = options?.maxRedirects ?? 5;
  const maxBytes = options?.maxBytes ?? 2_500_000;

  let currentUrl = initialUrl;

  for (let hop = 0; hop <= maxRedirects; hop++) {
    const validation = validateWebsiteUrl(currentUrl);
    if (!validation.valid || !validation.normalizedUrl || !validation.hostname) {
      throw new FetchValidationError(
        validation.error || 'Invalid URL. Please enter a valid http:// or https:// website address.'
      );
    }

    const parsed = new URL(validation.normalizedUrl);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new FetchValidationError('Only HTTP and HTTPS URLs are supported.');
    }

    const pinned = await resolveAndPinPublicHost(parsed.hostname);

    const response = await executePinnedSingleRequest(parsed, pinned, {
      method: 'GET',
      timeoutMs,
      maxBytes,
      readBody: true,
      headers: {
        'User-Agent':
          'Mozilla/5.0 (compatible; VerifyBeforeBuy-MetadataBot/1.0; +https://verifybeforebuy.local)',
        Accept: 'text/html,application/xhtml+xml,application/ld+json,application/json;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        ...(options?.headers || {}),
      },
    });

    // Handle redirects explicitly so EVERY hop is URL-validated and DNS/IP-pinned
    if (response.statusCode >= 300 && response.statusCode < 400) {
      const rawLocation = response.headers.location;
      const location = Array.isArray(rawLocation) ? rawLocation[0] : rawLocation;
      if (!location) {
        throw new Error(`Website returned redirect HTTP ${response.statusCode} without a Location header.`);
      }
      if (hop === maxRedirects) {
        throw new Error(`Too many HTTP redirects (exceeded ${maxRedirects} hops).`);
      }

      let nextUrl: string;
      try {
        nextUrl = new URL(location, parsed.toString()).toString();
      } catch {
        throw new FetchValidationError('Redirect target contained a malformed URL.');
      }

      const redirectScheme = new URL(nextUrl).protocol;
      if (redirectScheme !== 'http:' && redirectScheme !== 'https:') {
        throw new SsrfBlockedError(
          `Security restriction: Blocked redirect to unsupported scheme "${redirectScheme}".`
        );
      }

      currentUrl = nextUrl;
      continue;
    }

    const rawCt = response.headers['content-type'];
    const contentType = (Array.isArray(rawCt) ? rawCt[0] : rawCt || '').toLowerCase();

    return {
      finalUrl: parsed.toString(),
      statusCode: response.statusCode,
      contentType,
      body: response.body,
    };
  }

  throw new Error('Unexpected redirect loop termination.');
}
