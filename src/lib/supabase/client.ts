/**
 * Supabase Client & Live Connection Verification
 * Reads VITE_SUPABASE_URL and VITE_SUPABASE_PUBLISHABLE_KEY (with fallback support
 * for legacy VITE_SUPABASE_ANON_KEY) strictly from environment variables — never embeds
 * privileged service_role credentials and never reports "connected" until an actual
 * database check succeeds.
 */

import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { SupabaseConfigStatus } from '../../types';

function readViteEnv(): Record<string, string | undefined> {
  const result: Record<string, string | undefined> = {};
  try {
    if (typeof import.meta !== 'undefined' && import.meta.env) {
      Object.assign(result, import.meta.env);
      // Direct static reads ensure Vite production builds inline all supported keys
      if (import.meta.env.VITE_SUPABASE_URL) {
        result.VITE_SUPABASE_URL = import.meta.env.VITE_SUPABASE_URL;
      }
      if (import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY) {
        result.VITE_SUPABASE_PUBLISHABLE_KEY = import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY;
      }
      if (import.meta.env.VITE_SUPABASE_ANON_KEY) {
        result.VITE_SUPABASE_ANON_KEY = import.meta.env.VITE_SUPABASE_ANON_KEY;
      }
    }
  } catch {
    // ignore in non-Vite Node runners
  }
  return result;
}

export function isValidSupabaseUrl(rawUrl?: string): boolean {
  if (!rawUrl) return false;
  const trimmed = rawUrl.trim();
  if (!trimmed) return false;
  try {
    const parsed = new URL(trimmed);
    const isHttps = parsed.protocol === 'https:';
    const isLocalHttp =
      parsed.protocol === 'http:' &&
      (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1');
    return (isHttps || isLocalHttp) && Boolean(parsed.hostname);
  } catch {
    return false;
  }
}

export function extractSupabaseProjectId(rawUrl?: string): string | undefined {
  if (!rawUrl) return undefined;
  try {
    const parsed = new URL(rawUrl.trim());
    if (parsed.hostname.endsWith('.supabase.co')) {
      return parsed.hostname.split('.')[0];
    }
    return parsed.hostname;
  } catch {
    return undefined;
  }
}

/**
 * Guard against accidentally placing a privileged service_role / sb_secret key in browser VITE_ vars.
 */
export function isPrivilegedSupabaseKey(key: string): boolean {
  const trimmed = key.trim();
  if (!trimmed) return false;
  if (trimmed.startsWith('sb_secret_')) return true;

  // Check JWT payload role claim if key is a 3-part JWT
  const parts = trimmed.split('.');
  if (parts.length === 3) {
    try {
      const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
      const jsonStr =
        typeof atob === 'function'
          ? atob(b64)
          : Buffer.from(b64, 'base64').toString('utf8');
      const payload = JSON.parse(jsonStr);
      if (payload?.role === 'service_role') {
        return true;
      }
    } catch {
      // ignore non-JWT keys (e.g. sb_publishable_...)
    }
  }
  return false;
}

function looksLikePublicSupabaseKey(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length <= 10) return false;
  if (trimmed.includes('://')) return false;
  if (
    trimmed.includes('your-anon-key') ||
    trimmed.includes('your-publishable-key') ||
    trimmed.includes('your-supabase-url')
  ) {
    return false;
  }
  if (isPrivilegedSupabaseKey(trimmed)) return false;
  if (trimmed.startsWith('sb_publishable_')) return true;
  if (trimmed.split('.').length === 3) return true;
  return trimmed.length >= 20 && !/\s/.test(trimmed);
}

export interface SupabaseEnvResolution {
  url: string;
  anonKey: string;
  keySource?: 'VITE_SUPABASE_PUBLISHABLE_KEY' | 'VITE_SUPABASE_ANON_KEY' | 'VITE_SUPABASE_URL';
  urlConfigured: boolean;
  anonKeyConfigured: boolean;
  isConfigured: boolean;
  swappedEnvDetected?: boolean;
  projectId?: string;
  errorMessage?: string;
}

export function resolveSupabaseEnv(envOverride?: Record<string, string | undefined>): SupabaseEnvResolution {
  const env = envOverride ?? readViteEnv();
  const rawUrl = (env.VITE_SUPABASE_URL || '').trim();
  const publishableKey = (env.VITE_SUPABASE_PUBLISHABLE_KEY || '').trim();
  const legacyAnonKey = (env.VITE_SUPABASE_ANON_KEY || '').trim();

  // Security check across ALL configured Supabase variables first
  const privilegedBlocked = [rawUrl, publishableKey, legacyAnonKey].some(
    (candidate) => candidate.length > 10 && isPrivilegedSupabaseKey(candidate)
  );

  if (privilegedBlocked) {
    return {
      url: '',
      anonKey: '',
      keySource: undefined,
      urlConfigured: isValidSupabaseUrl(rawUrl),
      anonKeyConfigured: false,
      isConfigured: false,
      errorMessage:
        'Security block: Do not use a Supabase service_role or sb_secret key in browser variables. Use VITE_SUPABASE_PUBLISHABLE_KEY (or the public anon key) only.',
    };
  }

  let resolvedUrl = rawUrl;
  let resolvedKey = '';
  let keySource: SupabaseEnvResolution['keySource'];
  let swappedEnvDetected = false;

  if (isValidSupabaseUrl(rawUrl)) {
    if (looksLikePublicSupabaseKey(publishableKey)) {
      resolvedKey = publishableKey;
      keySource = 'VITE_SUPABASE_PUBLISHABLE_KEY';
    } else if (looksLikePublicSupabaseKey(legacyAnonKey)) {
      resolvedKey = legacyAnonKey;
      keySource = 'VITE_SUPABASE_ANON_KEY';
    }
  } else if (looksLikePublicSupabaseKey(rawUrl)) {
    // Recover cleanly if Secrets were entered swapped (e.g. URL placed in ANON/PUBLISHABLE slot and key in URL slot)
    const swappedUrlCandidate = isValidSupabaseUrl(publishableKey)
      ? publishableKey
      : isValidSupabaseUrl(legacyAnonKey)
        ? legacyAnonKey
        : '';
    if (swappedUrlCandidate) {
      resolvedUrl = swappedUrlCandidate;
      swappedEnvDetected = true;
      if (!isValidSupabaseUrl(publishableKey) && looksLikePublicSupabaseKey(publishableKey)) {
        resolvedKey = publishableKey;
        keySource = 'VITE_SUPABASE_PUBLISHABLE_KEY';
      } else {
        resolvedKey = rawUrl;
        keySource = 'VITE_SUPABASE_URL';
      }
    }
  } else {
    resolvedKey = publishableKey || legacyAnonKey;
    keySource = publishableKey
      ? 'VITE_SUPABASE_PUBLISHABLE_KEY'
      : legacyAnonKey
        ? 'VITE_SUPABASE_ANON_KEY'
        : undefined;
  }

  const urlConfigured = isValidSupabaseUrl(resolvedUrl);
  const anonKeyConfigured = looksLikePublicSupabaseKey(resolvedKey);

  let errorMessage: string | undefined;
  if (rawUrl && !urlConfigured) {
    errorMessage = 'VITE_SUPABASE_URL is not a valid https:// Supabase URL.';
  } else if ((resolvedUrl && !anonKeyConfigured) || (!resolvedUrl && anonKeyConfigured)) {
    errorMessage =
      'Both VITE_SUPABASE_URL and VITE_SUPABASE_PUBLISHABLE_KEY (or VITE_SUPABASE_ANON_KEY) must be configured together.';
  }

  const isConfigured = urlConfigured && anonKeyConfigured;
  return {
    url: isConfigured ? resolvedUrl : '',
    anonKey: isConfigured ? resolvedKey : '',
    keySource: isConfigured ? keySource : undefined,
    urlConfigured,
    anonKeyConfigured,
    isConfigured,
    swappedEnvDetected: isConfigured && swappedEnvDetected ? true : undefined,
    projectId: isConfigured ? extractSupabaseProjectId(resolvedUrl) : undefined,
    errorMessage,
  };
}

const resolvedEnv = resolveSupabaseEnv();

export const supabaseConfigStatus: SupabaseConfigStatus = {
  isConfigured: resolvedEnv.isConfigured,
  urlConfigured: resolvedEnv.urlConfigured,
  anonKeyConfigured: resolvedEnv.anonKeyConfigured,
  connectionState: resolvedEnv.errorMessage
    ? 'error'
    : resolvedEnv.isConfigured
      ? 'checking'
      : 'unconfigured',
  schemaReady: false,
  errorMessage: resolvedEnv.errorMessage,
  projectId: resolvedEnv.projectId,
};

export const supabase: SupabaseClient | null = resolvedEnv.isConfigured
  ? createClient(resolvedEnv.url, resolvedEnv.anonKey, {
      auth: {
        persistSession: true,
        autoRefreshToken: true,
      },
    })
  : null;

function formatSupabaseConnectionError(err: any): string {
  const msg = String(err?.message || err?.error_description || 'Database connection failed');
  const code = String(err?.code || '');

  if (
    code === '42P01' ||
    code === 'PGRST205' ||
    msg.includes('Could not find the table') ||
    msg.includes('does not exist')
  ) {
    return 'Connected to project, but required tables (profiles, scan_reports, scan_findings) are missing. Run src/lib/supabase/schema.sql in Supabase SQL Editor.';
  }
  if (code === '42501' || msg.toLowerCase().includes('row-level security') || msg.toLowerCase().includes('permission denied')) {
    return 'RLS policy denied access. Re-run the updated src/lib/supabase/schema.sql migration.';
  }
  if (msg.includes('Invalid API key') || msg.includes('JWT') || err?.status === 401) {
    return 'Invalid VITE_SUPABASE_PUBLISHABLE_KEY / VITE_SUPABASE_ANON_KEY or unauthorized project key.';
  }
  if (msg.includes('Failed to fetch') || msg.includes('fetch failed') || msg.includes('ENOTFOUND')) {
    return 'Supabase host unreachable (check VITE_SUPABASE_URL and network access).';
  }
  return msg;
}

let inFlightCheck: Promise<SupabaseConfigStatus> | null = null;
const CONNECTION_CACHE_MS = 15_000;
let lastVerifiedAtMs = 0;

/**
 * Performs an actual live read check against Supabase (`profiles`, `scan_reports`, and `scan_findings`)
 * and updates `supabaseConfigStatus`. Never fabricates `'connected'`.
 */
export async function checkSupabaseConnection(
  force = false,
  clientOverride?: SupabaseClient | null,
  statusTarget: SupabaseConfigStatus = supabaseConfigStatus
): Promise<SupabaseConfigStatus> {
  const client = clientOverride !== undefined ? clientOverride : supabase;

  if (!client) {
    statusTarget.connectionState = statusTarget.errorMessage ? 'error' : 'unconfigured';
    statusTarget.schemaReady = false;
    statusTarget.lastCheckedAt = new Date().toISOString();
    return { ...statusTarget };
  }

  if (
    !force &&
    clientOverride === undefined &&
    lastVerifiedAtMs > 0 &&
    Date.now() - lastVerifiedAtMs < CONNECTION_CACHE_MS &&
    (statusTarget.connectionState === 'connected' || statusTarget.connectionState === 'error')
  ) {
    return { ...statusTarget };
  }

  if (!force && clientOverride === undefined && inFlightCheck) {
    return inFlightCheck;
  }

  const runCheck = async (): Promise<SupabaseConfigStatus> => {
    statusTarget.connectionState = 'checking';
    try {
      const requiredTables = ['profiles', 'scan_reports', 'scan_findings'] as const;
      for (const tableName of requiredTables) {
        const { error: tableError, status: tableStatus } = await client
          .from(tableName)
          .select('id', { head: true, count: 'exact' })
          .limit(1);

        if (tableError) {
          statusTarget.connectionState = 'error';
          statusTarget.schemaReady = false;
          statusTarget.errorMessage = formatSupabaseConnectionError({
            ...tableError,
            status: tableStatus,
          });
          statusTarget.lastCheckedAt = new Date().toISOString();
          lastVerifiedAtMs = Date.now();
          return { ...statusTarget };
        }
      }

      let authUserId: string | null = null;
      let authEmail: string | null = null;
      try {
        const { data: sessionData } = await client.auth.getSession();
        authUserId = sessionData?.session?.user?.id ?? null;
        authEmail = sessionData?.session?.user?.email ?? null;
      } catch {
        authUserId = null;
        authEmail = null;
      }

      statusTarget.connectionState = 'connected';
      statusTarget.schemaReady = true;
      statusTarget.authUserId = authUserId;
      statusTarget.authEmail = authEmail;
      statusTarget.errorMessage = undefined;
      statusTarget.lastCheckedAt = new Date().toISOString();
      lastVerifiedAtMs = Date.now();
      return { ...statusTarget };
    } catch (err: any) {
      statusTarget.connectionState = 'error';
      statusTarget.schemaReady = false;
      statusTarget.errorMessage = formatSupabaseConnectionError(err);
      statusTarget.lastCheckedAt = new Date().toISOString();
      lastVerifiedAtMs = Date.now();
      return { ...statusTarget };
    } finally {
      if (clientOverride === undefined) {
        inFlightCheck = null;
      }
    }
  };

  if (clientOverride !== undefined) {
    return runCheck();
  }

  inFlightCheck = runCheck();
  return inFlightCheck;
}
