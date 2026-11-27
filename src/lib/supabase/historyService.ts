/**
 * Scan History Persistence Service
 * Dual-mode, strictly user-isolated persistence:
 * 1. Authenticated users: Supabase PostgreSQL (`public.scan_reports` + `public.scan_findings`)
 *    scoped by `auth.uid()` (`user_id`), with per-user `localStorage` fallback
 *    (`vbb_scan_history_v1:user:<userId>`) when Supabase is temporarily unreachable.
 * 2. Guest users (unauthenticated): Browser `localStorage` ONLY (`vbb_scan_history_v1:guest`) —
 *    guest scans are NEVER uploaded to Supabase and never leak into signed-in accounts.
 */

import { SupabaseClient } from '@supabase/supabase-js';
import { AssessmentResult, SavedScanRecord } from '../../types';
import { checkSupabaseConnection, supabase, supabaseConfigStatus } from './client';
import { RiskScoringEngine } from '../riskEngine/engine';

const LEGACY_LOCAL_STORAGE_KEY = 'vbb_scan_history_v1';
const GUEST_STORAGE_KEY = 'vbb_scan_history_v1:guest';
const USER_STORAGE_KEY_PREFIX = 'vbb_scan_history_v1:user:';
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export interface HistoryStorageAdapter {
  getItem: (key: string) => string | null;
  setItem: (key: string, value: string) => void;
  removeItem: (key: string) => void;
}

export interface HistoryServiceDependencies {
  client?: SupabaseClient | null;
  storage?: HistoryStorageAdapter | null;
  userId?: string | null;
}

export function getScopedHistoryStorageKey(userId?: string | null): string {
  const cleanUserId = (userId || '').trim();
  return cleanUserId ? `${USER_STORAGE_KEY_PREFIX}${cleanUserId}` : GUEST_STORAGE_KEY;
}

function getDefaultStorage(): HistoryStorageAdapter | null {
  try {
    if (typeof localStorage !== 'undefined') {
      return localStorage;
    }
  } catch {
    // ignore in Node / restricted contexts
  }
  return null;
}

function buildInitialDemoRecords(): SavedScanRecord[] {
  const webResult = RiskScoringEngine.assessWebsite({
    url: 'https://apple-security-verify-login.click/update-billing',
  });
  webResult.isDemoMode = true;

  const prodResult = RiskScoringEngine.assessProduct({
    productName: 'Sony WH-1000XM4 Noise Canceling Headphones (Refurbished Clearance)',
    brand: 'Sony',
    listedPrice: 39.99,
    referencePrice: 349.99,
    sellerName: 'DirectAudioLiquidation',
    sellerRating: 4.8,
    hasReturnPolicy: true,
    productDescription:
      'Factory recertified seasonal inventory liquidation. Includes 30-day warranty and original accessories.',
    productIdentifier: '027242919419',
  });
  prodResult.isDemoMode = true;

  const codeResult = RiskScoringEngine.assessCode({
    code: '012000000133',
  });
  codeResult.isDemoMode = true;

  return [
    {
      id: 'demo-rec-1',
      clientScanId: 'demo-rec-1',
      userId: null,
      createdAt: new Date(Date.now() - 3600000 * 2).toISOString(),
      type: 'website',
      target: 'https://apple-security-verify-login.click/update-billing',
      score: webResult.score,
      category: webResult.category,
      confidence: webResult.confidence,
      isDemo: true,
      storageSource: 'local',
      result: webResult,
    },
    {
      id: 'demo-rec-2',
      clientScanId: 'demo-rec-2',
      userId: null,
      createdAt: new Date(Date.now() - 3600000 * 24).toISOString(),
      type: 'product',
      target: 'Sony WH-1000XM4 Noise Canceling Headphones (Refurbished Clearance)',
      score: prodResult.score,
      category: prodResult.category,
      confidence: prodResult.confidence,
      isDemo: true,
      storageSource: 'local',
      result: prodResult,
    },
    {
      id: 'demo-rec-3',
      clientScanId: 'demo-rec-3',
      userId: null,
      createdAt: new Date(Date.now() - 3600000 * 48).toISOString(),
      type: 'code',
      target: '012000000133 (Synthetic Demo Specimen)',
      score: codeResult.score,
      category: codeResult.category,
      confidence: codeResult.confidence,
      isDemo: true,
      storageSource: 'local',
      result: codeResult,
    },
  ];
}

function mapRowToSavedRecord(row: any): SavedScanRecord {
  const rawResult: AssessmentResult = row.raw_result || {
    id: row.client_scan_id || row.id,
    timestamp: row.scanned_at || row.created_at,
    type: row.scan_type,
    inputSummary: {
      target: row.target_summary,
      subtarget: row.subtarget || undefined,
    },
    score: row.risk_score,
    category: row.risk_category,
    confidence: row.confidence_coverage,
    confidenceScore: row.confidence_score ?? 0,
    summary: row.summary_text || '',
    indicators: Array.isArray(row.indicators) ? row.indicators : [],
    positiveSignals: Array.isArray(row.positive_signals) ? row.positive_signals : [],
    recommendations: Array.isArray(row.recommendations) ? row.recommendations : [],
    unverifiedAspects: Array.isArray(row.unverified_aspects) ? row.unverified_aspects : [],
    aiExplanation: row.ai_explanation || undefined,
    aiExplanationProvider: row.ai_explanation_provider || undefined,
    aiExplanationModel: row.ai_explanation_model || undefined,
    mlPhishingPrediction: row.ml_phishing_prediction || undefined,
    mlProductPrediction: row.ml_product_prediction || undefined,
    domainVerification: row.domain_verification || undefined,
    barcodeLookup: row.barcode_lookup || undefined,
    sellerVerification: row.seller_verification || undefined,
    marketPriceComparison: row.market_price_comparison || undefined,
    disclaimer: 'Preliminary risk assessment based on available indicators.',
    isDemoMode: Boolean(row.is_demo),
  };

  // Ensure structured DB columns stay hydrated on rawResult
  const hydratedResult: AssessmentResult = {
    ...rawResult,
    aiExplanation: row.ai_explanation ?? rawResult.aiExplanation,
    aiExplanationProvider: row.ai_explanation_provider ?? rawResult.aiExplanationProvider,
    aiExplanationModel: row.ai_explanation_model ?? rawResult.aiExplanationModel,
    isDemoMode: typeof row.is_demo === 'boolean' ? row.is_demo : Boolean(rawResult.isDemoMode),
  };

  return {
    id: row.id,
    clientScanId: row.client_scan_id || hydratedResult.id,
    userId: row.user_id ?? null,
    createdAt: row.scanned_at || row.created_at,
    updatedAt: row.updated_at || undefined,
    type: row.scan_type,
    target: row.target_summary,
    score: row.risk_score,
    category: row.risk_category,
    confidence: row.confidence_coverage,
    isDemo: Boolean(row.is_demo || hydratedResult.isDemoMode),
    result: hydratedResult,
    storageSource: 'supabase',
  };
}

async function resolveAuthScopeUserId(
  client: SupabaseClient | null,
  deps: HistoryServiceDependencies
): Promise<string | null> {
  if (deps.userId !== undefined) {
    const clean = (deps.userId || '').trim();
    return clean || null;
  }
  if (!client) return null;
  try {
    const { data } = await client.auth.getSession();
    return data?.session?.user?.id ?? null;
  } catch {
    return null;
  }
}

export class HistoryService {
  /**
   * Fetch scan records for the active scope:
   * - Authenticated user: Supabase `scan_reports` filtered to `user_id`, falling back to
   *   `vbb_scan_history_v1:user:<userId>` if Supabase is unreachable.
   * - Guest (unauthenticated): strictly `vbb_scan_history_v1:guest` (never queries Supabase).
   */
  public static async getHistory(deps: HistoryServiceDependencies = {}): Promise<SavedScanRecord[]> {
    const client = deps.client !== undefined ? deps.client : supabase;
    const storage = deps.storage !== undefined ? deps.storage : getDefaultStorage();
    const authUserId = await resolveAuthScopeUserId(client, deps);

    // Guest scans stay exclusively in local browser storage
    if (!authUserId) {
      return this.getLocalRecords(storage, null);
    }

    if (client) {
      const status =
        deps.client !== undefined
          ? await checkSupabaseConnection(true, client, {
              ...supabaseConfigStatus,
              isConfigured: true,
            })
          : await checkSupabaseConnection();

      if (status.connectionState === 'connected') {
        try {
          const { data, error } = await client
            .from('scan_reports')
            .select('*')
            .eq('user_id', authUserId)
            .order('created_at', { ascending: false })
            .limit(100);

          if (!error && Array.isArray(data)) {
            return data.map(mapRowToSavedRecord);
          }
          if (error) {
            supabaseConfigStatus.connectionState = 'error';
            supabaseConfigStatus.errorMessage = error.message;
          }
        } catch (err: any) {
          supabaseConfigStatus.connectionState = 'error';
          supabaseConfigStatus.errorMessage = err?.message || 'Supabase query failed';
          console.warn('Supabase query failed, falling back to user-scoped local storage:', err);
        }
      }
    }

    return this.getLocalRecords(storage, authUserId);
  }

  /**
   * Save or update a completed assessment (Website, Product, or Barcode/QR).
   * - Authenticated users: upserts to Supabase (`onConflict: 'user_id,client_scan_id'`)
   *   and syncs owner-matched `scan_findings`, or falls back to `vbb_scan_history_v1:user:<userId>`.
   * - Guest users: saves exclusively to `vbb_scan_history_v1:guest` without calling Supabase.
   */
  public static async saveRecord(
    result: AssessmentResult,
    deps: HistoryServiceDependencies = {}
  ): Promise<SavedScanRecord> {
    const client = deps.client !== undefined ? deps.client : supabase;
    const storage = deps.storage !== undefined ? deps.storage : getDefaultStorage();
    const authUserId = await resolveAuthScopeUserId(client, deps);
    const targetSummary = result.inputSummary.target || 'Unknown Target';
    const isDemo = Boolean(result.isDemoMode);
    const clientScanId = result.id;

    let savedInSupabase: SavedScanRecord | null = null;

    if (client && authUserId) {
      const status =
        deps.client !== undefined
          ? await checkSupabaseConnection(true, client, {
              ...supabaseConfigStatus,
              isConfigured: true,
            })
          : await checkSupabaseConnection();

      if (status.connectionState === 'connected') {
        try {
          const reportRow = {
            client_scan_id: clientScanId,
            user_id: authUserId,
            scan_type: result.type,
            target_summary: targetSummary,
            subtarget: result.inputSummary.subtarget || null,
            risk_score: Math.round(result.score),
            risk_category: result.category,
            confidence_coverage: result.confidence,
            confidence_score: Math.round(result.confidenceScore),
            summary_text: result.summary || '',
            ai_explanation: result.aiExplanation || null,
            ai_explanation_provider: result.aiExplanationProvider || null,
            ai_explanation_model: result.aiExplanationModel || null,
            indicators: result.indicators || [],
            positive_signals: result.positiveSignals || [],
            recommendations: result.recommendations || [],
            unverified_aspects: result.unverifiedAspects || [],
            ml_phishing_prediction: result.mlPhishingPrediction || null,
            ml_product_prediction: result.mlProductPrediction || null,
            domain_verification: result.domainVerification || null,
            barcode_lookup: result.barcodeLookup || null,
            seller_verification: result.sellerVerification || null,
            market_price_comparison: result.marketPriceComparison || null,
            raw_result: result,
            is_demo: isDemo,
            scanned_at: result.timestamp || new Date().toISOString(),
          };

          const { data, error } = await client
            .from('scan_reports')
            .upsert(reportRow, { onConflict: 'user_id,client_scan_id' })
            .select()
            .single();

          if (!error && data) {
            // Sync normalized indicator rows in scan_findings with matching owner user_id
            try {
              await client
                .from('scan_findings')
                .delete()
                .eq('report_id', data.id)
                .eq('user_id', authUserId);

              if (Array.isArray(result.indicators) && result.indicators.length > 0) {
                const findingRows = result.indicators.map((ind) => ({
                  report_id: data.id,
                  user_id: authUserId,
                  indicator_id: ind.id,
                  name: ind.name,
                  category: ind.category,
                  severity: ind.severity,
                  score_impact: Math.round(ind.scoreImpact),
                  is_observed: Boolean(ind.isObserved),
                  description: ind.description,
                  remedy_or_precaution: ind.remedyOrPrecaution || null,
                }));
                await client.from('scan_findings').insert(findingRows);
              }
            } catch (findingsErr) {
              console.warn('Could not sync scan_findings rows:', findingsErr);
            }

            savedInSupabase = mapRowToSavedRecord(data);
          } else if (error) {
            supabaseConfigStatus.connectionState = 'error';
            supabaseConfigStatus.errorMessage = error.message;
            console.warn('Supabase upsert failed, storing in user-scoped local fallback:', error.message);
          }
        } catch (err: any) {
          supabaseConfigStatus.connectionState = 'error';
          supabaseConfigStatus.errorMessage = err?.message || 'Supabase insert failed';
          console.warn('Supabase save exception, storing in user-scoped local fallback:', err);
        }
      }
    }

    const localRecord: SavedScanRecord = savedInSupabase ?? {
      id: clientScanId,
      clientScanId,
      userId: authUserId,
      createdAt: result.timestamp || new Date().toISOString(),
      type: result.type,
      target: targetSummary,
      score: result.score,
      category: result.category,
      confidence: result.confidence,
      isDemo,
      result,
      storageSource: 'local',
    };

    if (!savedInSupabase) {
      const storageKey = getScopedHistoryStorageKey(authUserId);
      const current = this.getLocalRecords(storage, authUserId);
      const updated = [
        localRecord,
        ...current.filter((r) => r.id !== localRecord.id && r.clientScanId !== clientScanId),
      ].slice(0, 50);
      if (storage) {
        try {
          storage.setItem(storageKey, JSON.stringify(updated));
        } catch {
          // ignore quota errors
        }
      }
    }

    return localRecord;
  }

  /**
   * Delete a scan record by Supabase UUID or clientScanId within the current user/guest scope.
   */
  public static async deleteRecord(
    id: string,
    deps: HistoryServiceDependencies = {}
  ): Promise<boolean> {
    const client = deps.client !== undefined ? deps.client : supabase;
    const storage = deps.storage !== undefined ? deps.storage : getDefaultStorage();
    const authUserId = await resolveAuthScopeUserId(client, deps);

    if (client && authUserId) {
      try {
        if (UUID_REGEX.test(id)) {
          await client.from('scan_reports').delete().eq('id', id).eq('user_id', authUserId);
        } else {
          await client.from('scan_reports').delete().eq('client_scan_id', id).eq('user_id', authUserId);
        }
      } catch (err) {
        console.warn('Supabase delete failed:', err);
      }
    }

    const storageKey = getScopedHistoryStorageKey(authUserId);
    const current = this.getLocalRecords(storage, authUserId);
    const updated = current.filter((r) => r.id !== id && r.clientScanId !== id);
    if (storage) {
      try {
        storage.setItem(storageKey, JSON.stringify(updated));
      } catch {
        // ignore
      }
    }
    return true;
  }

  /**
   * Clear scan history exclusively for the active user or guest scope.
   * Never clears another account's or guest's localStorage key.
   */
  public static async clearHistory(deps: HistoryServiceDependencies = {}): Promise<boolean> {
    const client = deps.client !== undefined ? deps.client : supabase;
    const storage = deps.storage !== undefined ? deps.storage : getDefaultStorage();
    const authUserId = await resolveAuthScopeUserId(client, deps);

    if (client && authUserId) {
      try {
        await client.from('scan_reports').delete().eq('user_id', authUserId);
      } catch (err) {
        console.warn('Supabase clearHistory failed:', err);
      }
    }

    const storageKey = getScopedHistoryStorageKey(authUserId);
    if (storage) {
      try {
        storage.setItem(storageKey, JSON.stringify([]));
      } catch {
        // ignore
      }
    }
    return true;
  }

  private static getLocalRecords(
    storage: HistoryStorageAdapter | null,
    authUserId: string | null
  ): SavedScanRecord[] {
    if (!storage) {
      return [];
    }
    const storageKey = getScopedHistoryStorageKey(authUserId);

    try {
      let stored = storage.getItem(storageKey);

      // Migrate legacy pre-auth localStorage ONLY into Guest scope (never into an authenticated user's account)
      if (stored === null && !authUserId) {
        const legacyStored = storage.getItem(LEGACY_LOCAL_STORAGE_KEY);
        if (legacyStored !== null) {
          storage.setItem(GUEST_STORAGE_KEY, legacyStored);
          storage.removeItem(LEGACY_LOCAL_STORAGE_KEY);
          stored = legacyStored;
        } else {
          const seeded = buildInitialDemoRecords();
          storage.setItem(GUEST_STORAGE_KEY, JSON.stringify(seeded));
          return seeded;
        }
      }

      if (stored === null) {
        return [];
      }

      const parsed = JSON.parse(stored);
      if (!Array.isArray(parsed)) return [];
      return parsed
        .filter((rec: any) => {
          // Extra isolation safeguard: never surface another user's records
          if (authUserId) {
            return !rec?.userId || rec.userId === authUserId;
          }
          return !rec?.userId;
        })
        .map((rec: any) => ({
          ...rec,
          userId: authUserId,
          isDemo: Boolean(rec?.isDemo || rec?.result?.isDemoMode),
          storageSource: rec?.storageSource === 'supabase' ? 'supabase' : 'local',
        }));
    } catch {
      return [];
    }
  }
}
