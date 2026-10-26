/**
 * Scan History Persistence Service
 * Supports dual-mode persistence:
 * 1. Supabase PostgreSQL when credentials exist.
 * 2. Secure LocalStorage when in demo/local development mode.
 */

import { AssessmentResult, SavedScanRecord } from '../../types';
import { supabase, supabaseConfigStatus } from './client';
import { RiskScoringEngine } from '../riskEngine/engine';

const LOCAL_STORAGE_KEY = 'vbb_scan_history_v1';

// Sample demonstration records to populate initial view if empty
const INITIAL_DEMO_RECORDS: SavedScanRecord[] = [
  {
    id: 'demo-rec-1',
    createdAt: new Date(Date.now() - 3600000 * 2).toISOString(),
    type: 'website',
    target: 'https://apple-security-verify-login.click/update-billing',
    score: 75,
    category: 'elevated',
    confidence: 'high',
    storageSource: 'local',
    result: RiskScoringEngine.assessWebsite({
      url: 'https://apple-security-verify-login.click/update-billing',
    }),
  },
  {
    id: 'demo-rec-2',
    createdAt: new Date(Date.now() - 3600000 * 24).toISOString(),
    type: 'product',
    target: 'Sony WH-1000XM4 Noise Canceling Headphones (Refurbished Clearance)',
    score: 2,
    category: 'lower',
    confidence: 'comprehensive',
    storageSource: 'local',
    result: RiskScoringEngine.assessProduct({
      productName: 'Sony WH-1000XM4 Noise Canceling Headphones (Refurbished Clearance)',
      brand: 'Sony',
      listedPrice: 39.99,
      referencePrice: 349.99,
      sellerName: 'DirectAudioLiquidation',
      sellerRating: 4.8,
      hasReturnPolicy: true,
      productDescription: 'Factory recertified seasonal inventory liquidation. Includes 30-day warranty and original accessories.',
      productIdentifier: '027242919419',
    }),
  },
  {
    id: 'demo-rec-3',
    createdAt: new Date(Date.now() - 3600000 * 48).toISOString(),
    type: 'code',
    target: '012000000133 (Pepsi Cola 12 Fl Oz Specimen)',
    score: 0,
    category: 'lower',
    confidence: 'high',
    storageSource: 'local',
    result: RiskScoringEngine.assessCode({
      code: '012000000133',
    }),
  },
];

export class HistoryService {
  /**
   * Fetch all scan records
   */
  public static async getHistory(): Promise<SavedScanRecord[]> {
    if (supabaseConfigStatus.isConfigured && supabase) {
      try {
        const { data, error } = await supabase
          .from('scan_reports')
          .select('*')
          .order('created_at', { ascending: false });

        if (!error && data && data.length > 0) {
          return data.map((row: any) => ({
            id: row.id,
            userId: row.user_id,
            createdAt: row.created_at,
            type: row.scan_type,
            target: row.target_summary,
            score: row.risk_score,
            category: row.risk_category,
            confidence: row.confidence_coverage,
            result: row.raw_result,
            storageSource: 'supabase',
          }));
        }
      } catch (err) {
        console.warn('Supabase query failed, falling back to local storage:', err);
      }
    }

    // Local storage fallback
    return this.getLocalRecords();
  }

  /**
   * Save a completed assessment
   */
  public static async saveRecord(result: AssessmentResult): Promise<SavedScanRecord> {
    const targetSummary = result.inputSummary.target || 'Unknown Target';

    if (supabaseConfigStatus.isConfigured && supabase) {
      try {
        const { data, error } = await supabase
          .from('scan_reports')
          .insert({
            scan_type: result.type,
            target_summary: targetSummary,
            subtarget: result.inputSummary.subtarget || null,
            risk_score: result.score,
            risk_category: result.category,
            confidence_coverage: result.confidence,
            confidence_score: result.confidenceScore,
            summary_text: result.summary,
            ai_explanation: result.aiExplanation || null,
            raw_result: result,
            is_demo: Boolean(result.isDemoMode),
          })
          .select()
          .single();

        if (!error && data) {
          return {
            id: data.id,
            userId: data.user_id,
            createdAt: data.created_at,
            type: data.scan_type,
            target: data.target_summary,
            score: data.risk_score,
            category: data.risk_category,
            confidence: data.confidence_coverage,
            result,
            storageSource: 'supabase',
          };
        }
      } catch (err) {
        console.warn('Supabase insert failed, storing locally:', err);
      }
    }

    // Save to local storage
    const newRecord: SavedScanRecord = {
      id: result.id,
      createdAt: result.timestamp,
      type: result.type,
      target: targetSummary,
      score: result.score,
      category: result.category,
      confidence: result.confidence,
      result,
      storageSource: 'local',
    };

    const current = this.getLocalRecords();
    const updated = [newRecord, ...current.filter(r => r.id !== newRecord.id)].slice(0, 50);
    try {
      localStorage.setItem(LOCAL_STORAGE_KEY, JSON.stringify(updated));
    } catch {
      // ignore quota errors
    }

    return newRecord;
  }

  /**
   * Delete a scan record
   */
  public static async deleteRecord(id: string): Promise<boolean> {
    if (supabaseConfigStatus.isConfigured && supabase) {
      try {
        await supabase.from('scan_reports').delete().eq('id', id);
      } catch (err) {
        console.warn('Supabase delete failed:', err);
      }
    }

    const current = this.getLocalRecords();
    const updated = current.filter(r => r.id !== id);
    try {
      localStorage.setItem(LOCAL_STORAGE_KEY, JSON.stringify(updated));
    } catch {
      // ignore
    }
    return true;
  }

  /**
   * Reset / clear history
   */
  public static async clearHistory(): Promise<boolean> {
    try {
      localStorage.removeItem(LOCAL_STORAGE_KEY);
    } catch {
      // ignore
    }
    return true;
  }

  private static getLocalRecords(): SavedScanRecord[] {
    try {
      const stored = localStorage.getItem(LOCAL_STORAGE_KEY);
      if (!stored) {
        // Seed initial demo records so first-time users can immediately interact with the dashboard
        localStorage.setItem(LOCAL_STORAGE_KEY, JSON.stringify(INITIAL_DEMO_RECORDS));
        return INITIAL_DEMO_RECORDS;
      }
      return JSON.parse(stored);
    } catch {
      return INITIAL_DEMO_RECORDS;
    }
  }
}
