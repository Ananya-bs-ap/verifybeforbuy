/**
 * Supabase Client & Configuration Status
 * Configured with user's Supabase project:
 * Project ID: muwesnqibkfbjzxqdhfj
 * Publishable API Key: sb_publishable_NU6uokghkmB7cYXNRkAXVg_UAEq0cK9
 */

import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { SupabaseConfigStatus } from '../../types';

export const SUPABASE_PROJECT_ID = 'muwesnqibkfbjzxqdhfj';
const DEFAULT_SUPABASE_URL = `https://${SUPABASE_PROJECT_ID}.supabase.co`;
const DEFAULT_ANON_KEY = 'sb_publishable_NU6uokghkmB7cYXNRkAXVg_UAEq0cK9';

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL || DEFAULT_SUPABASE_URL;
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY || DEFAULT_ANON_KEY;

const isConfigured = Boolean(
  supabaseUrl &&
  supabaseUrl.startsWith('https://') &&
  supabaseAnonKey &&
  supabaseAnonKey.length > 10
);

export const supabaseConfigStatus: SupabaseConfigStatus = {
  isConfigured,
  urlConfigured: Boolean(supabaseUrl),
  anonKeyConfigured: Boolean(supabaseAnonKey),
  connectionState: isConfigured ? 'connected' : 'unconfigured',
  projectId: SUPABASE_PROJECT_ID,
};

export const supabase: SupabaseClient | null = isConfigured
  ? createClient(supabaseUrl, supabaseAnonKey, {
      auth: {
        persistSession: true,
        autoRefreshToken: true,
      },
    })
  : null;
