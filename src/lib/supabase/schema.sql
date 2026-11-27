-- ==============================================================================
-- VERIFYBEFOREBUY AI — COMPLETE SUPABASE POSTGRESQL MIGRATION SCRIPT
-- Execute in Supabase Dashboard -> SQL Editor (idempotent: safe to re-run)
--
-- Tables:
--   1. public.profiles      (Authenticated user profiles synced from auth.users)
--   2. public.scan_reports  (Website, Product, and Barcode/QR scan history)
--   3. public.scan_findings (Normalized risk indicators per scan report)
--
-- Security Model:
--   - Row Level Security (RLS) is enabled and enforced on all tables.
--   - Unauthenticated sessions (auth.uid() IS NULL) have ZERO access to tables.
--   - Guest scans stay exclusively in browser localStorage and are never uploaded.
--   - Authenticated users can SELECT, INSERT, UPDATE, and DELETE ONLY their own
--     profiles, scan_reports, and scan_findings (auth.uid() = user_id).
--   - scan_findings ownership is enforced both via RLS parent-report join AND
--     via trigger so a finding's user_id must always match its parent scan_report.
-- ==============================================================================

-- 1. Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 2. Shared updated_at trigger helper
CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

-- 3. Profiles Table (Linked to Supabase Authentication users)
CREATE TABLE IF NOT EXISTS public.profiles (
  id UUID REFERENCES auth.users(id) ON DELETE CASCADE PRIMARY KEY,
  email TEXT,
  display_name TEXT,
  avatar_url TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS avatar_url TEXT;
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

DROP TRIGGER IF EXISTS trg_profiles_updated_at ON public.profiles;
CREATE TRIGGER trg_profiles_updated_at
  BEFORE UPDATE ON public.profiles
  FOR EACH ROW
  EXECUTE FUNCTION public.set_updated_at();

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can view their own profile" ON public.profiles;
DROP POLICY IF EXISTS "Users can insert their own profile" ON public.profiles;
DROP POLICY IF EXISTS "Users can update their own profile" ON public.profiles;
DROP POLICY IF EXISTS "Users can delete their own profile" ON public.profiles;

CREATE POLICY "Users can view their own profile"
  ON public.profiles FOR SELECT
  USING (auth.uid() IS NOT NULL AND auth.uid() = id);

CREATE POLICY "Users can insert their own profile"
  ON public.profiles FOR INSERT
  WITH CHECK (auth.uid() IS NOT NULL AND auth.uid() = id);

CREATE POLICY "Users can update their own profile"
  ON public.profiles FOR UPDATE
  USING (auth.uid() IS NOT NULL AND auth.uid() = id)
  WITH CHECK (auth.uid() IS NOT NULL AND auth.uid() = id);

CREATE POLICY "Users can delete their own profile"
  ON public.profiles FOR DELETE
  USING (auth.uid() IS NOT NULL AND auth.uid() = id);

-- Auto-create profile row when a user registers via Supabase Auth
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO public.profiles (id, email, display_name)
  VALUES (
    NEW.id,
    NEW.email,
    COALESCE(
      NULLIF(TRIM(NEW.raw_user_meta_data->>'display_name'), ''),
      split_part(COALESCE(NEW.email, ''), '@', 1)
    )
  )
  ON CONFLICT (id) DO UPDATE
    SET email = EXCLUDED.email,
        display_name = COALESCE(NULLIF(TRIM(EXCLUDED.display_name), ''), public.profiles.display_name);
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW
  EXECUTE FUNCTION public.handle_new_user();

-- 4. Scan Reports Table (Website Checker, Product Checker, Barcode/QR Scanner)
CREATE TABLE IF NOT EXISTS public.scan_reports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  client_scan_id TEXT NOT NULL,
  user_id UUID NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  scan_type TEXT NOT NULL CHECK (scan_type IN ('website', 'product', 'code')),
  target_summary TEXT NOT NULL,
  subtarget TEXT,
  risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
  risk_category TEXT NOT NULL CHECK (risk_category IN ('lower', 'moderate', 'elevated', 'high')),
  confidence_coverage TEXT NOT NULL CHECK (confidence_coverage IN ('minimal', 'moderate', 'high', 'comprehensive')),
  confidence_score INTEGER NOT NULL CHECK (confidence_score >= 0 AND confidence_score <= 100),
  summary_text TEXT NOT NULL,
  ai_explanation TEXT,
  ai_explanation_provider TEXT CHECK (ai_explanation_provider IN ('gemini', 'deterministic-fallback')),
  ai_explanation_model TEXT,
  indicators JSONB NOT NULL DEFAULT '[]'::jsonb,
  positive_signals JSONB NOT NULL DEFAULT '[]'::jsonb,
  recommendations JSONB NOT NULL DEFAULT '[]'::jsonb,
  unverified_aspects JSONB NOT NULL DEFAULT '[]'::jsonb,
  ml_phishing_prediction JSONB,
  ml_product_prediction JSONB,
  domain_verification JSONB,
  barcode_lookup JSONB,
  seller_verification JSONB,
  market_price_comparison JSONB,
  raw_result JSONB NOT NULL,
  is_demo BOOLEAN NOT NULL DEFAULT FALSE,
  scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Upgrade existing installations idempotently
ALTER TABLE public.scan_reports ADD COLUMN IF NOT EXISTS client_scan_id TEXT;
ALTER TABLE public.scan_reports ADD COLUMN IF NOT EXISTS subtarget TEXT;
ALTER TABLE public.scan_reports ADD COLUMN IF NOT EXISTS confidence_score INTEGER NOT NULL DEFAULT 0;
ALTER TABLE public.scan_reports ADD COLUMN IF NOT EXISTS summary_text TEXT NOT NULL DEFAULT '';
ALTER TABLE public.scan_reports ADD COLUMN IF NOT EXISTS ai_explanation TEXT;
ALTER TABLE public.scan_reports ADD COLUMN IF NOT EXISTS ai_explanation_provider TEXT;
ALTER TABLE public.scan_reports ADD COLUMN IF NOT EXISTS ai_explanation_model TEXT;
ALTER TABLE public.scan_reports ADD COLUMN IF NOT EXISTS indicators JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE public.scan_reports ADD COLUMN IF NOT EXISTS positive_signals JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE public.scan_reports ADD COLUMN IF NOT EXISTS recommendations JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE public.scan_reports ADD COLUMN IF NOT EXISTS unverified_aspects JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE public.scan_reports ADD COLUMN IF NOT EXISTS ml_phishing_prediction JSONB;
ALTER TABLE public.scan_reports ADD COLUMN IF NOT EXISTS ml_product_prediction JSONB;
ALTER TABLE public.scan_reports ADD COLUMN IF NOT EXISTS domain_verification JSONB;
ALTER TABLE public.scan_reports ADD COLUMN IF NOT EXISTS barcode_lookup JSONB;
ALTER TABLE public.scan_reports ADD COLUMN IF NOT EXISTS seller_verification JSONB;
ALTER TABLE public.scan_reports ADD COLUMN IF NOT EXISTS market_price_comparison JSONB;
ALTER TABLE public.scan_reports ADD COLUMN IF NOT EXISTS is_demo BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE public.scan_reports ADD COLUMN IF NOT EXISTS scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE public.scan_reports ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Remove any legacy pre-auth rows without an owner and backfill client_scan_id before enforcing NOT NULL
DELETE FROM public.scan_reports WHERE user_id IS NULL;
UPDATE public.scan_reports SET client_scan_id = id::text WHERE client_scan_id IS NULL;

ALTER TABLE public.scan_reports ALTER COLUMN user_id SET DEFAULT auth.uid();
ALTER TABLE public.scan_reports ALTER COLUMN user_id SET NOT NULL;
ALTER TABLE public.scan_reports ALTER COLUMN client_scan_id SET NOT NULL;

-- Fix client_scan_id uniqueness: drop global partial index and enforce user-scoped composite UNIQUE constraint
-- compatible with PostgreSQL ON CONFLICT (user_id, client_scan_id)
DROP INDEX IF EXISTS public.uq_scan_reports_client_scan_id;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'uq_scan_reports_user_client_scan'
      AND conrelid = 'public.scan_reports'::regclass
  ) THEN
    ALTER TABLE public.scan_reports
      ADD CONSTRAINT uq_scan_reports_user_client_scan UNIQUE (user_id, client_scan_id);
  END IF;
END $$;

DROP TRIGGER IF EXISTS trg_scan_reports_updated_at ON public.scan_reports;
CREATE TRIGGER trg_scan_reports_updated_at
  BEFORE UPDATE ON public.scan_reports
  FOR EACH ROW
  EXECUTE FUNCTION public.set_updated_at();

ALTER TABLE public.scan_reports ENABLE ROW LEVEL SECURITY;

-- Remove all permissive / unauthenticated legacy policies
DROP POLICY IF EXISTS "Public read scan reports" ON public.scan_reports;
DROP POLICY IF EXISTS "Public insert scan reports" ON public.scan_reports;
DROP POLICY IF EXISTS "Public delete scan reports" ON public.scan_reports;
DROP POLICY IF EXISTS "Users view own reports" ON public.scan_reports;
DROP POLICY IF EXISTS "Users insert reports" ON public.scan_reports;
DROP POLICY IF EXISTS "Scoped read scan reports" ON public.scan_reports;
DROP POLICY IF EXISTS "Scoped insert scan reports" ON public.scan_reports;
DROP POLICY IF EXISTS "Scoped update scan reports" ON public.scan_reports;
DROP POLICY IF EXISTS "Scoped delete scan reports" ON public.scan_reports;
DROP POLICY IF EXISTS "Authenticated users read own scan reports" ON public.scan_reports;
DROP POLICY IF EXISTS "Authenticated users insert own scan reports" ON public.scan_reports;
DROP POLICY IF EXISTS "Authenticated users update own scan reports" ON public.scan_reports;
DROP POLICY IF EXISTS "Authenticated users delete own scan reports" ON public.scan_reports;

-- Strict Authenticated-Only RLS Policies (zero unauthenticated access)
CREATE POLICY "Authenticated users read own scan reports"
  ON public.scan_reports FOR SELECT
  USING (auth.uid() IS NOT NULL AND auth.uid() = user_id);

CREATE POLICY "Authenticated users insert own scan reports"
  ON public.scan_reports FOR INSERT
  WITH CHECK (auth.uid() IS NOT NULL AND auth.uid() = user_id);

CREATE POLICY "Authenticated users update own scan reports"
  ON public.scan_reports FOR UPDATE
  USING (auth.uid() IS NOT NULL AND auth.uid() = user_id)
  WITH CHECK (auth.uid() IS NOT NULL AND auth.uid() = user_id);

CREATE POLICY "Authenticated users delete own scan reports"
  ON public.scan_reports FOR DELETE
  USING (auth.uid() IS NOT NULL AND auth.uid() = user_id);

-- 5. Scan Findings Table (Normalized granular indicator records per scan)
CREATE TABLE IF NOT EXISTS public.scan_findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  report_id UUID NOT NULL REFERENCES public.scan_reports(id) ON DELETE CASCADE,
  user_id UUID NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  indicator_id TEXT NOT NULL,
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high')),
  score_impact INTEGER NOT NULL,
  is_observed BOOLEAN NOT NULL DEFAULT TRUE,
  description TEXT NOT NULL,
  remedy_or_precaution TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.scan_findings ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE;
ALTER TABLE public.scan_findings ADD COLUMN IF NOT EXISTS remedy_or_precaution TEXT;

-- Clean up any legacy unowned findings and enforce parent-synced NOT NULL ownership
DELETE FROM public.scan_findings
WHERE user_id IS NULL
   OR NOT EXISTS (SELECT 1 FROM public.scan_reports r WHERE r.id = report_id);

UPDATE public.scan_findings f
SET user_id = r.user_id
FROM public.scan_reports r
WHERE r.id = f.report_id
  AND f.user_id IS DISTINCT FROM r.user_id;

ALTER TABLE public.scan_findings ALTER COLUMN user_id SET DEFAULT auth.uid();
ALTER TABLE public.scan_findings ALTER COLUMN user_id SET NOT NULL;

-- Trigger ensuring scan_findings.user_id always matches parent scan_reports.user_id
CREATE OR REPLACE FUNCTION public.enforce_scan_finding_owner()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
  parent_owner UUID;
BEGIN
  SELECT user_id INTO parent_owner
  FROM public.scan_reports
  WHERE id = NEW.report_id;

  IF parent_owner IS NULL THEN
    RAISE EXCEPTION 'Parent scan_report % does not exist or has no owner', NEW.report_id;
  END IF;

  IF NEW.user_id IS DISTINCT FROM parent_owner THEN
    RAISE EXCEPTION 'scan_findings.user_id must match parent scan_reports.user_id';
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_scan_findings_owner ON public.scan_findings;
CREATE TRIGGER trg_scan_findings_owner
  BEFORE INSERT OR UPDATE ON public.scan_findings
  FOR EACH ROW
  EXECUTE FUNCTION public.enforce_scan_finding_owner();

ALTER TABLE public.scan_findings ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Public read scan findings" ON public.scan_findings;
DROP POLICY IF EXISTS "Public insert scan findings" ON public.scan_findings;
DROP POLICY IF EXISTS "Scoped read scan findings" ON public.scan_findings;
DROP POLICY IF EXISTS "Scoped insert scan findings" ON public.scan_findings;
DROP POLICY IF EXISTS "Scoped update scan findings" ON public.scan_findings;
DROP POLICY IF EXISTS "Scoped delete scan findings" ON public.scan_findings;
DROP POLICY IF EXISTS "Authenticated users read own scan findings" ON public.scan_findings;
DROP POLICY IF EXISTS "Authenticated users insert own scan findings" ON public.scan_findings;
DROP POLICY IF EXISTS "Authenticated users update own scan findings" ON public.scan_findings;
DROP POLICY IF EXISTS "Authenticated users delete own scan findings" ON public.scan_findings;

CREATE POLICY "Authenticated users read own scan findings"
  ON public.scan_findings FOR SELECT
  USING (
    auth.uid() IS NOT NULL
    AND auth.uid() = user_id
    AND EXISTS (
      SELECT 1 FROM public.scan_reports r
      WHERE r.id = report_id
        AND r.user_id = auth.uid()
    )
  );

CREATE POLICY "Authenticated users insert own scan findings"
  ON public.scan_findings FOR INSERT
  WITH CHECK (
    auth.uid() IS NOT NULL
    AND auth.uid() = user_id
    AND EXISTS (
      SELECT 1 FROM public.scan_reports r
      WHERE r.id = report_id
        AND r.user_id = auth.uid()
    )
  );

CREATE POLICY "Authenticated users update own scan findings"
  ON public.scan_findings FOR UPDATE
  USING (
    auth.uid() IS NOT NULL
    AND auth.uid() = user_id
    AND EXISTS (
      SELECT 1 FROM public.scan_reports r
      WHERE r.id = report_id
        AND r.user_id = auth.uid()
    )
  )
  WITH CHECK (
    auth.uid() IS NOT NULL
    AND auth.uid() = user_id
    AND EXISTS (
      SELECT 1 FROM public.scan_reports r
      WHERE r.id = report_id
        AND r.user_id = auth.uid()
    )
  );

CREATE POLICY "Authenticated users delete own scan findings"
  ON public.scan_findings FOR DELETE
  USING (
    auth.uid() IS NOT NULL
    AND auth.uid() = user_id
    AND EXISTS (
      SELECT 1 FROM public.scan_reports r
      WHERE r.id = report_id
        AND r.user_id = auth.uid()
    )
  );

-- 6. Performance Indexes
CREATE INDEX IF NOT EXISTS idx_scan_reports_user_id ON public.scan_reports(user_id);
CREATE INDEX IF NOT EXISTS idx_scan_reports_created_at ON public.scan_reports(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_reports_scanned_at ON public.scan_reports(scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_reports_scan_type ON public.scan_reports(scan_type);
CREATE INDEX IF NOT EXISTS idx_scan_reports_is_demo ON public.scan_reports(is_demo);
CREATE INDEX IF NOT EXISTS idx_scan_findings_report_id ON public.scan_findings(report_id);
CREATE INDEX IF NOT EXISTS idx_scan_findings_user_id ON public.scan_findings(user_id);
