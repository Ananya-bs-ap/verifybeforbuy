-- ==============================================================================
-- VERIFYBEFOREBUY AI — SUPABASE DATABASE SCHEMA MIGRATION
-- Project ID: muwesnqibkfbjzxqdhfj
-- Tables: scan_reports, scan_findings, profiles
-- Purpose: Saving online shopping product & website risk assessments
-- ==============================================================================

-- 1. Enable UUID Extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 2. Scan Reports Table (Stores every website, product, and barcode risk assessment)
CREATE TABLE IF NOT EXISTS public.scan_reports (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  scan_type TEXT NOT NULL CHECK (scan_type IN ('website', 'product', 'code')),
  target_summary TEXT NOT NULL,
  subtarget TEXT,
  risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
  risk_category TEXT NOT NULL CHECK (risk_category IN ('lower', 'moderate', 'elevated', 'high')),
  confidence_coverage TEXT NOT NULL CHECK (confidence_coverage IN ('minimal', 'moderate', 'high', 'comprehensive')),
  confidence_score INTEGER NOT NULL CHECK (confidence_score >= 0 AND confidence_score <= 100),
  summary_text TEXT NOT NULL,
  ai_explanation TEXT,
  raw_result JSONB NOT NULL,
  is_demo BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Enable Row Level Security (RLS)
ALTER TABLE public.scan_reports ENABLE ROW LEVEL SECURITY;

-- Allow public read and write so scans performed by users are saved directly
CREATE POLICY "Public read scan reports"
  ON public.scan_reports FOR SELECT
  USING (true);

CREATE POLICY "Public insert scan reports"
  ON public.scan_reports FOR INSERT
  WITH CHECK (true);

CREATE POLICY "Public delete scan reports"
  ON public.scan_reports FOR DELETE
  USING (true);

-- 3. Scan Findings Table (Normalized granular indicator records)
CREATE TABLE IF NOT EXISTS public.scan_findings (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  report_id UUID NOT NULL REFERENCES public.scan_reports(id) ON DELETE CASCADE,
  indicator_id TEXT NOT NULL,
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high')),
  score_impact INTEGER NOT NULL,
  is_observed BOOLEAN NOT NULL DEFAULT TRUE,
  description TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE public.scan_findings ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Public read scan findings"
  ON public.scan_findings FOR SELECT
  USING (true);

CREATE POLICY "Public insert scan findings"
  ON public.scan_findings FOR INSERT
  WITH CHECK (true);

-- 4. Profiles Table (Optional Auth user accounts)
CREATE TABLE IF NOT EXISTS public.profiles (
  id UUID REFERENCES auth.users ON DELETE CASCADE PRIMARY KEY,
  email TEXT,
  display_name TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view their own profile"
  ON public.profiles FOR SELECT
  USING (auth.uid() = id);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_scan_reports_created_at ON public.scan_reports(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_reports_scan_type ON public.scan_reports(scan_type);
CREATE INDEX IF NOT EXISTS idx_scan_findings_report_id ON public.scan_findings(report_id);
