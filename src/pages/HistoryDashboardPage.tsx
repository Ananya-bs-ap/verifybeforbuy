/**
 * VerifyBeforeBuy AI — Scan History & Dashboard
 * Displays private scan records with search, filter, export, and Supabase integration guidance.
 */

import React, { useState, useEffect } from 'react';
import {
  History,
  Search,
  Filter,
  Download,
  Trash2,
  ExternalLink,
  ShieldCheck,
  AlertTriangle,
  ShieldAlert,
  Info,
  Database,
  CheckCircle2,
  ArrowRight,
  Code2,
  X,
} from 'lucide-react';
import { SavedScanRecord, RiskCategory, AssessmentResult } from '../types';
import { HistoryService } from '../lib/supabase/historyService';
import { supabaseConfigStatus } from '../lib/supabase/client';
import { CATEGORY_META } from '../lib/riskEngine/rules';
import { VerificationReport } from '../components/VerificationReport';
import { NavTab } from '../components/Navbar';

interface HistoryDashboardPageProps {
  onNavigate: (tab: NavTab) => void;
}

export const HistoryDashboardPage: React.FC<HistoryDashboardPageProps> = ({ onNavigate }) => {
  const [records, setRecords] = useState<SavedScanRecord[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [activeReport, setActiveReport] = useState<AssessmentResult | null>(null);
  const [showSqlModal, setShowSqlModal] = useState(false);
  const [copiedSql, setCopiedSql] = useState(false);

  useEffect(() => {
    loadHistory();
  }, []);

  const loadHistory = async () => {
    const list = await HistoryService.getHistory();
    setRecords(list);
  };

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    await HistoryService.deleteRecord(id);
    await loadHistory();
    if (activeReport?.id === id) {
      setActiveReport(null);
    }
  };

  const handleClearAll = async () => {
    if (window.confirm('Clear all local scan history?')) {
      await HistoryService.clearHistory();
      await loadHistory();
      setActiveReport(null);
    }
  };

  const handleExportJson = () => {
    const blob = new Blob([JSON.stringify(records, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `verifybeforebuy_history_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportCsv = () => {
    const headers = ['ID', 'Date', 'Type', 'Target', 'Score', 'Category', 'Confidence', 'Storage'];
    const rows = records.map((r) => [
      r.id,
      new Date(r.createdAt).toISOString(),
      r.type,
      `"${r.target.replace(/"/g, '""')}"`,
      r.score,
      r.category,
      r.confidence,
      r.storageSource,
    ]);

    const csvContent = [headers.join(','), ...rows.map((row) => row.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `verifybeforebuy_history_${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const filtered = records.filter((r) => {
    const matchesSearch =
      r.target.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.type.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesCat = selectedCategory === 'all' || r.category === selectedCategory;
    return matchesSearch && matchesCat;
  });

  const sqlSchemaText = `-- Supabase PostgreSQL Schema for VerifyBeforeBuy AI
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS public.profiles (
  id UUID REFERENCES auth.users ON DELETE CASCADE PRIMARY KEY,
  email TEXT,
  display_name TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS public.scan_reports (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  scan_type TEXT NOT NULL CHECK (scan_type IN ('website', 'product', 'code')),
  target_summary TEXT NOT NULL,
  risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
  risk_category TEXT NOT NULL CHECK (risk_category IN ('lower', 'moderate', 'elevated', 'high')),
  confidence_coverage TEXT NOT NULL,
  raw_result JSONB NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE public.scan_reports ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users view own reports" ON public.scan_reports
  FOR SELECT USING (auth.uid() = user_id OR user_id IS NULL);

CREATE POLICY "Users insert reports" ON public.scan_reports
  FOR INSERT WITH CHECK (auth.uid() = user_id OR user_id IS NULL);
`;

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Header & Status Indicator */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-3">
            <h1 className="text-3xl font-extrabold text-white tracking-tight">
              Scan History &amp; Audits
            </h1>
            <span
              className={`text-[11px] font-mono px-2.5 py-0.5 rounded border uppercase font-medium ${
                supabaseConfigStatus.isConfigured
                  ? 'text-teal-400 border-teal-800 bg-teal-950/60'
                  : 'text-slate-400 border-slate-700 bg-slate-900/60'
              }`}
            >
              {supabaseConfigStatus.isConfigured ? `Supabase Connected (${supabaseConfigStatus.projectId || 'muwesnqibkfbjzxqdhfj'})` : 'Local Browser Mode'}
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Audit logs are saved locally in your browser. Configure Supabase PostgreSQL anytime for persistent multi-device cloud storage.
          </p>
        </div>

        {/* Database Config Modal Button */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowSqlModal(true)}
            className="flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-300 hover:text-white bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-lg transition-colors whitespace-nowrap"
          >
            <Database className="w-3.5 h-3.5 text-teal-400" />
            <span>Database Setup &amp; SQL</span>
          </button>

          {records.length > 0 && (
            <div className="flex items-center gap-1.5">
              <button
                onClick={handleExportCsv}
                className="flex items-center gap-1 px-3 py-2 text-xs font-medium text-slate-300 hover:text-white bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-lg transition-colors"
                title="Export as CSV"
              >
                <Download className="w-3.5 h-3.5" />
                <span>CSV</span>
              </button>
              <button
                onClick={handleExportJson}
                className="flex items-center gap-1 px-3 py-2 text-xs font-medium text-slate-300 hover:text-white bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-lg transition-colors"
                title="Export as JSON"
              >
                <Download className="w-3.5 h-3.5" />
                <span>JSON</span>
              </button>
              <button
                onClick={handleClearAll}
                className="p-2 text-slate-400 hover:text-rose-400 rounded-lg transition-colors"
                title="Clear History"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Filter & Search Bar */}
      <div className="flex flex-col sm:flex-row gap-4 justify-between items-center bg-slate-900/60 p-4 border border-slate-800 rounded-xl">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3 pointer-events-none" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search targets or keywords..."
            className="w-full pl-9 pr-4 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-teal-400 font-mono"
          />
        </div>

        {/* Filter Segmented Control (Interactive functional buttons) */}
        <div className="flex items-center gap-1 p-1 bg-slate-950 rounded-lg border border-slate-800 w-full sm:w-auto overflow-x-auto">
          {['all', 'lower', 'moderate', 'elevated', 'high'].map((cat) => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors capitalize whitespace-nowrap shrink-0 ${
                selectedCategory === cat
                  ? 'bg-slate-800 text-teal-300 shadow-sm font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {cat === 'all' ? 'All Risks' : `${cat} risk`}
            </button>
          ))}
        </div>
      </div>

      {/* Active Selected Report Viewer */}
      {activeReport && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-teal-400 uppercase tracking-wider">
              Viewing Selected Scan Report
            </h2>
            <button
              onClick={() => setActiveReport(null)}
              className="text-xs text-slate-400 hover:text-white"
            >
              Close report view
            </button>
          </div>
          <VerificationReport
            result={activeReport}
            onReset={() => setActiveReport(null)}
          />
        </div>
      )}

      {/* Records Table / Card List */}
      <div className="space-y-3">
        {filtered.length === 0 ? (
          <div className="p-12 border border-dashed border-slate-800 rounded-2xl text-center space-y-4 bg-slate-950/40">
            <div className="w-12 h-12 rounded-full bg-slate-900 border border-slate-800 flex items-center justify-center mx-auto text-slate-400">
              <History className="w-6 h-6" />
            </div>
            <div className="space-y-1">
              <h3 className="text-sm font-semibold text-white">No scans match your criteria</h3>
              <p className="text-xs text-slate-400 max-w-sm mx-auto">
                {records.length === 0
                  ? 'Run your first website or product inspection to start logging safety audits.'
                  : 'Try clearing your search query or switching risk category filters.'}
              </p>
            </div>
            {records.length === 0 && (
              <div className="flex justify-center gap-3 pt-2">
                <button
                  onClick={() => onNavigate('website')}
                  className="px-4 py-2 text-xs font-semibold text-slate-950 bg-teal-400 hover:bg-teal-300 rounded-lg transition-colors"
                >
                  Check a Website
                </button>
                <button
                  onClick={() => onNavigate('product')}
                  className="px-4 py-2 text-xs font-semibold text-white bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors"
                >
                  Check a Product
                </button>
              </div>
            )}
          </div>
        ) : (
          <div className="space-y-2">
            {filtered.map((record) => {
              const meta = CATEGORY_META[record.category];
              return (
                <div
                  key={record.id}
                  onClick={() => setActiveReport(record.result)}
                  className={`p-4 bg-slate-900/80 hover:bg-slate-850 border rounded-xl cursor-pointer transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-4 ${
                    activeReport?.id === record.id
                      ? 'border-teal-500/80 bg-slate-900 ring-1 ring-teal-500/40'
                      : 'border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="space-y-1 truncate pr-2">
                    <div className="flex items-center gap-2 text-xs text-slate-400">
                      <span className="uppercase font-semibold text-teal-400 font-mono text-[10px]">
                        {record.type}
                      </span>
                      <span aria-hidden="true">·</span>
                      <span className="font-mono text-[11px] tabular-nums">
                        {new Date(record.createdAt).toLocaleDateString()} at{' '}
                        {new Date(record.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </span>
                      <span aria-hidden="true">·</span>
                      <span className="text-slate-500 capitalize">{record.confidence} data</span>
                    </div>
                    <div className="text-sm font-semibold text-white truncate">
                      {record.target}
                    </div>
                  </div>

                  <div className="flex items-center gap-4 shrink-0">
                    {/* Score & Category Indicator */}
                    <div className="flex items-center gap-3 text-right">
                      <div>
                        <div className="text-xs font-bold text-slate-200">
                          {meta.label}
                        </div>
                        <div className="text-[10px] text-slate-400">
                          {record.storageSource === 'supabase' ? 'Cloud' : 'Local'}
                        </div>
                      </div>
                      <div className={`px-2.5 py-1 rounded border font-mono font-bold text-sm tabular-nums ${meta.badgeClass}`}>
                        {record.score}
                      </div>
                    </div>

                    <button
                      onClick={(e) => handleDelete(record.id, e)}
                      className="p-1.5 text-slate-500 hover:text-rose-400 rounded transition-colors"
                      title="Delete record"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Supabase SQL Migration Modal */}
      {showSqlModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Database className="w-5 h-5 text-teal-400" />
                <h3 className="font-bold text-base text-white">Supabase Integration Guide</h3>
              </div>
              <button
                onClick={() => setShowSqlModal(false)}
                className="text-slate-400 hover:text-white p-1"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              VerifyBeforeBuy AI supports direct PostgreSQL persistence via Supabase. To connect your instance:
            </p>

            <div className="space-y-2 text-xs text-slate-300">
              <p>1. Open your <strong>Supabase Dashboard &gt; SQL Editor</strong>.</p>
              <p>2. Paste and run the migration script below to create the schema and Row Level Security policies:</p>
            </div>

            <div className="relative">
              <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-[11px] font-mono text-teal-300 overflow-x-auto max-h-48">
                {sqlSchemaText}
              </pre>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(sqlSchemaText);
                  setCopiedSql(true);
                  setTimeout(() => setCopiedSql(false), 2000);
                }}
                className="absolute top-2 right-2 px-2 py-1 text-[10px] font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 rounded border border-slate-700"
              >
                {copiedSql ? 'Copied' : 'Copy SQL'}
              </button>
            </div>

            <p className="text-xs text-slate-400">
              3. Set <code>VITE_SUPABASE_URL</code> and <code>VITE_SUPABASE_ANON_KEY</code> in your environment or <code>.env</code>.
            </p>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setShowSqlModal(false)}
                className="px-4 py-2 text-xs font-semibold text-slate-950 bg-teal-400 hover:bg-teal-300 rounded-lg transition-colors"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
