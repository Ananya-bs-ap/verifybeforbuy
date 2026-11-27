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
  UserCheck,
  UserX,
  LogIn,
  UserPlus,
} from 'lucide-react';
import { AuthUserProfile, SavedScanRecord, AssessmentResult, SupabaseConfigStatus } from '../types';
import { HistoryService } from '../lib/supabase/historyService';
import { checkSupabaseConnection, supabaseConfigStatus } from '../lib/supabase/client';
import schemaSql from '../lib/supabase/schema.sql?raw';
import { CATEGORY_META } from '../lib/riskEngine/rules';
import { VerificationReport } from '../components/VerificationReport';
import { NavTab } from '../components/Navbar';

interface HistoryDashboardPageProps {
  onNavigate: (tab: NavTab) => void;
  authUser?: AuthUserProfile | null;
}

export const HistoryDashboardPage: React.FC<HistoryDashboardPageProps> = ({
  onNavigate,
  authUser = null,
}) => {
  const [records, setRecords] = useState<SavedScanRecord[]>([]);
  const [dbStatus, setDbStatus] = useState<SupabaseConfigStatus>({ ...supabaseConfigStatus });
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [activeReport, setActiveReport] = useState<AssessmentResult | null>(null);
  const [showSqlModal, setShowSqlModal] = useState(false);
  const [copiedSql, setCopiedSql] = useState(false);

  const activeUserId = authUser?.id ?? null;

  useEffect(() => {
    setActiveReport(null);
    setRecords([]);
    void refreshConnectionAndHistory(false, activeUserId);
  }, [activeUserId]);

  const refreshConnectionAndHistory = async (
    forceCheck = false,
    scopedUserId: string | null = activeUserId
  ) => {
    const status = await checkSupabaseConnection(forceCheck);
    setDbStatus(status);
    const list = await HistoryService.getHistory({ userId: scopedUserId });
    setRecords(list);
  };

  const loadHistory = async (scopedUserId: string | null = activeUserId) => {
    const list = await HistoryService.getHistory({ userId: scopedUserId });
    setRecords(list);
  };

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    await HistoryService.deleteRecord(id, { userId: activeUserId });
    await loadHistory(activeUserId);
    if (activeReport?.id === id) {
      setActiveReport(null);
    }
  };

  const handleClearAll = async () => {
    const scopeLabel =
      activeUserId && dbStatus.connectionState === 'connected'
        ? `Clear all scan history for ${authUser?.email || 'your account'} from Supabase and local fallback?`
        : activeUserId
          ? `Clear all local fallback scan history for ${authUser?.email || 'your account'}?`
          : 'Clear all guest scan history from local browser storage?';
    if (window.confirm(scopeLabel)) {
      await HistoryService.clearHistory({ userId: activeUserId });
      await loadHistory(activeUserId);
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

  const sqlSchemaText = schemaSql;

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Header & Status Indicator */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-3xl font-extrabold text-white tracking-tight">
              Scan History &amp; Audits
            </h1>
            <button
              type="button"
              onClick={() => refreshConnectionAndHistory(true)}
              title="Click to re-verify live Supabase database connection"
              className={`text-[11px] font-mono px-2.5 py-0.5 rounded border uppercase font-medium transition-colors ${
                dbStatus.connectionState === 'connected'
                  ? 'text-teal-400 border-teal-800 bg-teal-950/60 hover:bg-teal-950'
                  : dbStatus.connectionState === 'error'
                    ? 'text-amber-300 border-amber-700 bg-amber-950/60 hover:bg-amber-950'
                    : dbStatus.connectionState === 'checking'
                      ? 'text-indigo-300 border-indigo-700 bg-indigo-950/60'
                      : 'text-slate-400 border-slate-700 bg-slate-900/60 hover:bg-slate-800'
              }`}
            >
              {dbStatus.connectionState === 'connected'
                ? `Supabase Connected (${dbStatus.projectId})`
                : dbStatus.connectionState === 'checking'
                  ? 'Checking Supabase Connection...'
                  : dbStatus.connectionState === 'error'
                    ? 'Supabase Unavailable · Local Fallback'
                    : 'Local Browser Mode (Unconfigured)'}
            </button>
          </div>
          <p className="text-xs text-slate-400">
            {!activeUserId
              ? 'Guest Mode active: scans stay strictly in your browser localStorage and are never uploaded to Supabase.'
              : dbStatus.connectionState === 'connected'
                ? `Signed in as ${authUser?.displayName} (${authUser?.email}) — syncing private scans to Supabase PostgreSQL.`
                : dbStatus.connectionState === 'error'
                  ? `Database check failed: ${dbStatus.errorMessage || 'Unable to reach Supabase'}. Scans for ${authUser?.email} are isolated in local fallback storage.`
                  : `Signed in as ${authUser?.displayName}. Configure VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY for cloud sync.`}
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

      {/* Account Scope & Isolation Banner */}
      {authUser ? (
        <div className="p-4 bg-slate-900/80 border border-teal-800/60 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-teal-500/15 border border-teal-500/30 text-teal-300 flex items-center justify-center shrink-0">
              <UserCheck className="w-4 h-4" />
            </div>
            <div>
              <div className="text-xs font-bold text-white">
                {authUser.displayName}{' '}
                <span className="font-mono font-normal text-slate-400">({authUser.email})</span>
              </div>
              <div className="text-[11px] text-slate-400">
                Account-isolated history active · Other users and guest scans are strictly separated.
              </div>
            </div>
          </div>
          <span className="text-[10px] font-mono uppercase px-2 py-1 rounded bg-teal-950/70 text-teal-300 border border-teal-800 self-start sm:self-center">
            Authenticated Sync
          </span>
        </div>
      ) : (
        <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-slate-800 border border-slate-700 text-slate-300 flex items-center justify-center shrink-0">
              <UserX className="w-4 h-4" />
            </div>
            <div>
              <div className="text-xs font-bold text-white">Guest Mode (Local Storage Only)</div>
              <div className="text-[11px] text-slate-400">
                Guest scan history is stored only in this browser and is never uploaded to Supabase. Sign in to save private cloud history.
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => onNavigate('login')}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 rounded-lg transition-colors"
            >
              <LogIn className="w-3.5 h-3.5" />
              <span>Sign In</span>
            </button>
            <button
              type="button"
              onClick={() => onNavigate('register')}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors"
            >
              <UserPlus className="w-3.5 h-3.5" />
              <span>Register</span>
            </button>
          </div>
        </div>
      )}

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
                    <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
                      <span className="uppercase font-semibold text-teal-400 font-mono text-[10px]">
                        {record.type}
                      </span>
                      {(record.isDemo || record.result?.isDemoMode) ? (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono uppercase bg-amber-950/70 text-amber-300 border border-amber-700/70">
                          Synthetic Demo
                        </span>
                      ) : (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono uppercase bg-emerald-950/60 text-emerald-300 border border-emerald-800/60">
                          Actual Scan
                        </span>
                      )}
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
                          {record.storageSource === 'supabase' ? 'Supabase Cloud' : 'Local Browser'}
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
              <p>1. Open your <strong>Supabase Dashboard &gt; SQL Editor</strong> and run the complete migration script below:</p>
            </div>

            <div className="relative">
              <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-[11px] font-mono text-teal-300 overflow-x-auto max-h-56">
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

            <div className="text-xs text-slate-400 space-y-1.5">
              <p>
                2. Set <code className="text-teal-300">VITE_SUPABASE_URL</code> and your public publishable/anon key <code className="text-teal-300">VITE_SUPABASE_ANON_KEY</code> in <code className="text-slate-300">.env</code> (for local VS Code) or Google AI Studio environment settings.
              </p>
              <p className="text-[11px] text-amber-300/90">
                Never place a <code className="font-mono">service_role</code> or <code className="font-mono">sb_secret_</code> key in frontend <code className="font-mono">VITE_</code> variables.
              </p>
            </div>

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
