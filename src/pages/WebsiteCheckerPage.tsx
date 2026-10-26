/**
 * VerifyBeforeBuy AI — Website Risk Checker Page
 * URL input, format validation, preset test cases, SSRF safety disclosure,
 * and comprehensive risk report rendering.
 */

import React, { useState } from 'react';
import { Globe, Search, AlertCircle, ShieldCheck, ArrowRight, Loader2, Sparkles, CheckCircle2 } from 'lucide-react';
import { AssessmentResult } from '../types';
import { ApiService } from '../lib/api';
import { HistoryService } from '../lib/supabase/historyService';
import { VerificationReport } from '../components/VerificationReport';

export const WebsiteCheckerPage: React.FC = () => {
  const [urlInput, setUrlInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [currentResult, setCurrentResult] = useState<AssessmentResult | null>(null);

  const presets = [
    {
      label: 'Recognized Retailer',
      url: 'https://www.amazon.com/dp/B08N5WRWNW',
      type: 'lower',
      note: 'Verified global commercial domain',
    },
    {
      label: 'Brand Lookalike Phishing',
      url: 'https://apple-security-verify-login.click/update-billing',
      type: 'elevated',
      note: 'Misleading domain with brand keyword and abuse TLD',
    },
    {
      label: 'Discount Outlet Multi-Hyphen',
      url: 'https://official-nike-cheap-wholesale-outlet.xyz/sale',
      type: 'elevated',
      note: 'Hyphen stuffing + non-standard retail TLD',
    },
    {
      label: 'Raw IP Hostname',
      url: 'http://45.33.32.156:8080/shop',
      type: 'high',
      note: 'Unencrypted raw IP host on non-standard port',
    },
  ];

  const handleAnalyze = async (urlToTest?: string) => {
    const targetUrl = (urlToTest || urlInput).trim();
    setErrorMessage(null);

    if (!targetUrl) {
      setErrorMessage('Please enter a website URL to evaluate.');
      return;
    }

    // Basic format test
    try {
      const sanitized = targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`;
      new URL(sanitized);
    } catch {
      setErrorMessage('Invalid URL format. Please provide a standard address such as https://example.com');
      return;
    }

    setIsLoading(true);
    try {
      const result = await ApiService.analyzeWebsite({ url: targetUrl });
      setCurrentResult(result);
      await HistoryService.saveRecord(result);
    } catch (err: any) {
      setErrorMessage(err.message || 'Analysis could not be completed.');
    } finally {
      setIsLoading(false);
    }
  };

  const handlePresetClick = (presetUrl: string) => {
    setUrlInput(presetUrl);
    handleAnalyze(presetUrl);
  };

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Page Header */}
      <div className="space-y-3">
        <div className="inline-flex items-center gap-2 text-xs font-semibold text-teal-400 bg-teal-950/60 px-3 py-1 rounded-full border border-teal-800/60">
          <Globe className="w-3.5 h-3.5" />
          <span>Website &amp; Storefront Risk Checker</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          Inspect a Shopping Website
        </h1>
        <p className="text-sm text-slate-400 max-w-2xl leading-relaxed">
          Evaluate URL structure, brand typosquatting, deceptive lookalikes, encryption status, and suspicious domain patterns before entering personal or financial details.
        </p>
      </div>

      {/* Input Box Card */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 sm:p-8 space-y-6 shadow-xl">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleAnalyze();
          }}
          className="space-y-4"
        >
          <label htmlFor="url-input" className="block text-xs font-semibold uppercase text-slate-300 tracking-wider">
            Storefront or Checkout URL
          </label>
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                <Globe className="w-4 h-4" />
              </div>
              <input
                id="url-input"
                type="text"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                placeholder="e.g., https://outlet-store-deals.com or www.brand.com/sale"
                className="w-full pl-10 pr-4 py-3 bg-slate-950 border border-slate-700/80 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-teal-400 focus:border-transparent transition-all font-mono"
              />
            </div>
            <button
              type="submit"
              disabled={isLoading}
              className="px-6 py-3 text-sm font-semibold text-slate-950 bg-teal-400 hover:bg-teal-300 rounded-xl transition-colors disabled:opacity-50 flex items-center justify-center gap-2 shrink-0 shadow-sm"
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Inspecting...</span>
                </>
              ) : (
                <>
                  <Search className="w-4 h-4" />
                  <span>Analyze Website</span>
                </>
              )}
            </button>
          </div>

          {errorMessage && (
            <div className="p-3 bg-rose-950/60 border border-rose-900/60 rounded-lg text-xs text-rose-300 flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
              <span>{errorMessage}</span>
            </div>
          )}
        </form>

        {/* Preset test cases */}
        <div className="pt-4 border-t border-slate-800/80 space-y-3">
          <span className="text-xs text-slate-400 font-medium block">
            Or test with a representative scenario:
          </span>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
            {presets.map((p, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => handlePresetClick(p.url)}
                className="p-3 bg-slate-950/60 hover:bg-slate-800/80 border border-slate-800 rounded-lg text-left transition-colors flex items-center justify-between group"
              >
                <div className="space-y-0.5 truncate pr-2">
                  <div className="text-xs font-semibold text-slate-200 group-hover:text-teal-300 transition-colors">
                    {p.label}
                  </div>
                  <div className="text-[11px] font-mono text-slate-400 truncate">
                    {p.url}
                  </div>
                </div>
                <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-teal-400 shrink-0" />
              </button>
            ))}
          </div>
        </div>

        {/* Security disclosure banner */}
        <div className="p-4 bg-slate-950/40 border border-slate-800/60 rounded-lg text-xs text-slate-400 space-y-1">
          <div className="flex items-center gap-2 text-slate-300 font-medium">
            <ShieldCheck className="w-3.5 h-3.5 text-teal-400" />
            <span>Server-Side SSRF &amp; Sandbox Protection</span>
          </div>
          <p>
            Submitted addresses are inspected safely. Private networks, loopbacks, and cloud metadata endpoints are strictly blocked. We do not execute untrusted client scripts or visit dangerous links from your browser.
          </p>
        </div>
      </div>

      {/* Assessment Report View */}
      {currentResult && (
        <div className="pt-4">
          <VerificationReport
            result={currentResult}
            onReset={() => {
              setCurrentResult(null);
              setUrlInput('');
            }}
          />
        </div>
      )}
    </div>
  );
};
