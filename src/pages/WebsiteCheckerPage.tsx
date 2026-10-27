/**
 * VerifyBeforeBuy AI — Website Risk Checker Page
 * Redesigned with a warm, human-crafted light SaaS aesthetic.
 */

import React, { useState } from 'react';
import { Globe, Search, AlertCircle, ShieldCheck, ArrowRight, Loader2 } from 'lucide-react';
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
      note: 'Verified global commercial domain',
    },
    {
      label: 'Brand Lookalike Phishing',
      url: 'https://apple-security-verify-login.click/update-billing',
      note: 'Misleading domain with brand keyword and abuse TLD',
    },
    {
      label: 'Discount Outlet Multi-Hyphen',
      url: 'https://official-nike-cheap-wholesale-outlet.xyz/sale',
      note: 'Hyphen stuffing + non-standard retail TLD',
    },
    {
      label: 'Raw IP Hostname',
      url: 'http://45.33.32.156:8080/shop',
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
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Page Header */}
      <div className="space-y-3">
        <div className="inline-flex items-center gap-2 text-xs font-bold text-indigo-700 bg-indigo-50 px-3 py-1 rounded-full border border-indigo-100">
          <Globe className="w-3.5 h-3.5" />
          <span>Website &amp; Storefront Risk Checker</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-slate-900 tracking-tight">
          Inspect a Shopping Website
        </h1>
        <p className="text-sm text-slate-600 max-w-2xl leading-relaxed">
          Evaluate URL structure, brand typosquatting, deceptive lookalikes, encryption status, and suspicious domain patterns before entering personal or financial details.
        </p>
      </div>

      {/* Input Box Card */}
      <div className="bg-white border border-slate-200/80 rounded-2xl p-6 sm:p-8 space-y-6 shadow-xl shadow-slate-200/50">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleAnalyze();
          }}
          className="space-y-4"
        >
          <label htmlFor="url-input" className="block text-xs font-bold uppercase text-slate-700 tracking-wider">
            Storefront or Checkout URL
          </label>
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                <Globe className="w-4 h-4 text-indigo-500" />
              </div>
              <input
                id="url-input"
                type="text"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                placeholder="e.g., https://outlet-store-deals.com or www.brand.com/sale"
                className="w-full pl-10 pr-4 py-3.5 bg-slate-50 border border-slate-200 rounded-xl text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white transition-all font-mono"
              />
            </div>
            <button
              type="submit"
              disabled={isLoading}
              className="px-6 py-3.5 text-sm font-bold text-white bg-indigo-600 hover:bg-indigo-700 rounded-xl transition-colors disabled:opacity-50 flex items-center justify-center gap-2 shrink-0 shadow-md shadow-indigo-500/20"
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
            <div className="p-3.5 bg-rose-50 border border-rose-200 rounded-xl text-xs text-rose-700 flex items-center gap-2 font-medium">
              <AlertCircle className="w-4 h-4 shrink-0 text-rose-600" />
              <span>{errorMessage}</span>
            </div>
          )}
        </form>

        {/* Preset test cases */}
        <div className="pt-4 border-t border-slate-100 space-y-3">
          <span className="text-xs text-slate-500 font-semibold block">
            Or test with a representative scenario:
          </span>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {presets.map((p, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => handlePresetClick(p.url)}
                className="p-3.5 bg-slate-50 hover:bg-indigo-50/50 border border-slate-200 hover:border-indigo-200 rounded-xl text-left transition-colors flex items-center justify-between group"
              >
                <div className="space-y-0.5 truncate pr-2">
                  <div className="text-xs font-bold text-slate-800 group-hover:text-indigo-600 transition-colors">
                    {p.label}
                  </div>
                  <div className="text-[11px] font-mono text-slate-500 truncate">
                    {p.url}
                  </div>
                </div>
                <ArrowRight className="w-3.5 h-3.5 text-slate-400 group-hover:text-indigo-600 shrink-0" />
              </button>
            ))}
          </div>
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
