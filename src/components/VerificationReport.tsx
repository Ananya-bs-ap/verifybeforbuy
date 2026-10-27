/**
 * Reusable Verification & Risk Assessment Report Component
 * Redesigned with a clean, warm, human-crafted SaaS light theme.
 */

import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
  CheckCircle2,
  Sparkles,
  Printer,
  Copy,
  RotateCcw,
  FileCheck2,
} from 'lucide-react';
import { AssessmentResult } from '../types';
import { ApiService } from '../lib/api';

interface VerificationReportProps {
  result: AssessmentResult;
  onReset?: () => void;
  onSave?: (result: AssessmentResult) => void;
  isSaved?: boolean;
}

export const VerificationReport: React.FC<VerificationReportProps> = ({
  result,
  onReset,
  onSave,
  isSaved = false,
}) => {
  const [aiExplanation, setAiExplanation] = useState<string | undefined>(result.aiExplanation);
  const [aiProvider, setAiProvider] = useState<'gemini' | 'deterministic-fallback' | undefined>(
    result.aiExplanationProvider
  );
  const [isExplaining, setIsExplaining] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleGenerateAiExplanation = async () => {
    setIsExplaining(true);
    try {
      const res = await ApiService.requestAiExplanation(result);
      setAiExplanation(res.explanation);
      setAiProvider(res.provider);
      result.aiExplanation = res.explanation;
      result.aiExplanationProvider = res.provider;
      if (onSave) onSave(result);
    } catch (err) {
      console.error('Explanation request failed:', err);
    } finally {
      setIsExplaining(false);
    }
  };

  const handleCopySummary = () => {
    const text = `VerifyBeforeBuy AI Report
Target: ${result.inputSummary.target}
Risk Score: ${result.score}/100 (${result.category.toUpperCase()} RISK)
Confidence Coverage: ${result.confidence} (${result.confidenceScore}%)
Summary: ${result.summary}
Disclaimer: ${result.disclaimer}`;

    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handlePrint = () => {
    window.print();
  };

  const severityBadge = (sev: string) => {
    switch (sev) {
      case 'high':
        return 'text-rose-700 border-rose-200 bg-rose-50 font-bold';
      case 'medium':
        return 'text-amber-700 border-amber-200 bg-amber-50 font-bold';
      case 'low':
        return 'text-indigo-700 border-indigo-200 bg-indigo-50 font-bold';
      default:
        return 'text-slate-700 border-slate-200 bg-slate-50 font-bold';
    }
  };

  const getScoreColor = (score: number) => {
    if (score <= 25) return 'text-emerald-600';
    if (score <= 50) return 'text-indigo-600';
    if (score <= 75) return 'text-amber-600';
    return 'text-rose-600';
  };

  const getMeterColor = (score: number) => {
    if (score <= 25) return 'bg-emerald-500';
    if (score <= 50) return 'bg-indigo-500';
    if (score <= 75) return 'bg-amber-500';
    return 'bg-rose-500';
  };

  return (
    <div className="bg-white border border-slate-200/80 rounded-2xl p-6 md:p-8 space-y-8 text-slate-900 shadow-xl shadow-slate-200/50">
      {/* 1. Header & Meta */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-100">
        <div>
          <div className="flex items-center gap-3 text-xs text-slate-500 mb-2 font-medium">
            <span className="uppercase tracking-wider font-bold text-indigo-600 bg-indigo-50 px-2.5 py-0.5 rounded-md border border-indigo-100">
              {result.type === 'website' ? 'Website Assessment' : result.type === 'product' ? 'Product Listing Assessment' : 'Barcode & QR Assessment'}
            </span>
            <span aria-hidden="true">·</span>
            <span className="font-mono tabular-nums">{new Date(result.timestamp).toLocaleString()}</span>
            {result.isDemoMode && (
              <>
                <span aria-hidden="true">·</span>
                <span className="text-amber-600 font-semibold">Demo Reference</span>
              </>
            )}
          </div>
          <h2 className="text-xl md:text-2xl font-extrabold text-slate-900 break-words">
            {result.inputSummary.target}
          </h2>
          {result.inputSummary.brand && (
            <p className="text-xs text-slate-500 mt-1">
              Brand: <span className="text-slate-800 font-semibold">{result.inputSummary.brand}</span>
              {result.inputSummary.sellerName && ` · Seller: ${result.inputSummary.sellerName}`}
              {result.inputSummary.price !== undefined && ` · Price: $${result.inputSummary.price}`}
            </p>
          )}
        </div>

        {/* Quick Actions */}
        <div className="flex items-center gap-2 shrink-0 print:hidden">
          <button
            onClick={handleCopySummary}
            className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-slate-700 hover:text-slate-900 bg-slate-100 hover:bg-slate-200 border border-slate-200 rounded-xl transition-colors"
          >
            <Copy className="w-3.5 h-3.5" />
            <span>{copied ? 'Copied' : 'Copy'}</span>
          </button>
          <button
            onClick={handlePrint}
            className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-slate-700 hover:text-slate-900 bg-slate-100 hover:bg-slate-200 border border-slate-200 rounded-xl transition-colors"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print</span>
          </button>
          {onReset && (
            <button
              onClick={onReset}
              className="flex items-center gap-1.5 px-4 py-2 text-xs font-bold text-white bg-indigo-600 hover:bg-indigo-700 rounded-xl transition-colors shadow-sm"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>New Check</span>
            </button>
          )}
        </div>
      </div>

      {/* 2. Primary Score & Category Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Score Card */}
        <div className="p-6 bg-slate-50 border border-slate-200/80 rounded-2xl flex flex-col justify-between">
          <div className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">
            Assessed Risk Score
          </div>
          <div className="flex items-baseline gap-2">
            <span className={`text-5xl font-extrabold font-mono tabular-nums ${getScoreColor(result.score)}`}>
              {result.score}
            </span>
            <span className="text-slate-400 font-mono text-lg">/ 100</span>
          </div>

          <div className="mt-4">
            <div className="w-full h-2.5 bg-slate-200 rounded-full overflow-hidden">
              <div
                className={`h-full transition-all duration-500 ${getMeterColor(result.score)}`}
                style={{ width: `${Math.max(result.score, 4)}%` }}
              />
            </div>
            <div className="flex justify-between text-[10px] text-slate-400 font-mono mt-1.5">
              <span>0 (Low)</span>
              <span>25</span>
              <span>50</span>
              <span>75</span>
              <span>100 (High)</span>
            </div>
          </div>
        </div>

        {/* Category Card */}
        <div className="p-6 bg-slate-50 border border-slate-200/80 rounded-2xl flex flex-col justify-between">
          <div>
            <div className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">
              Risk Classification
            </div>
            <div className="flex items-center gap-2 mb-2">
              {result.category === 'lower' ? (
                <ShieldCheck className="w-6 h-6 text-emerald-600" />
              ) : result.category === 'moderate' ? (
                <Info className="w-6 h-6 text-indigo-600" />
              ) : result.category === 'elevated' ? (
                <AlertTriangle className="w-6 h-6 text-amber-600" />
              ) : (
                <ShieldAlert className="w-6 h-6 text-rose-600" />
              )}
              <span className={`text-lg font-bold capitalize ${getScoreColor(result.score)}`}>
                {result.category} Risk
              </span>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">
              {result.summary}
            </p>
          </div>
          <div className="text-[11px] text-slate-400 pt-3 border-t border-slate-200">
            Probability estimation · Not a certificate of authenticity
          </div>
        </div>

        {/* Evidence Coverage Card */}
        <div className="p-6 bg-slate-50 border border-slate-200/80 rounded-2xl flex flex-col justify-between">
          <div>
            <div className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">
              Evidence Coverage
            </div>
            <div className="flex items-baseline gap-2 mb-2">
              <span className="text-2xl font-extrabold text-slate-900 capitalize">
                {result.confidence}
              </span>
              <span className="text-xs text-slate-500 font-mono tabular-nums">
                ({result.confidenceScore}%)
              </span>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">
              Evaluated against available input signals. Missing data is not scored as fraud.
            </p>
          </div>
          <div className="text-[11px] text-slate-400 pt-3 border-t border-slate-200">
            {result.indicators.length} indicators · {result.positiveSignals.length} positive signals
          </div>
        </div>
      </div>

      {/* 3. Warning Indicators List */}
      <div className="space-y-4">
        <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-amber-600" />
          <span>Identified Risk Indicators ({result.indicators.length})</span>
        </h3>

        {result.indicators.length === 0 ? (
          <div className="p-4 bg-emerald-50 border border-emerald-200 rounded-xl text-xs text-emerald-800 flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-600" />
            <span>No suspicious indicators detected based on the available input.</span>
          </div>
        ) : (
          <div className="space-y-3">
            {result.indicators.map((ind) => (
              <div
                key={ind.id}
                className="p-4 bg-slate-50 border border-slate-200/80 rounded-xl space-y-2 hover:border-slate-300 transition-colors"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded-md border uppercase ${severityBadge(ind.severity)}`}>
                      {ind.severity}
                    </span>
                    <span className="font-bold text-sm text-slate-900">{ind.name}</span>
                  </div>
                  <span className="font-mono text-xs font-bold text-rose-600 tabular-nums">
                    +{ind.scoreImpact} pts
                  </span>
                </div>
                <p className="text-xs text-slate-600 leading-relaxed">
                  {ind.description}
                </p>
                {ind.remedyOrPrecaution && (
                  <div className="text-xs text-indigo-700 bg-indigo-50 p-2.5 rounded-lg border border-indigo-100 flex items-start gap-1.5">
                    <span className="font-bold shrink-0">Recommendation:</span>
                    <span>{ind.remedyOrPrecaution}</span>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 4. Positive Signals */}
      {result.positiveSignals.length > 0 && (
        <div className="space-y-4">
          <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-600" />
            <span>Positive Reassurance Signals ({result.positiveSignals.length})</span>
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {result.positiveSignals.map((sig) => (
              <div
                key={sig.id}
                className="p-4 bg-emerald-50/50 border border-emerald-200 rounded-xl space-y-1"
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-xs text-emerald-900">{sig.name}</span>
                  <span className="font-mono text-[11px] text-emerald-700 tabular-nums font-bold">
                    -{sig.scoreDeduction} pts
                  </span>
                </div>
                <p className="text-xs text-emerald-800/80 leading-relaxed">
                  {sig.description}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 5. AI Explanation Panel */}
      <div className="p-6 bg-gradient-to-br from-indigo-50/80 to-violet-50/50 border border-indigo-100 rounded-2xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-indigo-600" />
            <h4 className="font-bold text-sm text-slate-900">AI Plain-Language Risk Explanation</h4>
            {aiProvider && (
              <span className="text-[11px] text-slate-500 font-mono">
                · {aiProvider === 'gemini' ? 'Gemini 3.8 Flash' : 'Standard Analysis'}
              </span>
            )}
          </div>

          {!aiExplanation && (
            <button
              onClick={handleGenerateAiExplanation}
              disabled={isExplaining}
              className="flex items-center gap-2 px-4 py-2 text-xs font-bold text-white bg-indigo-600 hover:bg-indigo-700 rounded-xl transition-colors disabled:opacity-50 shadow-sm"
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>{isExplaining ? 'Analyzing...' : 'Generate AI Explanation'}</span>
            </button>
          )}
        </div>

        {aiExplanation ? (
          <div className="text-xs text-slate-700 leading-relaxed whitespace-pre-line border-t border-indigo-100 pt-3">
            {aiExplanation}
          </div>
        ) : (
          <p className="text-xs text-slate-600">
            Click &ldquo;Generate AI Explanation&rdquo; to receive an objective summary of these findings powered by Gemini AI.
          </p>
        )}
      </div>

      {/* 6. Disclaimer */}
      <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl text-[11px] text-slate-500 leading-relaxed">
        <strong className="text-slate-700 block mb-1">Consumer Safety Disclaimer:</strong>
        {result.disclaimer}
      </div>
    </div>
  );
};
