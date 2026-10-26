/**
 * Reusable Verification & Risk Assessment Report Component
 * Displays score gauge, risk category, evidence coverage, indicators,
 * positive signals, AI explanation, and legal disclaimers.
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
  ExternalLink,
  ChevronRight,
  FileCheck2,
} from 'lucide-react';
import { AssessmentResult, RiskIndicator, PositiveSignal } from '../types';
import { CATEGORY_META } from '../lib/riskEngine/rules';
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

  const categoryInfo = CATEGORY_META[result.category];

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
Risk Score: ${result.score}/100 (${categoryInfo.label})
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

  // Severity styling map
  const severityBadge = (sev: string) => {
    switch (sev) {
      case 'high':
        return 'text-rose-400 border-rose-900/60 bg-rose-950/40';
      case 'medium':
        return 'text-amber-400 border-amber-900/60 bg-amber-950/40';
      case 'low':
        return 'text-sky-400 border-sky-900/60 bg-sky-950/40';
      default:
        return 'text-slate-400 border-slate-800 bg-slate-900/40';
    }
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 md:p-8 space-y-8 text-slate-100 shadow-xl print:bg-white print:text-black print:border-none print:shadow-none">
      {/* 1. Header & Meta */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800/80">
        <div>
          <div className="flex items-center gap-3 text-xs text-slate-400 mb-2">
            <span className="uppercase tracking-wider font-semibold text-teal-400">
              {result.type === 'website' ? 'Website Assessment' : result.type === 'product' ? 'Product Listing Assessment' : 'Barcode & QR Assessment'}
            </span>
            <span aria-hidden="true">·</span>
            <span className="font-mono tabular-nums">{new Date(result.timestamp).toLocaleString()}</span>
            {result.isDemoMode && (
              <>
                <span aria-hidden="true">·</span>
                <span className="text-amber-400">Demo Reference</span>
              </>
            )}
          </div>
          <h2 className="text-xl md:text-2xl font-bold text-white break-words">
            {result.inputSummary.target}
          </h2>
          {result.inputSummary.brand && (
            <p className="text-sm text-slate-400 mt-1">
              Brand: <span className="text-slate-200 font-medium">{result.inputSummary.brand}</span>
              {result.inputSummary.sellerName && ` · Seller: ${result.inputSummary.sellerName}`}
              {result.inputSummary.price !== undefined && ` · Price: $${result.inputSummary.price}`}
            </p>
          )}
        </div>

        {/* Quick Actions */}
        <div className="flex items-center gap-2 shrink-0 print:hidden">
          <button
            onClick={handleCopySummary}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 rounded-lg transition-colors"
            title="Copy Report Summary"
          >
            <Copy className="w-3.5 h-3.5" />
            <span>{copied ? 'Copied' : 'Copy'}</span>
          </button>
          <button
            onClick={handlePrint}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 rounded-lg transition-colors"
            title="Print Report"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print</span>
          </button>
          {onReset && (
            <button
              onClick={onReset}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-teal-300 hover:text-teal-200 bg-teal-950/60 hover:bg-teal-900/60 border border-teal-800/60 rounded-lg transition-colors"
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
        <div className="p-6 bg-slate-950/70 border border-slate-800 rounded-xl flex flex-col justify-between">
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
            Assessed Risk Score
          </div>
          <div className="flex items-baseline gap-3">
            <span className={`text-5xl font-extrabold font-mono tabular-nums ${categoryInfo.colorClass}`}>
              {result.score}
            </span>
            <span className="text-slate-500 font-mono text-xl">/ 100</span>
          </div>

          {/* Calibrated score meter */}
          <div className="mt-4">
            <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
              <div
                className={`h-full transition-all duration-500 ${
                  result.score <= 25
                    ? 'bg-emerald-500'
                    : result.score <= 50
                    ? 'bg-sky-500'
                    : result.score <= 75
                    ? 'bg-amber-500'
                    : 'bg-rose-500'
                }`}
                style={{ width: `${Math.max(result.score, 4)}%` }}
              />
            </div>
            <div className="flex justify-between text-[10px] text-slate-500 font-mono mt-1">
              <span>0 (Low)</span>
              <span>25</span>
              <span>50</span>
              <span>75</span>
              <span>100 (High)</span>
            </div>
          </div>
        </div>

        {/* Category Card */}
        <div className="p-6 bg-slate-950/70 border border-slate-800 rounded-xl flex flex-col justify-between">
          <div>
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
              Assessed Risk Classification
            </div>
            <div className="flex items-center gap-2 mb-2">
              {result.category === 'lower' ? (
                <ShieldCheck className="w-6 h-6 text-emerald-400" />
              ) : result.category === 'moderate' ? (
                <Info className="w-6 h-6 text-sky-400" />
              ) : result.category === 'elevated' ? (
                <AlertTriangle className="w-6 h-6 text-amber-400" />
              ) : (
                <ShieldAlert className="w-6 h-6 text-rose-400" />
              )}
              <span className={`text-xl font-bold ${categoryInfo.colorClass}`}>
                {categoryInfo.label}
              </span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              {categoryInfo.description}
            </p>
          </div>
          <div className="text-[11px] text-slate-400 pt-3 border-t border-slate-800/80">
            Probability estimation · Not a certificate of authenticity
          </div>
        </div>

        {/* Evidence Coverage Card */}
        <div className="p-6 bg-slate-950/70 border border-slate-800 rounded-xl flex flex-col justify-between">
          <div>
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
              Evidence Coverage & Depth
            </div>
            <div className="flex items-baseline gap-2 mb-2">
              <span className="text-2xl font-bold text-white capitalize font-sans">
                {result.confidence}
              </span>
              <span className="text-xs text-slate-400 font-mono tabular-nums">
                ({result.confidenceScore}% data signals)
              </span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              {result.confidence === 'minimal'
                ? 'Limited attributes were provided. System avoids false penalties for missing data, but suggests further inspection.'
                : result.confidence === 'moderate'
                ? 'Sufficient baseline information available for standard heuristic evaluation.'
                : 'Robust input dataset allowing cross-verification across multiple signal dimensions.'}
            </p>
          </div>
          <div className="text-[11px] text-slate-400 pt-3 border-t border-slate-800/80">
            {result.indicators.length} warning signs · {result.positiveSignals.length} positive factors
          </div>
        </div>
      </div>

      {/* 3. Executive Summary */}
      <div className="p-4 bg-slate-950/40 border border-slate-800 rounded-lg">
        <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
          Analysis Overview
        </div>
        <p className="text-sm text-slate-200 leading-relaxed">
          {result.summary}
        </p>
      </div>

      {/* 4. Warning Indicators List */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-base font-semibold text-white flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            <span>Identified Risk Indicators ({result.indicators.length})</span>
          </h3>
          <span className="text-xs text-slate-400">
            Impact on risk score
          </span>
        </div>

        {result.indicators.length === 0 ? (
          <div className="p-4 bg-slate-950/30 border border-slate-800 rounded-lg text-sm text-slate-400 flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>No suspicious indicators detected based on the available input.</span>
          </div>
        ) : (
          <div className="space-y-3">
            {result.indicators.map((ind) => (
              <div
                key={ind.id}
                className="p-4 bg-slate-950/60 border border-slate-800/80 rounded-lg space-y-2 hover:border-slate-700 transition-colors"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className={`text-[11px] font-mono px-2 py-0.5 rounded border uppercase ${severityBadge(ind.severity)}`}>
                      {ind.severity}
                    </span>
                    <span className="font-semibold text-sm text-slate-100">{ind.name}</span>
                    <span className="text-xs text-slate-400">
                      {ind.isObserved ? '(Observed Signal)' : '(Reported Detail)'}
                    </span>
                  </div>
                  <span className="font-mono text-xs font-medium text-rose-400 tabular-nums">
                    +{ind.scoreImpact} pts
                  </span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {ind.description}
                </p>
                {ind.remedyOrPrecaution && (
                  <div className="text-xs text-teal-400/90 pt-1 flex items-start gap-1.5">
                    <span className="font-semibold text-teal-400 shrink-0">Action:</span>
                    <span>{ind.remedyOrPrecaution}</span>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 5. Positive Signals */}
      {result.positiveSignals.length > 0 && (
        <div className="space-y-4">
          <h3 className="text-base font-semibold text-white flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>Positive Reassurance Signals ({result.positiveSignals.length})</span>
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {result.positiveSignals.map((sig) => (
              <div
                key={sig.id}
                className="p-4 bg-slate-950/60 border border-emerald-950/50 rounded-lg space-y-1"
              >
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-xs text-emerald-300">{sig.name}</span>
                  <span className="font-mono text-[11px] text-emerald-400 tabular-nums">
                    -{sig.scoreDeduction} pts
                  </span>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">
                  {sig.description}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 6. Unverified Aspects & Limitations */}
      <div className="p-4 bg-slate-950/60 border border-slate-800 rounded-lg space-y-2">
        <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
          <Info className="w-3.5 h-3.5 text-sky-400" />
          <span>Information Requiring Independent Verification</span>
        </div>
        <p className="text-xs text-slate-400">
          The following dimensions could not be confirmed solely from submitted data:
        </p>
        <ul className="text-xs text-slate-300 space-y-1 pl-4 list-disc marker:text-slate-500">
          {result.unverifiedAspects.map((item, idx) => (
            <li key={idx}>{item}</li>
          ))}
        </ul>
      </div>

      {/* 7. Actionable Recommendations */}
      <div className="space-y-3">
        <h3 className="text-base font-semibold text-white flex items-center gap-2">
          <FileCheck2 className="w-4 h-4 text-teal-400" />
          <span>Recommended Precautions Before Buying</span>
        </h3>
        <div className="space-y-2">
          {result.recommendations.map((rec, idx) => (
            <div
              key={idx}
              className="p-3 bg-slate-950/50 border border-slate-800/80 rounded-lg flex items-start gap-3 text-xs text-slate-200"
            >
              <span className="font-mono font-bold text-teal-400 shrink-0 tabular-nums">
                0{idx + 1}.
              </span>
              <span>{rec}</span>
            </div>
          ))}
        </div>
      </div>

      {/* 8. AI Plain-Language Explanation Panel */}
      <div className="p-6 bg-slate-950/80 border border-teal-900/40 rounded-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-teal-400" />
            <h4 className="font-semibold text-sm text-white">AI Plain-Language Risk Assessment</h4>
            {aiProvider && (
              <span className="text-[11px] text-slate-400 font-mono">
                · {aiProvider === 'gemini' ? 'Gemini 3.8 Flash' : 'Standard Analysis'}
              </span>
            )}
          </div>

          {!aiExplanation && (
            <button
              onClick={handleGenerateAiExplanation}
              disabled={isExplaining}
              className="flex items-center gap-2 px-3.5 py-1.5 text-xs font-medium text-slate-950 bg-teal-400 hover:bg-teal-300 rounded-lg transition-colors disabled:opacity-50"
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>{isExplaining ? 'Analyzing...' : 'Generate AI Explanation'}</span>
            </button>
          )}
        </div>

        {aiExplanation ? (
          <div className="text-xs text-slate-300 leading-relaxed whitespace-pre-line border-t border-slate-800/80 pt-3">
            {aiExplanation}
          </div>
        ) : (
          <p className="text-xs text-slate-400">
            Click &ldquo;Generate AI Explanation&rdquo; to receive an objective, plain-language synthesis of these findings, what remains unverified, and what you should do next.
          </p>
        )}
      </div>

      {/* 9. Mandatory Safety Disclaimer */}
      <div className="p-4 bg-slate-950/90 border border-slate-800 rounded-lg text-[11px] text-slate-400 leading-relaxed">
        <strong className="text-slate-300 block mb-1">Consumer Safety Disclaimer:</strong>
        {result.disclaimer}
      </div>
    </div>
  );
};
