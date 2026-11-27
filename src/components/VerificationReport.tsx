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
  Cpu,
  Layers,
  Database,
  Package,
  Globe,
  Lock,
  Server,
  Clock,
  ArrowRightLeft,
  Shield,
  Store,
  UserCheck,
  ExternalLink,
  Scale,
} from 'lucide-react';
import {
  AssessmentResult,
  MarketPriceComparisonStatus,
  MarketPriceType,
  SellerVerificationStatus,
  VerificationCheckStatus,
} from '../types';
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
  const [aiModel, setAiModel] = useState<string | undefined>(result.aiExplanationModel);
  const [aiFallbackReason, setAiFallbackReason] = useState<string | undefined>(
    result.aiExplanationFallbackReason
  );
  const [isExplaining, setIsExplaining] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleGenerateAiExplanation = async () => {
    setIsExplaining(true);
    try {
      const res = await ApiService.requestAiExplanation(result);
      setAiExplanation(res.explanation);
      setAiProvider(res.provider);
      setAiModel(res.model);
      setAiFallbackReason(res.fallbackReason);
      result.aiExplanation = res.explanation;
      result.aiExplanationProvider = res.provider;
      result.aiExplanationModel = res.model;
      result.aiExplanationFallbackReason = res.fallbackReason;
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

  const verificationBadge = (status: VerificationCheckStatus) => {
    switch (status) {
      case 'verified':
        return {
          label: 'Verified',
          className: 'bg-emerald-100 text-emerald-800 border-emerald-200',
        };
      case 'suspicious':
        return {
          label: 'Suspicious',
          className: 'bg-rose-100 text-rose-800 border-rose-200',
        };
      default:
        return {
          label: 'Unavailable',
          className: 'bg-slate-200 text-slate-700 border-slate-300',
        };
    }
  };

  const sellerStatusBadge = (status: SellerVerificationStatus) => {
    switch (status) {
      case 'verified':
        return {
          label: 'Externally Retrieved',
          className: 'bg-emerald-100 text-emerald-800 border-emerald-200',
        };
      case 'mismatch_or_warning':
        return {
          label: 'Discrepancy / Warning',
          className: 'bg-rose-100 text-rose-800 border-rose-200',
        };
      case 'restricted':
        return {
          label: 'Marketplace Restricted',
          className: 'bg-amber-100 text-amber-800 border-amber-200',
        };
      case 'unverified':
        return {
          label: 'Unverified (User Input Only)',
          className: 'bg-slate-200 text-slate-700 border-slate-300',
        };
      default:
        return {
          label: 'Unavailable',
          className: 'bg-slate-200 text-slate-700 border-slate-300',
        };
    }
  };

  const marketStatusBadge = (status: MarketPriceComparisonStatus) => {
    switch (status) {
      case 'verified_comparison':
        return {
          label: 'External Market Prices Retrieved',
          className: 'bg-emerald-100 text-emerald-800 border-emerald-200',
        };
      case 'partial_or_user_reference':
        return {
          label: 'Manual Reference Only',
          className: 'bg-indigo-100 text-indigo-800 border-indigo-200',
        };
      case 'currency_mismatch':
        return {
          label: 'Currency Mismatch',
          className: 'bg-amber-100 text-amber-800 border-amber-200',
        };
      default:
        return {
          label: 'Unavailable',
          className: 'bg-slate-200 text-slate-700 border-slate-300',
        };
    }
  };

  const marketPriceTypeBadge = (priceType: MarketPriceType) => {
    switch (priceType) {
      case 'official_msrp':
        return {
          label: 'Official MSRP',
          className: 'bg-indigo-50 text-indigo-700 border-indigo-200',
        };
      case 'current_retail':
        return {
          label: 'Current Retail',
          className: 'bg-emerald-50 text-emerald-700 border-emerald-200',
        };
      case 'historical_price':
        return {
          label: 'Historical Price',
          className: 'bg-amber-50 text-amber-700 border-amber-200',
        };
      default:
        return {
          label: 'User-Entered Reference',
          className: 'bg-slate-100 text-slate-700 border-slate-200',
        };
    }
  };

  const safeHttpHref = (rawUrl?: string): string | undefined => {
    if (!rawUrl) return undefined;
    try {
      const parsed = new URL(rawUrl);
      if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
        return parsed.toString();
      }
    } catch {
      return undefined;
    }
    return undefined;
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
                <span className="text-amber-600 font-semibold">Demo Database Match (Synthetic)</span>
              </>
            )}
          </div>
          <h2 className="text-xl md:text-2xl font-extrabold text-slate-900 break-words">
            {result.inputSummary.target}
          </h2>
          {result.inputSummary.subtarget && !result.inputSummary.brand && (
            <p className="text-xs text-slate-500 mt-1">
              Detected Format: <span className="text-slate-800 font-semibold font-mono">{result.inputSummary.subtarget}</span>
            </p>
          )}
          {result.inputSummary.brand && (
            <p className="text-xs text-slate-500 mt-1">
              Brand: <span className="text-slate-800 font-semibold">{result.inputSummary.brand}</span>
              {result.inputSummary.sellerName && ` · Seller: ${result.inputSummary.sellerName}`}
              {result.inputSummary.price !== undefined &&
                ` · Price: ${result.inputSummary.currency ? `${result.inputSummary.currency} ` : '$'}${result.inputSummary.price}`}
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
          {result.scoreBreakdown && (
            <div className="text-[11px] text-slate-400 pt-3 mt-3 border-t border-slate-200 font-mono tabular-nums">
              Base +{result.scoreBreakdown.baselineScore} · Indicators +{result.scoreBreakdown.indicatorsAppliedTotal} · Signals -{result.scoreBreakdown.appliedPositiveDeduction}
              {result.scoreBreakdown.deductionsZeroedByCriticalRisk ? ' (halted by high-risk flag)' : ''}
            </div>
          )}
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

      {/* Machine Learning Phishing Classification Card (for website assessments and QR URL code scans) */}
      {(result.type === 'website' || (result.type === 'code' && Boolean(result.mlPhishingPrediction))) && (
        <div className="p-6 bg-slate-900 text-white rounded-2xl space-y-5 shadow-xl border border-slate-800">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="p-2.5 bg-indigo-500/20 text-indigo-400 rounded-xl border border-indigo-500/30">
                <Cpu className="w-5 h-5" />
              </div>
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <h4 className="font-bold text-sm text-white">Machine Learning Phishing Detector</h4>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border bg-emerald-500/20 text-emerald-300 border-emerald-500/30 font-semibold flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                    Trained on malicious_phish.csv (80,000 URLs)
                  </span>
                  {result.type === 'code' && (
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border bg-indigo-500/20 text-indigo-300 border-indigo-500/30 font-semibold">
                      QR URL Screened Safely (Not Opened)
                    </span>
                  )}
                </div>
                <p className="text-[11px] text-slate-400 mt-1">
                  Supervised Logistic Classification evaluating 18 lexical &amp; structural indicators.
                  {result.type === 'code' && result.mlPhishingPrediction?.url && (
                    <>
                      {' '}Inspected QR URL:{' '}
                      <code className="text-indigo-300 break-all">{result.mlPhishingPrediction.url}</code>
                    </>
                  )}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-3 bg-slate-800/90 px-4 py-2.5 rounded-xl border border-slate-700/80 self-start sm:self-auto">
              <div className="text-right">
                <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-medium">
                  Model Prediction
                </span>
                <span
                  className={`text-sm font-bold ${
                    (result.mlPhishingPrediction?.probability ?? result.score / 100) >= 0.5
                      ? 'text-rose-400'
                      : 'text-emerald-400'
                  }`}
                >
                  {(result.mlPhishingPrediction?.probability ?? result.score / 100) >= 0.5
                    ? 'Phishing / Malicious Risk'
                    : 'Legitimate / Benign Pattern'}
                </span>
              </div>
              <div className="text-2xl font-mono font-extrabold text-white">
                {Math.round((result.mlPhishingPrediction?.probability ?? result.score / 100) * 100)}%
              </div>
            </div>
          </div>

          {/* Model Evaluation Metrics Row */}
          {result.mlPhishingPrediction?.metrics && (
            <div className="bg-slate-950/70 p-4 rounded-xl border border-slate-800 space-y-3">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between text-xs font-semibold text-slate-300 border-b border-slate-800/80 pb-2">
                <span className="flex items-center gap-1.5 text-indigo-300 font-bold">
                  <Layers className="w-3.5 h-3.5" />
                  Test Set Evaluation Metrics (20% Holdout — 16,000 URLs)
                </span>
                <span className="text-[11px] font-mono text-slate-400">
                  Total Training Corpus: 80,000 URLs
                </span>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center">
                <div className="bg-slate-900/90 p-2.5 rounded-lg border border-slate-800">
                  <span className="text-[10px] text-slate-400 uppercase block font-medium">Accuracy</span>
                  <span className="text-base font-bold font-mono text-emerald-400">
                    {(result.mlPhishingPrediction.metrics.accuracy * 100).toFixed(1)}%
                  </span>
                </div>
                <div className="bg-slate-900/90 p-2.5 rounded-lg border border-slate-800">
                  <span className="text-[10px] text-slate-400 uppercase block font-medium">Precision</span>
                  <span className="text-base font-bold font-mono text-indigo-400">
                    {(result.mlPhishingPrediction.metrics.precision * 100).toFixed(1)}%
                  </span>
                </div>
                <div className="bg-slate-900/90 p-2.5 rounded-lg border border-slate-800">
                  <span className="text-[10px] text-slate-400 uppercase block font-medium">Recall</span>
                  <span className="text-base font-bold font-mono text-violet-400">
                    {(result.mlPhishingPrediction.metrics.recall * 100).toFixed(1)}%
                  </span>
                </div>
                <div className="bg-slate-900/90 p-2.5 rounded-lg border border-slate-800">
                  <span className="text-[10px] text-slate-400 uppercase block font-medium">F1 Score</span>
                  <span className="text-base font-bold font-mono text-amber-400">
                    {(result.mlPhishingPrediction.metrics.f1Score * 100).toFixed(1)}%
                  </span>
                </div>
              </div>

              {/* Confusion Matrix Detail */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] pt-1 text-slate-400 font-mono">
                <div className="bg-slate-900/60 px-2.5 py-1.5 rounded border border-slate-800/70">
                  <span className="text-emerald-400 font-bold block">True Positives:</span>
                  <span>{result.mlPhishingPrediction.metrics.confusionMatrix.truePositives.toLocaleString()} (Caught)</span>
                </div>
                <div className="bg-slate-900/60 px-2.5 py-1.5 rounded border border-slate-800/70">
                  <span className="text-indigo-400 font-bold block">True Negatives:</span>
                  <span>{result.mlPhishingPrediction.metrics.confusionMatrix.trueNegatives.toLocaleString()} (Safe)</span>
                </div>
                <div className="bg-slate-900/60 px-2.5 py-1.5 rounded border border-slate-800/70">
                  <span className="text-amber-400 font-bold block">False Positives:</span>
                  <span>{result.mlPhishingPrediction.metrics.confusionMatrix.falsePositives.toLocaleString()} (Benign Flagged)</span>
                </div>
                <div className="bg-slate-900/60 px-2.5 py-1.5 rounded border border-slate-800/70">
                  <span className="text-rose-400 font-bold block">False Negatives:</span>
                  <span>{result.mlPhishingPrediction.metrics.confusionMatrix.falseNegatives.toLocaleString()} (Missed)</span>
                </div>
              </div>
            </div>
          )}

          {/* Model Flagged URL Indicators */}
          {result.mlPhishingPrediction?.indicatorsFlagged && result.mlPhishingPrediction.indicatorsFlagged.length > 0 && (
            <div className="space-y-1.5">
              <span className="text-xs font-bold text-amber-300 block">
                Model Flagged Suspicious Structural Features:
              </span>
              <div className="flex flex-wrap gap-1.5">
                {result.mlPhishingPrediction.indicatorsFlagged.map((flag, idx) => (
                  <span
                    key={idx}
                    className="text-[11px] bg-slate-800 text-slate-200 px-2.5 py-1 rounded-md border border-slate-700 font-medium"
                  >
                    • {flag}
                  </span>
                ))}
              </div>
            </div>
          )}

          <div className="pt-2 border-t border-slate-800 text-xs text-slate-300 grid grid-cols-1 md:grid-cols-2 gap-3">
            <div className="bg-slate-800/50 p-3 rounded-xl border border-slate-800/80">
              <span className="font-bold text-indigo-300 block mb-1">Architecture Separation:</span>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                This prediction evaluates URL structural deception (brand lookalikes, TLD abuse, subdomain nesting). It does <strong>not</strong> prove whether physical items sold are counterfeit or authentic.
              </p>
            </div>
            <div className="bg-slate-800/50 p-3 rounded-xl border border-slate-800/80">
              <span className="font-bold text-indigo-300 block mb-1">Dataset &amp; Weights Artifact:</span>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                Trained on <code>malicious_phish.csv</code>. Evaluated across 16,000 holdout URLs with zero data leakage. Model weights saved in <code>ml/trained_model.json</code>.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Live Domain Verification Card (Website Checker real-time DNS, TLS, RDAP, Redirects & Threat Intel) */}
      {result.type === 'website' && result.domainVerification && (
        <div className="p-6 bg-slate-50 border border-slate-200 rounded-2xl space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-200">
            <div className="flex items-center gap-2.5">
              <div className="p-2 bg-indigo-100 text-indigo-700 rounded-xl border border-indigo-200">
                <Globe className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-slate-900">
                  Live Domain Verification
                </h3>
                <p className="text-[11px] text-slate-500">
                  Host: <span className="font-mono font-semibold text-slate-700">{result.domainVerification.hostname}</span>
                  {' · '}Apex: <span className="font-mono font-semibold text-slate-700">{result.domainVerification.apexDomain}</span>
                  {result.domainVerification.cached ? ' · Cached (5m TTL)' : ' · Live Check'}
                </p>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-1.5 text-[10px] font-bold">
              <span className="px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 border border-emerald-200">
                Verified
              </span>
              <span className="px-2 py-0.5 rounded-full bg-rose-100 text-rose-800 border border-rose-200">
                Suspicious
              </span>
              <span className="px-2 py-0.5 rounded-full bg-slate-200 text-slate-700 border border-slate-300">
                Unavailable
              </span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* 1. DNS Resolution */}
            {(() => {
              const badge = verificationBadge(result.domainVerification.dns.status);
              return (
                <div className="p-4 bg-white border border-slate-200 rounded-xl space-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2 text-xs font-bold text-slate-900">
                      <Server className="w-4 h-4 text-indigo-600" />
                      <span>DNS Resolution</span>
                    </div>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${badge.className}`}>
                      {badge.label}
                    </span>
                  </div>
                  {result.domainVerification.dns.exists ? (
                    <div className="text-xs text-slate-700 space-y-1">
                      <div>
                        Domain exists in DNS and resolves cleanly to public IP(s):
                      </div>
                      <div className="font-mono text-[11px] text-slate-800 bg-slate-50 px-2.5 py-1.5 rounded-lg border border-slate-200 break-all">
                        {result.domainVerification.dns.resolvedIps.slice(0, 4).join(', ')}
                      </div>
                    </div>
                  ) : (
                    <p className="text-xs text-rose-700">
                      {result.domainVerification.dns.error || 'No public DNS records returned.'}
                    </p>
                  )}
                </div>
              );
            })()}

            {/* 2. SSL/TLS Certificate */}
            {(() => {
              const tls = result.domainVerification.tls;
              const badge = verificationBadge(tls.status);
              return (
                <div className="p-4 bg-white border border-slate-200 rounded-xl space-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2 text-xs font-bold text-slate-900">
                      <Lock className="w-4 h-4 text-indigo-600" />
                      <span>SSL/TLS Certificate</span>
                    </div>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${badge.className}`}>
                      {badge.label}
                    </span>
                  </div>
                  {tls.checked ? (
                    <div className="grid grid-cols-2 gap-x-3 gap-y-1.5 text-[11px]">
                      <div>
                        <span className="text-slate-400 uppercase font-bold text-[10px] block">Trust Status</span>
                        <span className={`font-semibold ${tls.isTrusted && !tls.isExpired && !tls.isNotYetValid ? 'text-emerald-700' : 'text-rose-700'}`}>
                          {tls.isExpired
                            ? 'Expired Certificate'
                            : tls.isNotYetValid
                              ? 'Not Yet Valid'
                              : tls.isTrusted
                                ? `Trusted (${tls.protocol || 'TLS'})`
                                : `Untrusted${tls.authorizationError ? `: ${tls.authorizationError}` : ''}`}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-400 uppercase font-bold text-[10px] block">Issuer / CN</span>
                        <span className="text-slate-700 font-medium break-words">
                          {tls.issuer || 'Unknown CA'}
                          {tls.subjectCN ? ` · ${tls.subjectCN}` : ''}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-400 uppercase font-bold text-[10px] block">Valid From</span>
                        <span className="font-mono text-slate-700">
                          {tls.validFrom ? new Date(tls.validFrom).toISOString().slice(0, 10) : 'Unavailable'}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-400 uppercase font-bold text-[10px] block">Expires</span>
                        <span className={`font-mono ${tls.isExpired ? 'text-rose-700 font-bold' : 'text-slate-700'}`}>
                          {tls.validTo ? new Date(tls.validTo).toISOString().slice(0, 10) : 'Unavailable'}
                          {tls.daysRemaining !== undefined ? ` (${tls.daysRemaining}d)` : ''}
                        </span>
                      </div>
                    </div>
                  ) : (
                    <p className="text-xs text-slate-600">
                      {tls.error || 'TLS certificate inspection unavailable.'}
                    </p>
                  )}
                </div>
              );
            })()}

            {/* 3. RDAP Domain Registration & Age */}
            {(() => {
              const rdap = result.domainVerification.rdap;
              const badge = verificationBadge(rdap.status);
              return (
                <div className="p-4 bg-white border border-slate-200 rounded-xl space-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2 text-xs font-bold text-slate-900">
                      <Clock className="w-4 h-4 text-indigo-600" />
                      <span>Domain Registration (RDAP)</span>
                    </div>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${badge.className}`}>
                      {badge.label}
                    </span>
                  </div>
                  {rdap.registrationDate ? (
                    <div className="grid grid-cols-2 gap-x-3 gap-y-1.5 text-[11px]">
                      <div>
                        <span className="text-slate-400 uppercase font-bold text-[10px] block">Registered On</span>
                        <span className="font-mono text-slate-800 font-semibold">
                          {new Date(rdap.registrationDate).toISOString().slice(0, 10)}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-400 uppercase font-bold text-[10px] block">Domain Age</span>
                        <span className={`font-mono font-bold ${(rdap.domainAgeDays ?? 0) < 180 ? 'text-rose-700' : 'text-slate-800'}`}>
                          {rdap.domainAgeDays !== undefined
                            ? rdap.domainAgeDays >= 365
                              ? `${Math.floor(rdap.domainAgeDays / 365)}y ${rdap.domainAgeDays % 365}d (${rdap.domainAgeDays.toLocaleString()}d)`
                              : `${rdap.domainAgeDays} days`
                            : 'Unavailable'}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-400 uppercase font-bold text-[10px] block">Registrar</span>
                        <span className="text-slate-700 break-words">
                          {rdap.registrar || 'Not disclosed by RDAP'}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-400 uppercase font-bold text-[10px] block">RDAP Expires</span>
                        <span className="font-mono text-slate-700">
                          {rdap.expirationDate ? new Date(rdap.expirationDate).toISOString().slice(0, 10) : 'Not disclosed'}
                        </span>
                      </div>
                    </div>
                  ) : (
                    <p className="text-xs text-slate-600">
                      {rdap.error || 'RDAP registration date unavailable.'}
                    </p>
                  )}
                </div>
              );
            })()}

            {/* 4. Redirect & HTTP-to-HTTPS Inspection */}
            {(() => {
              const redir = result.domainVerification.redirects;
              const badge = verificationBadge(redir.status);
              return (
                <div className="p-4 bg-white border border-slate-200 rounded-xl space-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2 text-xs font-bold text-slate-900">
                      <ArrowRightLeft className="w-4 h-4 text-indigo-600" />
                      <span>Redirects &amp; Protocol Upgrade</span>
                    </div>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${badge.className}`}>
                      {badge.label}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-700 space-y-1">
                    <div>
                      <span className="font-semibold">Hops:</span> {redir.hopCount}
                      {redir.finalStatusCode ? ` · Final HTTP ${redir.finalStatusCode}` : ''}
                      {redir.httpToHttpsUpgrade && (
                        <span className="ml-1.5 text-emerald-700 font-bold">· HTTP → HTTPS Upgraded</span>
                      )}
                    </div>
                    <div className="font-mono text-[10px] bg-slate-50 p-2 rounded border border-slate-200 break-all">
                      Final URL: {redir.finalUrl}
                    </div>
                    {redir.suspiciousReasons.length > 0 && (
                      <div className="text-rose-700 font-medium">
                        {redir.suspiciousReasons.join('; ')}
                      </div>
                    )}
                    {redir.error && !redir.suspiciousDestination && (
                      <div className="text-slate-500">
                        {redir.error}
                      </div>
                    )}
                  </div>
                </div>
              );
            })()}
          </div>

          {/* 5. Threat Intelligence Feeds Row */}
          {(() => {
            const threat = result.domainVerification.threatIntel;
            const totalFeeds = threat.providers.length;
            const checkedFeeds = threat.providers.filter((p) => p.checked).length;
            const hasUnavailableFeeds = threat.providers.some((p) => p.status === 'unavailable');
            const badge = verificationBadge(threat.status);
            const badgeClassName =
              threat.status === 'verified' && hasUnavailableFeeds
                ? 'bg-indigo-100 text-indigo-800 border-indigo-200'
                : badge.className;
            const badgeText = threat.listed
              ? 'Flagged'
              : threat.status === 'verified'
                ? hasUnavailableFeeds
                  ? `Partial (${checkedFeeds}/${totalFeeds} Checked)`
                  : `Not Listed (${checkedFeeds}/${totalFeeds} Checked)`
                : badge.label;
            return (
              <div className="p-4 bg-white border border-slate-200 rounded-xl space-y-2.5">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 text-xs font-bold text-slate-900">
                    <Shield className="w-4 h-4 text-indigo-600" />
                    <span>Phishing &amp; Malicious Threat Intelligence</span>
                  </div>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${badgeClassName}`}>
                    {badgeText}
                  </span>
                </div>

                {threat.listed && threat.matches.length > 0 && (
                  <div className="p-2.5 bg-rose-50 border border-rose-200 rounded-lg text-xs text-rose-800 font-medium">
                    {threat.matches.map((m, idx) => (
                      <div key={idx}>
                        <strong>{m.provider}:</strong> {m.threatType} ({m.reference || 'Listed'})
                      </div>
                    ))}
                  </div>
                )}

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px]">
                  {threat.providers.map((p, idx) => (
                    <div
                      key={idx}
                      className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 flex flex-col gap-0.5"
                    >
                      <div className="flex items-center justify-between gap-1">
                        <span className="font-bold text-slate-800">{p.provider}</span>
                        <span
                          className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                            p.status === 'flagged'
                              ? 'bg-rose-100 text-rose-700'
                              : p.status === 'clean'
                                ? 'bg-emerald-100 text-emerald-700'
                                : 'bg-slate-200 text-slate-600'
                          }`}
                        >
                          {p.status === 'flagged' ? 'Flagged' : p.status === 'clean' ? 'Not Listed' : 'Unavailable'}
                        </span>
                      </div>
                      {p.detail && <span className="text-[10px] text-slate-500">{p.detail}</span>}
                    </div>
                  ))}
                </div>
              </div>
            );
          })()}

          <div className="p-3 bg-amber-50 border border-amber-200 rounded-xl text-[11px] text-amber-900">
            <strong>Security Limitation:</strong> A valid SSL/TLS certificate or an older domain registration date does <strong>not</strong> make a website safe—phishing campaigns frequently abuse HTTPS and compromised or aged domains.
          </div>
        </div>
      )}

      {/* Machine Learning Product Listing Classification Card & Scope Breakdown (for product assessments) */}
      {result.type === 'product' && result.mlProductPrediction && (
        <div className="space-y-4">
          {/* Explicit 3-Way Scope Distinction Banner */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
              <div className="text-[10px] font-bold uppercase tracking-wider text-indigo-600">
                1. Listing URL Phishing Risk
              </div>
              <div className="text-sm font-bold text-slate-900">
                {result.mlPhishingPrediction
                  ? `${result.mlPhishingPrediction.isPhishing ? 'Elevated Phishing Risk' : 'Low Phishing Risk'} (${Math.round(result.mlPhishingPrediction.probability * 100)}%)`
                  : 'Not Evaluated (No URL Provided)'}
              </div>
              <p className="text-[11px] text-slate-500 leading-relaxed">
                Evaluated by the 80,000-URL website phishing model for link/domain deception only.
              </p>
            </div>

            <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
              <div className="text-[10px] font-bold uppercase tracking-wider text-violet-600">
                2. Suspicious Listing Risk
              </div>
              <div className="text-sm font-bold text-slate-900">
                {result.mlProductPrediction.isHighRisk ? 'Suspicious Metadata Signals' : 'Lower-Risk Metadata Pattern'} ({Math.round(result.mlProductPrediction.probability * 100)}%)
              </div>
              <p className="text-[11px] text-slate-500 leading-relaxed">
                Evaluates pricing variance, seller handle/rating, return guarantees, and listing copy.
              </p>
            </div>

            <div className="p-4 bg-amber-50/70 border border-amber-200 rounded-xl space-y-1">
              <div className="text-[10px] font-bold uppercase tracking-wider text-amber-700">
                3. Physical Product Authenticity
              </div>
              <div className="text-sm font-bold text-amber-900">
                Not Verifiable Online
              </div>
              <p className="text-[11px] text-amber-800/80 leading-relaxed">
                Neither ML model inspects physical goods, packaging seals, or genuine serial ownership.
              </p>
            </div>
          </div>

          {/* Connected Website Phishing ML Result for Listing URL */}
          {result.mlPhishingPrediction && (
            <div className="p-5 bg-slate-900 text-white rounded-2xl border border-slate-800 space-y-3 shadow-md">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-indigo-500/20 text-indigo-400 rounded-xl border border-indigo-500/30">
                    <Cpu className="w-4 h-4" />
                  </div>
                  <div>
                    <h4 className="font-bold text-sm text-white">
                      Listing URL Phishing Detection (Website Logistic Regression)
                    </h4>
                    <p className="text-[11px] text-slate-400 font-mono break-all">
                      URL: {result.mlPhishingPrediction.url}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-3 bg-slate-800/90 px-3.5 py-2 rounded-xl border border-slate-700/80 self-start sm:self-auto">
                  <span
                    className={`text-xs font-bold ${
                      result.mlPhishingPrediction.isPhishing ? 'text-rose-400' : 'text-emerald-400'
                    }`}
                  >
                    {result.mlPhishingPrediction.isPhishing ? 'Phishing Risk' : 'Benign URL Pattern'}
                  </span>
                  <span className="text-lg font-mono font-extrabold text-white">
                    {Math.round(result.mlPhishingPrediction.probability * 100)}%
                  </span>
                </div>
              </div>
              {result.mlPhishingPrediction.indicatorsFlagged.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {result.mlPhishingPrediction.indicatorsFlagged.map((flag, idx) => (
                    <span
                      key={idx}
                      className="text-[11px] bg-slate-800 text-slate-200 px-2.5 py-1 rounded-md border border-slate-700"
                    >
                      • {flag}
                    </span>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Product Listing ML Classifier Card */}
          <div className="p-6 bg-slate-900 text-white rounded-2xl space-y-5 shadow-xl border border-slate-800">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="p-2.5 bg-violet-500/20 text-violet-400 rounded-xl border border-violet-500/30">
                  <Cpu className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <h4 className="font-bold text-sm text-white">Machine Learning Product Listing Classifier</h4>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border bg-emerald-500/20 text-emerald-300 border-emerald-500/30 font-semibold flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                      {(result.mlProductPrediction.totalDatasetRows ?? result.mlProductPrediction.trainingSamples ?? 0).toLocaleString()} listings
                    </span>
                    {result.mlProductPrediction.isSyntheticDataset && (
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border bg-amber-500/20 text-amber-300 border-amber-500/30 font-semibold">
                        Synthetic Corpus
                      </span>
                    )}
                  </div>
                  <p className="text-[11px] text-slate-400 mt-1">
                    {result.mlProductPrediction.modelType} evaluating 14 pricing, seller, return-policy &amp; content markers.
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-3 bg-slate-800/90 px-4 py-2.5 rounded-xl border border-slate-700/80 self-start sm:self-auto">
                <div className="text-right">
                  <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-medium">
                    Listing Risk Prediction
                  </span>
                  <span
                    className={`text-sm font-bold ${
                      result.mlProductPrediction.probability >= 0.5 ? 'text-rose-400' : 'text-emerald-400'
                    }`}
                  >
                    {result.mlProductPrediction.probability >= 0.5
                      ? 'Suspicious Listing Pattern'
                      : 'Lower-Risk Listing Pattern'}
                  </span>
                </div>
                <div className="text-2xl font-mono font-extrabold text-white">
                  {Math.round(result.mlProductPrediction.probability * 100)}%
                </div>
              </div>
            </div>

            {result.mlProductPrediction.isSyntheticDataset && (
              <div className="flex items-start gap-2 bg-amber-950/50 border border-amber-500/30 rounded-xl p-3 text-[11px] text-amber-200 leading-relaxed">
                <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                <span>
                  <strong>Synthetic Training Disclosure:</strong> This classifier was trained on synthetic records (<code className="text-amber-100">{result.mlProductPrediction.datasetName}</code>). Reported metrics measure fit to synthetic rules and do <strong>not</strong> represent verified real-world counterfeit detection performance.
                </span>
              </div>
            )}

            {result.mlProductPrediction.metrics && (
              <div className="bg-slate-950/70 p-4 rounded-xl border border-slate-800 space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between text-xs font-semibold text-slate-300 border-b border-slate-800/80 pb-2">
                  <span className="flex items-center gap-1.5 text-violet-300 font-bold">
                    <Layers className="w-3.5 h-3.5" />
                    {result.mlProductPrediction.isSyntheticDataset
                      ? `Synthetic-Data Holdout Metrics (${(result.mlProductPrediction.samplesTested ?? 0).toLocaleString()} Test Listings)`
                      : `Holdout Evaluation Metrics (${(result.mlProductPrediction.samplesTested ?? 0).toLocaleString()} Test Listings)`}
                  </span>
                  <span className="text-[11px] font-mono text-slate-400">
                    Train: {(result.mlProductPrediction.trainingSamples ?? 0).toLocaleString()} · Test: {(result.mlProductPrediction.samplesTested ?? 0).toLocaleString()}
                    {result.mlProductPrediction.metrics.rocAuc !== undefined
                      ? ` · ROC-AUC: ${(result.mlProductPrediction.metrics.rocAuc * 100).toFixed(2)}%`
                      : ''}
                    {result.mlProductPrediction.metrics.prAuc !== undefined
                      ? ` · PR-AUC: ${(result.mlProductPrediction.metrics.prAuc * 100).toFixed(2)}%`
                      : ''}
                  </span>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center">
                  <div className="bg-slate-900/90 p-2.5 rounded-lg border border-slate-800">
                    <span className="text-[10px] text-slate-400 uppercase block font-medium">Accuracy</span>
                    <span className="text-base font-bold font-mono text-emerald-400">
                      {(result.mlProductPrediction.metrics.accuracy * 100).toFixed(2)}%
                    </span>
                  </div>
                  <div className="bg-slate-900/90 p-2.5 rounded-lg border border-slate-800">
                    <span className="text-[10px] text-slate-400 uppercase block font-medium">Precision</span>
                    <span className="text-base font-bold font-mono text-indigo-400">
                      {(result.mlProductPrediction.metrics.precision * 100).toFixed(2)}%
                    </span>
                  </div>
                  <div className="bg-slate-900/90 p-2.5 rounded-lg border border-slate-800">
                    <span className="text-[10px] text-slate-400 uppercase block font-medium">Recall</span>
                    <span className="text-base font-bold font-mono text-violet-400">
                      {(result.mlProductPrediction.metrics.recall * 100).toFixed(2)}%
                    </span>
                  </div>
                  <div className="bg-slate-900/90 p-2.5 rounded-lg border border-slate-800">
                    <span className="text-[10px] text-slate-400 uppercase block font-medium">F1 Score</span>
                    <span className="text-base font-bold font-mono text-amber-400">
                      {(result.mlProductPrediction.metrics.f1Score * 100).toFixed(2)}%
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] pt-1 text-slate-400 font-mono">
                  <div className="bg-slate-900/60 px-2.5 py-1.5 rounded border border-slate-800/70">
                    <span className="text-emerald-400 font-bold block">True Positives:</span>
                    <span>{result.mlProductPrediction.metrics.confusionMatrix.truePositives.toLocaleString()} (Caught)</span>
                  </div>
                  <div className="bg-slate-900/60 px-2.5 py-1.5 rounded border border-slate-800/70">
                    <span className="text-indigo-400 font-bold block">True Negatives:</span>
                    <span>{result.mlProductPrediction.metrics.confusionMatrix.trueNegatives.toLocaleString()} (Safe)</span>
                  </div>
                  <div className="bg-slate-900/60 px-2.5 py-1.5 rounded border border-slate-800/70">
                    <span className="text-amber-400 font-bold block">False Positives:</span>
                    <span>{result.mlProductPrediction.metrics.confusionMatrix.falsePositives.toLocaleString()} (Flagged)</span>
                  </div>
                  <div className="bg-slate-900/60 px-2.5 py-1.5 rounded border border-slate-800/70">
                    <span className="text-rose-400 font-bold block">False Negatives:</span>
                    <span>{result.mlProductPrediction.metrics.confusionMatrix.falseNegatives.toLocaleString()} (Missed)</span>
                  </div>
                </div>
              </div>
            )}

            {result.mlProductPrediction.indicatorsFlagged && result.mlProductPrediction.indicatorsFlagged.length > 0 && (
              <div className="space-y-1.5">
                <span className="text-xs font-bold text-amber-300 block">
                  Model Flagged Listing Risk Features:
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {result.mlProductPrediction.indicatorsFlagged.map((flag, idx) => (
                    <span
                      key={idx}
                      className="text-[11px] bg-slate-800 text-slate-200 px-2.5 py-1 rounded-md border border-slate-700 font-medium"
                    >
                      • {flag}
                    </span>
                  ))}
                </div>
              </div>
            )}

            <div className="pt-2 border-t border-slate-800 text-xs text-slate-300 grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="bg-slate-800/50 p-3 rounded-xl border border-slate-800/80">
                <span className="font-bold text-violet-300 block mb-1">Anti-Bias &amp; Physical Scope:</span>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  {result.mlProductPrediction.disclaimer}
                </p>
              </div>
              <div className="bg-slate-800/50 p-3 rounded-xl border border-slate-800/80">
                <span className="font-bold text-violet-300 block mb-1">Dataset &amp; Weights Artifact:</span>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  Dataset: <code>{result.mlProductPrediction.datasetName}</code>. Model weights saved in <code>src/ml_product_model.json</code>.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Seller Verification Card (Product Checker: clearly distinguishes User-Provided vs Externally Retrieved seller data) */}
      {result.type === 'product' && result.sellerVerification && (() => {
        const sv = result.sellerVerification;
        const badge = sellerStatusBadge(sv.status);
        const safeProfileUrl = safeHttpHref(sv.retrieved.sellerProfileUrl);
        const authLabel =
          sv.retrieved.authorizedSellerStatus === 'confirmed_official'
            ? 'Confirmed Official Storefront'
            : sv.retrieved.authorizedSellerStatus === 'third_party_unverified'
              ? 'Third-Party (Authorization Unverified)'
              : 'Unavailable';

        return (
          <div className="p-6 bg-slate-50 border border-slate-200 rounded-2xl space-y-5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-200">
              <div className="flex items-center gap-2.5">
                <div className="p-2 bg-violet-100 text-violet-700 rounded-xl border border-violet-200">
                  <Store className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-slate-900">
                    Seller Verification
                  </h3>
                  <p className="text-[11px] text-slate-500">
                    {sv.marketplace ? `Source: ${sv.marketplace}` : 'Source: Listing Inputs'}
                    {sv.cached ? ' · Cached Result' : ''}
                    {sv.statusCode ? ` · HTTP ${sv.statusCode}` : ''}
                  </p>
                </div>
              </div>

              <span className={`inline-flex items-center gap-1.5 text-[11px] font-bold px-2.5 py-1 rounded-full border self-start sm:self-auto ${badge.className}`}>
                <UserCheck className="w-3.5 h-3.5" />
                {badge.label}
              </span>
            </div>

            <p className="text-xs text-slate-700 leading-relaxed bg-white p-3.5 rounded-xl border border-slate-200">
              {sv.message}
            </p>

            {/* Clear Side-by-Side Distinction: User-Provided vs Externally Retrieved */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Column 1: User-Provided Inputs */}
              <div className="p-4 bg-white border border-slate-200 rounded-xl space-y-2.5">
                <div className="flex items-center justify-between border-b border-slate-100 pb-2">
                  <span className="text-xs font-bold text-slate-900">User-Provided Details</span>
                  <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200">
                    Unverified Input
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-x-3 gap-y-2 text-[11px]">
                  <div>
                    <span className="text-slate-400 uppercase font-bold text-[10px] block">Seller Name</span>
                    <span className="font-semibold text-slate-800 break-words">
                      {sv.userProvided.sellerName || 'Not provided'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 uppercase font-bold text-[10px] block">Entered Rating</span>
                    <span className="font-mono text-slate-800">
                      {sv.userProvided.sellerRating !== undefined ? `${sv.userProvided.sellerRating} / 5` : 'Not provided'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 uppercase font-bold text-[10px] block">Return Policy Input</span>
                    <span className="text-slate-700 capitalize">
                      {sv.userProvided.returnPolicyStatus.replace('_', ' ')}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 uppercase font-bold text-[10px] block">Platform Context</span>
                    <span className="text-slate-700">
                      {sv.userProvided.sourcePlatform || 'Not specified'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Column 2: Externally Retrieved Metadata */}
              <div className="p-4 bg-white border border-slate-200 rounded-xl space-y-2.5">
                <div className="flex items-center justify-between border-b border-slate-100 pb-2">
                  <span className="text-xs font-bold text-slate-900">Externally Retrieved Details</span>
                  <span
                    className={`text-[10px] font-semibold px-2 py-0.5 rounded border ${
                      sv.source !== 'none'
                        ? 'bg-indigo-50 text-indigo-700 border-indigo-200'
                        : 'bg-slate-100 text-slate-600 border-slate-200'
                    }`}
                  >
                    {sv.source === 'official_merchant_page'
                      ? 'Official Merchant Page'
                      : sv.source === 'public_metadata'
                        ? 'Public Structured Metadata'
                        : sv.source === 'authorized_api'
                          ? 'Authorized API'
                          : 'Unavailable'}
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-x-3 gap-y-2 text-[11px]">
                  <div>
                    <span className="text-slate-400 uppercase font-bold text-[10px] block">Seller Name</span>
                    <span className="font-semibold text-slate-900 break-words">
                      {sv.retrieved.sellerName || 'Unavailable'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 uppercase font-bold text-[10px] block">Seller Rating</span>
                    <span className="font-mono text-slate-800">
                      {sv.retrieved.sellerRating !== undefined
                        ? `${sv.retrieved.sellerRating} / 5${
                            sv.retrieved.sellerRatingCount !== undefined
                              ? ` (${sv.retrieved.sellerRatingCount.toLocaleString()} ratings)`
                              : ''
                          }`
                        : 'Unavailable'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 uppercase font-bold text-[10px] block">Account Age</span>
                    <span className="text-slate-700 font-mono">
                      {sv.retrieved.sellerAccountAgeDays !== undefined
                        ? sv.retrieved.sellerAccountAgeDays >= 365
                          ? `${Math.floor(sv.retrieved.sellerAccountAgeDays / 365)}y (${sv.retrieved.foundingDate?.slice(0, 10)})`
                          : `${sv.retrieved.sellerAccountAgeDays} days (${sv.retrieved.foundingDate?.slice(0, 10)})`
                        : 'Unavailable'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 uppercase font-bold text-[10px] block">Authorized Seller</span>
                    <span
                      className={`font-semibold ${
                        sv.retrieved.authorizedSellerStatus === 'confirmed_official'
                          ? 'text-emerald-700'
                          : sv.retrieved.authorizedSellerStatus === 'third_party_unverified'
                            ? 'text-amber-700'
                            : 'text-slate-500'
                      }`}
                    >
                      {authLabel}
                    </span>
                  </div>
                  <div className="col-span-2">
                    <span className="text-slate-400 uppercase font-bold text-[10px] block">Business Registration</span>
                    <span className="text-slate-700 break-words">
                      {sv.retrieved.businessRegistration || 'Unavailable'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 uppercase font-bold text-[10px] block">Seller Profile URL</span>
                    {safeProfileUrl ? (
                      <a
                        href={safeProfileUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-indigo-600 hover:text-indigo-800 font-mono break-all underline"
                      >
                        <span>View Profile</span>
                        <ExternalLink className="w-3 h-3 shrink-0" />
                      </a>
                    ) : (
                      <span className="text-slate-500">Unavailable</span>
                    )}
                  </div>
                  <div>
                    <span className="text-slate-400 uppercase font-bold text-[10px] block">Retrieved Return Policy</span>
                    <span className="text-slate-700">
                      {sv.retrieved.returnPolicySummary ||
                        (sv.retrieved.returnPolicyStatus !== 'unknown'
                          ? sv.retrieved.returnPolicyStatus.replace('_', ' ')
                          : 'Unavailable')}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Mismatches, Discrepancies & Suspicious Handle Findings */}
            {(sv.comparison.inconsistencies.length > 0 ||
              sv.comparison.suspiciousHandleFlags.length > 0 ||
              sv.comparison.warnings.length > 0) && (
              <div className="space-y-2">
                {sv.comparison.inconsistencies.map((inc, idx) => (
                  <div
                    key={`inc-${idx}`}
                    className="p-3 bg-rose-50 border border-rose-200 rounded-xl text-xs text-rose-800 font-medium flex items-start gap-2"
                  >
                    <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
                    <span>{inc}</span>
                  </div>
                ))}
                {sv.comparison.suspiciousHandleFlags.map((flag, idx) => (
                  <div
                    key={`flag-${idx}`}
                    className="p-3 bg-amber-50 border border-amber-200 rounded-xl text-xs text-amber-900 font-medium flex items-start gap-2"
                  >
                    <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
                    <span>{flag}</span>
                  </div>
                ))}
                {sv.comparison.warnings.map((warn, idx) => (
                  <div
                    key={`warn-${idx}`}
                    className="p-2.5 bg-white border border-slate-200 rounded-xl text-[11px] text-slate-600"
                  >
                    • {warn}
                  </div>
                ))}
              </div>
            )}

            <div className="p-3 bg-amber-50 border border-amber-200 rounded-xl text-[11px] text-amber-900">
              <strong>Transparency Notice:</strong> Unavailable or restricted seller details do <strong>not</strong> indicate fraud, and product review scores are never substituted for seller ratings. Official seller authorization is shown only when confirmed by an official source.
            </div>
          </div>
        );
      })()}

      {/* Market Price Comparison Card (Product Checker: compares listed price vs verified external market / MSRP quotes) */}
      {result.type === 'product' && result.marketPriceComparison && (() => {
        const mpc = result.marketPriceComparison;
        const badge = marketStatusBadge(mpc.status);
        const stats = mpc.stats;

        return (
          <div className="p-6 bg-slate-50 border border-slate-200 rounded-2xl space-y-5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-200">
              <div className="flex items-center gap-2.5">
                <div className="p-2 bg-indigo-100 text-indigo-700 rounded-xl border border-indigo-200">
                  <Scale className="w-4 h-4" />
                </div>
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <h3 className="text-sm font-bold text-slate-900">
                      Market Price Comparison
                    </h3>
                    {mpc.indianMarketPrioritized && (
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-orange-50 text-orange-800 border border-orange-200">
                        India (INR) Prioritized
                      </span>
                    )}
                    {mpc.inferredCondition !== 'unknown' && (
                      <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-slate-200 text-slate-700 capitalize">
                        Condition: {mpc.inferredCondition}
                      </span>
                    )}
                  </div>
                  <p className="text-[11px] text-slate-500 mt-0.5">
                    Target Currency: <span className="font-mono font-semibold text-slate-700">{mpc.targetCurrency}</span>
                    {mpc.queriedSources.length > 0 && ` · Checked: ${mpc.queriedSources.join(', ')}`}
                    {mpc.cached ? ' · Cached Result' : ''}
                  </p>
                </div>
              </div>

              <span className={`inline-flex items-center gap-1.5 text-[11px] font-bold px-2.5 py-1 rounded-full border self-start sm:self-auto ${badge.className}`}>
                {badge.label}
              </span>
            </div>

            <p className="text-xs text-slate-700 leading-relaxed bg-white p-3.5 rounded-xl border border-slate-200">
              {mpc.message}
            </p>

            {/* Summary Stats Grid (Min / Median / Max / % Difference) */}
            {stats && (
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="p-3.5 bg-white border border-slate-200 rounded-xl">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">
                    Minimum Market Price
                  </span>
                  <span className="text-base font-extrabold font-mono text-slate-900 mt-0.5 block">
                    {stats.minPrice !== undefined ? `${stats.currency} ${stats.minPrice.toLocaleString()}` : 'Unavailable'}
                  </span>
                </div>
                <div className="p-3.5 bg-white border border-slate-200 rounded-xl">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">
                    Median Market Price
                  </span>
                  <span className="text-base font-extrabold font-mono text-indigo-700 mt-0.5 block">
                    {stats.medianPrice !== undefined ? `${stats.currency} ${stats.medianPrice.toLocaleString()}` : 'Unavailable'}
                  </span>
                </div>
                <div className="p-3.5 bg-white border border-slate-200 rounded-xl">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">
                    Maximum Market Price
                  </span>
                  <span className="text-base font-extrabold font-mono text-slate-900 mt-0.5 block">
                    {stats.maxPrice !== undefined ? `${stats.currency} ${stats.maxPrice.toLocaleString()}` : 'Unavailable'}
                  </span>
                </div>
                <div className="p-3.5 bg-white border border-slate-200 rounded-xl">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">
                    Listed vs Reference
                  </span>
                  {stats.percentageDifference !== undefined ? (
                    <span
                      className={`text-base font-extrabold font-mono mt-0.5 block ${
                        stats.percentageDifference >= 60
                          ? 'text-amber-700'
                          : stats.percentageDifference < 0
                            ? 'text-slate-800'
                            : 'text-emerald-700'
                      }`}
                    >
                      {stats.percentageDifference >= 0
                        ? `${stats.percentageDifference}% below`
                        : `${Math.abs(stats.percentageDifference)}% above`}
                    </span>
                  ) : (
                    <span className="text-sm font-mono text-slate-500 mt-0.5 block">No Listed Price</span>
                  )}
                </div>
              </div>
            )}

            {/* FX Conversion Transparency Banner */}
            {mpc.currencyConversion && (
              <div
                className={`p-3 rounded-xl border text-[11px] ${
                  mpc.currencyConversion.performed
                    ? 'bg-indigo-50/70 border-indigo-200 text-indigo-900'
                    : 'bg-amber-50 border-amber-200 text-amber-900'
                }`}
              >
                {mpc.currencyConversion.performed && mpc.currencyConversion.rates ? (
                  <div>
                    <strong>Verified Live FX Conversion:</strong> Converted from{' '}
                    {Object.entries(mpc.currencyConversion.rates)
                      .map(([curr, rate]) => `1 ${curr} = ${rate.toFixed(4)} ${mpc.currencyConversion!.toCurrency}`)
                      .join(', ')}{' '}
                    via {mpc.currencyConversion.provider} (retrieved{' '}
                    {mpc.currencyConversion.retrievedAt
                      ? new Date(mpc.currencyConversion.retrievedAt).toLocaleString()
                      : 'live'}).
                  </div>
                ) : (
                  <div>
                    <strong>Currency Limitation:</strong>{' '}
                    {mpc.currencyConversion.unavailableReason || 'Cross-currency comparison skipped because live FX conversion rates were unavailable.'}
                  </div>
                )}
              </div>
            )}

            {/* Comparable Price Quotes Table/Cards */}
            {mpc.quotes.length > 0 && (
              <div className="space-y-2.5">
                <div className="text-xs font-bold text-slate-800">
                  Reference &amp; Market Price Sources ({mpc.quotes.length})
                </div>
                <div className="space-y-2">
                  {mpc.quotes.map((q) => {
                    const typeBadge = marketPriceTypeBadge(q.priceType);
                    const safeUrl = safeHttpHref(q.sourceUrl);
                    return (
                      <div
                        key={q.id}
                        className="p-3.5 bg-white border border-slate-200 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                      >
                        <div className="space-y-1 min-w-0">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="text-xs font-bold text-slate-900">{q.sourceName}</span>
                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${typeBadge.className}`}>
                              {typeBadge.label}
                            </span>
                            {q.condition !== 'unknown' && (
                              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 capitalize">
                                {q.condition}
                              </span>
                            )}
                          </div>
                          {q.matchedTitle && (
                            <div className="text-[11px] text-slate-600 truncate">
                              Matched: {q.matchedTitle}
                            </div>
                          )}
                          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px] text-slate-500 font-mono">
                            <span>Retrieved: {new Date(q.retrievedAt).toLocaleString()}</span>
                            {safeUrl && (
                              <a
                                href={safeUrl}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="inline-flex items-center gap-1 text-indigo-600 hover:text-indigo-800 underline"
                              >
                                <span className="truncate max-w-[240px]">{safeUrl}</span>
                                <ExternalLink className="w-3 h-3 shrink-0" />
                              </a>
                            )}
                          </div>
                        </div>

                        <div className="text-left sm:text-right shrink-0">
                          <div className="text-sm font-extrabold font-mono text-slate-900">
                            {q.currency} {q.price.toLocaleString()}
                          </div>
                          {q.convertedPrice !== undefined && q.convertedCurrency && (
                            <div className="text-[11px] font-mono text-indigo-700">
                              ≈ {q.convertedCurrency} {q.convertedPrice.toLocaleString()}
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Excluded Mismatched Variants / Conditions / Currencies */}
            {mpc.excludedMismatches.length > 0 && (
              <div className="p-3.5 bg-white border border-slate-200 rounded-xl space-y-1.5">
                <div className="text-[11px] font-bold text-slate-800">
                  Excluded Non-Comparable Offers ({mpc.excludedMismatches.length})
                </div>
                <ul className="space-y-1 text-[11px] text-slate-600">
                  {mpc.excludedMismatches.map((ex) => (
                    <li key={ex.id}>
                      <strong>{ex.sourceName}</strong> ({ex.currency} {ex.price.toLocaleString()}):{' '}
                      {ex.variantMatchReason || 'Variant or condition mismatch'}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Provider / Source Access Notes */}
            {mpc.sourceErrors.length > 0 && (
              <div className="text-[11px] text-slate-500 space-y-0.5">
                {mpc.sourceErrors.map((err, idx) => (
                  <div key={idx}>
                    • <strong>{err.source}:</strong> {err.reason}
                  </div>
                ))}
              </div>
            )}

            <div className="p-3 bg-amber-50 border border-amber-200 rounded-xl text-[11px] text-amber-900">
              <strong>Pricing Scope Notice:</strong> An unusually low price alone <strong>never</strong> proves a product is counterfeit—refurbished items, clearances, open-box deals, and regional discounts are common. When external prices are unavailable, the manual reference price input remains active.
            </div>
          </div>
        );
      })()}

      {/* External Barcode Product Database Lookup Card (for Barcode & Product checks) */}
      {result.barcodeLookup && (
        <div className="p-6 bg-slate-50 border border-slate-200 rounded-2xl space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-200">
            <div className="flex items-center gap-2.5">
              <div className="p-2 bg-indigo-100 text-indigo-700 rounded-xl border border-indigo-200">
                <Database className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-slate-900">
                  Product Barcode Database Lookup
                </h3>
                <p className="text-[11px] text-slate-500">
                  Queried: {result.barcodeLookup.queriedDatabases.length > 0
                    ? result.barcodeLookup.queriedDatabases.join(' · ')
                    : 'GS1 pre-validation only (no external query sent)'}
                  {result.barcodeLookup.cached ? ' · Cached Result' : ''}
                </p>
              </div>
            </div>

            <div>
              {result.barcodeLookup.sourceType === 'live_database' ? (
                <span className="inline-flex items-center gap-1.5 text-[11px] font-bold px-2.5 py-1 rounded-full bg-emerald-100 text-emerald-800 border border-emerald-200">
                  <Globe className="w-3 h-3" />
                  Live Database · {result.barcodeLookup.product?.databaseSource}
                </span>
              ) : result.barcodeLookup.sourceType === 'synthetic_demo' ? (
                <span className="inline-flex items-center gap-1.5 text-[11px] font-bold px-2.5 py-1 rounded-full bg-amber-100 text-amber-800 border border-amber-200">
                  Synthetic Demo Catalog · Not Live Data
                </span>
              ) : result.barcodeLookup.status === 'not_found' ? (
                <span className="inline-flex items-center gap-1.5 text-[11px] font-bold px-2.5 py-1 rounded-full bg-slate-200 text-slate-700 border border-slate-300">
                  Not Found in Databases
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 text-[11px] font-bold px-2.5 py-1 rounded-full bg-rose-100 text-rose-800 border border-rose-200">
                  {result.barcodeLookup.status === 'invalid_checksum' ? 'Invalid GS1 Checksum' : 'Database Lookup Unavailable'}
                </span>
              )}
            </div>
          </div>

          {result.barcodeLookup.found && result.barcodeLookup.product ? (
            <div className="space-y-4">
              <div className="flex flex-col sm:flex-row gap-4 items-start">
                {result.barcodeLookup.product.imageUrl ? (
                  <div className="w-24 h-24 rounded-xl bg-white border border-slate-200 overflow-hidden shrink-0 flex items-center justify-center p-1">
                    <img
                      src={result.barcodeLookup.product.imageUrl}
                      alt={result.barcodeLookup.product.productName || 'Database product'}
                      referrerPolicy="no-referrer"
                      className="w-full h-full object-contain"
                      onError={(e) => {
                        e.currentTarget.style.display = 'none';
                      }}
                    />
                  </div>
                ) : (
                  <div className="w-24 h-24 rounded-xl bg-white border border-slate-200 shrink-0 flex flex-col items-center justify-center text-slate-400 text-[10px]">
                    <Package className="w-6 h-6 mb-1" />
                    <span>No Image</span>
                  </div>
                )}

                <div className="flex-1 grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2 text-xs">
                  <div>
                    <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">
                      Product Name
                    </span>
                    <span className="font-bold text-slate-900">
                      {result.barcodeLookup.product.productName || 'Not specified'}
                    </span>
                  </div>
                  <div>
                    <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">
                      Brand
                    </span>
                    <span className="font-semibold text-slate-800">
                      {result.barcodeLookup.product.brand || 'Not specified'}
                    </span>
                  </div>
                  <div>
                    <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">
                      UPC / EAN / GTIN
                    </span>
                    <span className="font-mono text-slate-800 tabular-nums">
                      {result.barcodeLookup.product.code}
                      {result.barcodeLookup.product.formatLabel ? ` (${result.barcodeLookup.product.formatLabel})` : ''}
                    </span>
                  </div>
                  <div>
                    <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">
                      Manufacturer
                    </span>
                    <span className="text-slate-700">
                      {result.barcodeLookup.product.manufacturer || 'Not specified in database'}
                    </span>
                  </div>
                  <div>
                    <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">
                      Product Category
                    </span>
                    <span className="text-slate-700">
                      {result.barcodeLookup.product.category || 'Not specified in database'}
                    </span>
                  </div>
                  <div>
                    <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">
                      Country Information
                    </span>
                    <span className="text-slate-700">
                      {result.barcodeLookup.product.countries || 'Not specified in database'}
                    </span>
                  </div>
                  <div>
                    <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">
                      Database Source
                    </span>
                    <span className="font-semibold text-indigo-700">
                      {result.barcodeLookup.product.databaseSource}
                      {result.barcodeLookup.product.quantity ? ` · ${result.barcodeLookup.product.quantity}` : ''}
                    </span>
                  </div>
                </div>
              </div>

              <div className="p-3 bg-amber-50 border border-amber-200 rounded-xl text-[11px] text-amber-900">
                <strong>Non-Authenticity Guarantee:</strong> Existence of barcode{' '}
                <code className="font-mono">{result.barcodeLookup.product.code}</code> in{' '}
                <strong>{result.barcodeLookup.product.databaseSource}</strong> confirms only that this GTIN is registered to this product metadata—it <strong>never proves</strong> a physical item is genuine.
              </div>
            </div>
          ) : result.barcodeLookup.status === 'not_found' ? (
            <div className="p-4 bg-white border border-slate-200 rounded-xl text-xs text-slate-700 space-y-1">
              <div className="font-bold text-slate-900">Product not found in available databases.</div>
              <p className="text-slate-600 leading-relaxed">
                This valid GS1 barcode did not return a match in the queried public product registries. Many regional, private-label, or newly launched products are unlisted; absence from a database does not indicate counterfeiting.
              </p>
            </div>
          ) : (
            <div className="p-4 bg-amber-50/70 border border-amber-200 rounded-xl text-xs text-amber-900 space-y-1">
              <div className="font-bold">{result.barcodeLookup.message}</div>
              {result.barcodeLookup.providerErrors && result.barcodeLookup.providerErrors.length > 0 && (
                <ul className="list-disc pl-5 text-[11px] text-amber-800 space-y-0.5">
                  {result.barcodeLookup.providerErrors.map((err, idx) => (
                    <li key={idx}>
                      <strong>{err.database}:</strong> {err.reason}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}

          {result.barcodeLookup.found && result.barcodeLookup.providerErrors && result.barcodeLookup.providerErrors.length > 0 && (
            <div className="text-[11px] text-slate-500">
              Other queried sources note:{' '}
              {result.barcodeLookup.providerErrors.map((e) => `${e.database} (${e.reason})`).join('; ')}
            </div>
          )}
        </div>
      )}

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
          <div className="flex flex-wrap items-center gap-2">
            <Sparkles className="w-4 h-4 text-indigo-600" />
            <h4 className="font-bold text-sm text-slate-900">AI Plain-Language Risk Explanation</h4>
            {aiProvider === 'gemini' && (
              <span className="text-[11px] font-mono px-2 py-0.5 rounded-full border bg-indigo-100 text-indigo-800 border-indigo-200 font-semibold">
                Source: Gemini AI ({aiModel || 'gemini-4-hydrogen'})
              </span>
            )}
            {aiProvider === 'deterministic-fallback' && (
              <span className="text-[11px] font-mono px-2 py-0.5 rounded-full border bg-amber-100 text-amber-800 border-amber-200 font-semibold">
                Source: Deterministic Fallback (Gemini Unavailable)
              </span>
            )}
          </div>

          {(!aiExplanation || aiProvider === 'deterministic-fallback') && (
            <button
              onClick={handleGenerateAiExplanation}
              disabled={isExplaining}
              className="flex items-center gap-2 px-4 py-2 text-xs font-bold text-white bg-indigo-600 hover:bg-indigo-700 rounded-xl transition-colors disabled:opacity-50 shadow-sm"
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>
                {isExplaining
                  ? 'Analyzing...'
                  : aiProvider === 'deterministic-fallback'
                    ? 'Retry Gemini AI'
                    : 'Generate AI Explanation'}
              </span>
            </button>
          )}
        </div>

        {aiExplanation ? (
          <div className="space-y-2 border-t border-indigo-100 pt-3">
            {aiProvider === 'deterministic-fallback' && aiFallbackReason && (
              <div className="text-[11px] text-amber-800 bg-amber-50/80 border border-amber-200 rounded-lg px-3 py-1.5">
                Fallback note: {aiFallbackReason}. Displaying deterministic summary grounded in the verified assessment signals above.
              </div>
            )}
            <div className="text-xs text-slate-700 leading-relaxed whitespace-pre-line">
              {aiExplanation}
            </div>
          </div>
        ) : (
          <p className="text-xs text-slate-600">
            Click &ldquo;Generate AI Explanation&rdquo; to receive an objective summary of these findings powered by Gemini AI (with automatic deterministic fallback if unavailable).
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
