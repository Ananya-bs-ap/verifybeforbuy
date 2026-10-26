/**
 * VerifyBeforeBuy AI — How It Works & Methodology Page
 * Deep dive into the 0-100 scoring model, anti-bias principles,
 * evidence coverage, and Machine Learning readiness roadmap.
 */

import React from 'react';
import {
  HelpCircle,
  Shield,
  Layers,
  Scale,
  Cpu,
  BarChart3,
  CheckCircle2,
  AlertTriangle,
  FileCode,
  ArrowRight,
  Database,
} from 'lucide-react';
import { CATEGORY_META } from '../lib/riskEngine/rules';

export const HowItWorksPage: React.FC = () => {
  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-12">
      {/* Header */}
      <div className="space-y-3">
        <div className="inline-flex items-center gap-2 text-xs font-semibold text-teal-400 bg-teal-950/60 px-3 py-1 rounded-full border border-teal-800/60">
          <HelpCircle className="w-3.5 h-3.5" />
          <span>Transparent Risk Methodology</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          How Our Scoring &amp; AI Engine Evaluates Risk
        </h1>
        <p className="text-sm text-slate-400 max-w-2xl leading-relaxed">
          VerifyBeforeBuy AI was designed from first principles to be explainable, anti-biased, and grounded in observable evidence rather than arbitrary numbers.
        </p>
      </div>

      {/* 1. The 0–100 Calibrated Risk Scale */}
      <section className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 sm:p-8 space-y-6">
        <div className="space-y-2">
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Scale className="w-5 h-5 text-teal-400" />
            <span>01. The Calibrated 0–100 Risk Scale</span>
          </h2>
          <p className="text-xs text-slate-300 leading-relaxed">
            Every inspection produces a normalized score between 0 (lowest detected probability of deception) and 100 (highest concentration of critical red flags).
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-4 bg-slate-950/70 border border-emerald-950/60 rounded-xl space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs font-bold text-emerald-400">0 – 25</span>
              <span className="text-[10px] uppercase font-bold text-emerald-400">Lower Risk</span>
            </div>
            <h3 className="text-sm font-semibold text-white">Nominal Indicators</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Standard brand domain syntax, HTTPS encryption, valid barcode modulo checksums, and standard pricing.
            </p>
          </div>

          <div className="p-4 bg-slate-950/70 border border-sky-950/60 rounded-xl space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs font-bold text-sky-400">26 – 50</span>
              <span className="text-[10px] uppercase font-bold text-sky-400">Moderate Risk</span>
            </div>
            <h3 className="text-sm font-semibold text-white">Caution Flags</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Noticeable price deviations, newly registered or unverified seller handles, or minor domain structural flags.
            </p>
          </div>

          <div className="p-4 bg-slate-950/70 border border-amber-950/60 rounded-xl space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs font-bold text-amber-400">51 – 75</span>
              <span className="text-[10px] uppercase font-bold text-amber-400">Elevated Risk</span>
            </div>
            <h3 className="text-sm font-semibold text-white">Multiple Warning Signs</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Combination of high-abuse TLDs, absence of return guarantees, hyphen-stuffed domains, or poor seller feedback.
            </p>
          </div>

          <div className="p-4 bg-slate-950/70 border border-rose-950/60 rounded-xl space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs font-bold text-rose-400">76 – 100</span>
              <span className="text-[10px] uppercase font-bold text-rose-400">High Risk</span>
            </div>
            <h3 className="text-sm font-semibold text-white">Critical Deception</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Explicit brand typosquatting, peer-to-peer wire payment demands, punycode homographs, or direct replica declarations.
            </p>
          </div>
        </div>
      </section>

      {/* 2. Anti-Bias & Missing Data Principles */}
      <section className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 sm:p-8 space-y-6">
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <Shield className="w-5 h-5 text-teal-400" />
          <span>02. Core Ethical Anti-Bias Principles</span>
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="p-5 bg-slate-950/60 border border-slate-800 rounded-xl space-y-2">
            <h3 className="text-sm font-bold text-teal-300">
              Steep Discounts ≠ Counterfeit Proof
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              Clearance blowouts, seasonal overstocks, factory refurbished items, and certified liquidations frequently sell at 70% to 90% below original MSRP. Our pricing rule strictly caps price variance impact so that price alone cannot force a listing into high risk without corroborating red flags.
            </p>
          </div>

          <div className="p-5 bg-slate-950/60 border border-slate-800 rounded-xl space-y-2">
            <h3 className="text-sm font-bold text-sky-300">
              Missing Data ≠ Proof of Fraud
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              When a user submits only a product name or omits optional seller ratings, our system reduces the <em>Evidence Coverage</em> metric. We never penalize missing fields with artificial risk points, which would falsely accuse small merchants.
            </p>
          </div>

          <div className="p-5 bg-slate-950/60 border border-slate-800 rounded-xl space-y-2">
            <h3 className="text-sm font-bold text-amber-300">
              Category Caps &amp; Anti-Double-Counting
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              If a domain has an unusual TLD, multiple hyphens, and a non-standard port, these related syntactic signals are grouped under the technical/URL category cap. This prevents mathematical compounding of the same underlying condition.
            </p>
          </div>

          <div className="p-5 bg-slate-950/60 border border-slate-800 rounded-xl space-y-2">
            <h3 className="text-sm font-bold text-purple-300">
              Observed Signals vs. Self-Reported Data
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              Every indicator clearly specifies whether it was derived from an RFC-verifiable technical attribute (such as an IP address or GS1 checksum) versus user-entered text (such as reported seller feedback), ensuring full audit integrity.
            </p>
          </div>
        </div>
      </section>

      {/* 3. Machine Learning Readiness & Architecture */}
      <section className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 sm:p-8 space-y-6">
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <Cpu className="w-5 h-5 text-purple-400" />
            <h2 className="text-xl font-bold text-white">03. Machine Learning Readiness Architecture</h2>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            The current system utilizes an explainable rule-based engine. Below is the technical specification for transitioning to a hybrid machine-learning pipeline.
          </p>
        </div>

        <div className="space-y-4">
          <div className="p-4 bg-slate-950/70 border border-slate-800 rounded-xl space-y-3">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <BarChart3 className="w-4 h-4 text-teal-400" />
              <span>Phishing Website Classifier Pipeline (Scikit-Learn / XGBoost)</span>
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              Note: Website phishing classification is mathematically distinct from physical counterfeit detection and requires a separate model pipeline.
            </p>
            <ul className="text-xs text-slate-400 space-y-1.5 pl-4 list-disc marker:text-teal-400">
              <li>
                <strong>Curated Dataset:</strong> Labeled benign URLs (Tranco / Alexa Top 1M) and confirmed phishing feeds (PhishTank / OpenPhish).
              </li>
              <li>
                <strong>Feature Extraction:</strong> Shannon entropy of hostname, vowel-to-consonant ratio, token length variance, brand Levenshtein distance, TLD risk quotient, and subdirectory depth.
              </li>
              <li>
                <strong>Evaluation Metrics:</strong> High precision ($\ge 98\%$) to prevent false positive storefront blocks, with recall and confusion matrix auditing.
              </li>
              <li>
                <strong>Deployment:</strong> Standalone Python / FastAPI microservice exposing <code>/predict/url</code>, consumed by our Express backend.
              </li>
            </ul>
          </div>

          <div className="p-4 bg-slate-950/70 border border-slate-800 rounded-xl space-y-2 text-xs text-slate-400">
            <div className="text-slate-200 font-semibold">Integrity Commitment:</div>
            We never describe our deterministic rule-based prototype scores as &ldquo;machine-learning predictions&rdquo; until an actual model is trained, validated, and actively serving predictions.
          </div>
        </div>
      </section>
    </div>
  );
};
