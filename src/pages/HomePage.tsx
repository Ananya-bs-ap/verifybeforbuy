/**
 * VerifyBeforeBuy AI — Home Page
 * Landing page with hero, original security illustration, 3-step workflow,
 * feature cards with live/external labeling, sample demo report, and educational warning signs.
 */

import React, { useState } from 'react';
import {
  Shield,
  Globe,
  Package,
  QrCode,
  FileCheck2,
  Database,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  Lock,
  Layers,
  Sparkles,
  ExternalLink,
} from 'lucide-react';
import { HeroVisual } from '../components/HeroVisual';
import { VerificationReport } from '../components/VerificationReport';
import { RiskScoringEngine } from '../lib/riskEngine/engine';
import { NavTab } from '../components/Navbar';

interface HomePageProps {
  onNavigate: (tab: NavTab) => void;
}

export const HomePage: React.FC<HomePageProps> = ({ onNavigate }) => {
  const [showDemoModal, setShowDemoModal] = useState(false);

  // Pre-calculated sample demo report for preview section
  const sampleDemoReport = RiskScoringEngine.assessWebsite({
    url: 'https://apple-security-verify-login.click/update-billing',
  });

  return (
    <div className="space-y-24 pb-20">
      {/* 1. Hero Section */}
      <section className="relative pt-12 md:pt-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
            {/* Left Column: Headline and CTAs */}
            <div className="space-y-6 text-center lg:text-left">
              <div className="inline-flex items-center gap-2 px-3 py-1 text-xs font-semibold text-teal-300 bg-teal-950/60 border border-teal-800/60 rounded-full">
                <Shield className="w-3.5 h-3.5 text-teal-400" />
                <span>Cybersecurity &amp; Consumer Protection</span>
              </div>

              <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold text-white tracking-tight leading-[1.15]" style={{ textWrap: 'balance' }}>
                Shop Smarter. Verify Before You Buy.
              </h1>

              <p className="text-base sm:text-lg text-slate-300 max-w-xl mx-auto lg:mx-0 leading-relaxed">
                Assess potential online shopping risks with clear warnings, understandable risk scores, and practical safety recommendations.
              </p>

              <div className="flex flex-col sm:flex-row items-center justify-center lg:justify-start gap-3 pt-2">
                <button
                  onClick={() => onNavigate('website')}
                  className="w-full sm:w-auto px-6 py-3.5 text-sm font-semibold text-slate-950 bg-teal-400 hover:bg-teal-300 rounded-xl transition-all shadow-lg hover:shadow-teal-500/20 flex items-center justify-center gap-2"
                >
                  <Globe className="w-4 h-4" />
                  <span>Check a Website</span>
                </button>
                <button
                  onClick={() => onNavigate('product')}
                  className="w-full sm:w-auto px-6 py-3.5 text-sm font-semibold text-white bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-xl transition-colors flex items-center justify-center gap-2"
                >
                  <Package className="w-4 h-4" />
                  <span>Check a Product</span>
                </button>
              </div>

              {/* Trust statement & non-claim */}
              <div className="pt-4 border-t border-slate-800/80 text-xs text-slate-400 flex items-center justify-center lg:justify-start gap-2">
                <Lock className="w-3.5 h-3.5 text-teal-400 shrink-0" />
                <span>Transparent scoring rules. Never claims proof of authenticity or guarantees fraud.</span>
              </div>
            </div>

            {/* Right Column: Hero Visual Graphic */}
            <div className="flex justify-center">
              <HeroVisual />
            </div>
          </div>
        </div>
      </section>

      {/* 2. How It Works (3 Steps) */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center max-w-2xl mx-auto mb-12 space-y-3">
          <span className="text-xs uppercase font-semibold text-teal-400 tracking-wider">
            Three-Step Safety Protocol
          </span>
          <h2 className="text-2xl sm:text-3xl font-bold text-white">
            How VerifyBeforeBuy AI Works
          </h2>
          <p className="text-sm text-slate-400">
            A structured, explainable methodology to help buyers make informed decisions before submitting payment.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          <div className="p-6 bg-slate-900/60 border border-slate-800 rounded-xl space-y-4 relative">
            <div className="w-10 h-10 rounded-lg bg-teal-500/10 border border-teal-500/30 flex items-center justify-center text-teal-400 font-mono font-bold text-lg">
              01
            </div>
            <h3 className="text-lg font-semibold text-white">Enter Website or Product Info</h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              Paste a store URL, input listed product specifications and seller details, or scan a retail barcode / packaging QR code.
            </p>
          </div>

          <div className="p-6 bg-slate-900/60 border border-slate-800 rounded-xl space-y-4 relative">
            <div className="w-10 h-10 rounded-lg bg-sky-500/10 border border-sky-500/30 flex items-center justify-center text-sky-400 font-mono font-bold text-lg">
              02
            </div>
            <h3 className="text-lg font-semibold text-white">Analyze Available Risk Indicators</h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              Our explainable engine evaluates typosquatting, domain syntax, price variance bounds, seller protections, and suspicious terms.
            </p>
          </div>

          <div className="p-6 bg-slate-900/60 border border-slate-800 rounded-xl space-y-4 relative">
            <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 font-mono font-bold text-lg">
              03
            </div>
            <h3 className="text-lg font-semibold text-white">Review Score &amp; Recommendations</h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              Receive a calibrated 0–100 risk score, confidence coverage gauge, AI explanation, and practical precautions prior to checkout.
            </p>
          </div>
        </div>
      </section>

      {/* 3. Feature Cards (Clearly labeled live vs external data dependent) */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center max-w-2xl mx-auto mb-12 space-y-3">
          <span className="text-xs uppercase font-semibold text-teal-400 tracking-wider">
            Comprehensive Verification Suite
          </span>
          <h2 className="text-2xl sm:text-3xl font-bold text-white">
            Built for Transparent Consumer Protection
          </h2>
          <p className="text-sm text-slate-400">
            Every feature distinguishes directly observed evidence from unverified assumptions.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {/* Card 1 */}
          <div className="p-6 bg-slate-900/80 border border-slate-800 rounded-xl flex flex-col justify-between space-y-4 hover:border-slate-700 transition-colors">
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <Globe className="w-6 h-6 text-teal-400" />
                <span className="text-[11px] font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/60">
                  LIVE ENGINE
                </span>
              </div>
              <h3 className="text-base font-semibold text-white">Website Risk Assessment</h3>
              <p className="text-xs text-slate-300 leading-relaxed">
                Evaluates URL structure, homograph/punycode attacks, brand typosquatting, high-abuse TLDs, and SSRF-protected routing.
              </p>
            </div>
            <button
              onClick={() => onNavigate('website')}
              className="text-xs font-semibold text-teal-400 hover:text-teal-300 flex items-center gap-1 self-start pt-2"
            >
              <span>Inspect a website</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Card 2 */}
          <div className="p-6 bg-slate-900/80 border border-slate-800 rounded-xl flex flex-col justify-between space-y-4 hover:border-slate-700 transition-colors">
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <Package className="w-6 h-6 text-sky-400" />
                <span className="text-[11px] font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/60">
                  LIVE ENGINE
                </span>
              </div>
              <h3 className="text-base font-semibold text-white">Product Listing Assessment</h3>
              <p className="text-xs text-slate-300 leading-relaxed">
                Fairly compares listed price against retail baseline without falsely marking legitimate seasonal discounts as counterfeit.
              </p>
            </div>
            <button
              onClick={() => onNavigate('product')}
              className="text-xs font-semibold text-teal-400 hover:text-teal-300 flex items-center gap-1 self-start pt-2"
            >
              <span>Check a product</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Card 3 */}
          <div className="p-6 bg-slate-900/80 border border-slate-800 rounded-xl flex flex-col justify-between space-y-4 hover:border-slate-700 transition-colors">
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <Layers className="w-6 h-6 text-amber-400" />
                <span className="text-[11px] font-mono text-sky-400 bg-sky-950/60 px-2 py-0.5 rounded border border-sky-800/60">
                  SELF-REPORTED AUDIT
                </span>
              </div>
              <h3 className="text-base font-semibold text-white">Seller Information Review</h3>
              <p className="text-xs text-slate-300 leading-relaxed">
                Screens seller handles, customer dispute ratings, and return policy disclosures with explicit unverified marking.
              </p>
            </div>
            <button
              onClick={() => onNavigate('product')}
              className="text-xs font-semibold text-teal-400 hover:text-teal-300 flex items-center gap-1 self-start pt-2"
            >
              <span>Review seller info</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Card 4 */}
          <div className="p-6 bg-slate-900/80 border border-slate-800 rounded-xl flex flex-col justify-between space-y-4 hover:border-slate-700 transition-colors">
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <QrCode className="w-6 h-6 text-teal-400" />
                <span className="text-[11px] font-mono text-amber-400 bg-amber-950/60 px-2 py-0.5 rounded border border-amber-800/60">
                  CAMERA &amp; SYNTHETIC DB
                </span>
              </div>
              <h3 className="text-base font-semibold text-white">QR / Barcode Lookup</h3>
              <p className="text-xs text-slate-300 leading-relaxed">
                Live camera scanner + GS1 Modulo-10 checksum validation with clear disclosure that barcode scanning alone does not prove authenticity.
              </p>
            </div>
            <button
              onClick={() => onNavigate('scanner')}
              className="text-xs font-semibold text-teal-400 hover:text-teal-300 flex items-center gap-1 self-start pt-2"
            >
              <span>Open barcode scanner</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Card 5 */}
          <div className="p-6 bg-slate-900/80 border border-slate-800 rounded-xl flex flex-col justify-between space-y-4 hover:border-slate-700 transition-colors">
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <Sparkles className="w-6 h-6 text-purple-400" />
                <span className="text-[11px] font-mono text-purple-400 bg-purple-950/60 px-2 py-0.5 rounded border border-purple-800/60">
                  AI ASSISTED
                </span>
              </div>
              <h3 className="text-base font-semibold text-white">Explainable Risk Reports</h3>
              <p className="text-xs text-slate-300 leading-relaxed">
                Objective natural language summaries generated via server-side Gemini 3.8 Flash, or deterministic fallback without external keys.
              </p>
            </div>
            <button
              onClick={() => onNavigate('how-it-works')}
              className="text-xs font-semibold text-teal-400 hover:text-teal-300 flex items-center gap-1 self-start pt-2"
            >
              <span>Learn scoring methodology</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Card 6 */}
          <div className="p-6 bg-slate-900/80 border border-slate-800 rounded-xl flex flex-col justify-between space-y-4 hover:border-slate-700 transition-colors">
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <Database className="w-6 h-6 text-indigo-400" />
                <span className="text-[11px] font-mono text-indigo-400 bg-indigo-950/60 px-2 py-0.5 rounded border border-indigo-800/60">
                  SUPABASE READY
                </span>
              </div>
              <h3 className="text-base font-semibold text-white">Scan History &amp; Cloud Sync</h3>
              <p className="text-xs text-slate-300 leading-relaxed">
                Saves reports automatically in private browser storage or securely into Supabase PostgreSQL tables with Row Level Security.
              </p>
            </div>
            <button
              onClick={() => onNavigate('history')}
              className="text-xs font-semibold text-teal-400 hover:text-teal-300 flex items-center gap-1 self-start pt-2"
            >
              <span>View scan history</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </section>

      {/* 4. Sample Report Preview (Clearly labeled DEMO report) */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-6 sm:p-10 space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-800">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono uppercase px-2 py-0.5 rounded bg-amber-950/60 text-amber-400 border border-amber-800/60 font-semibold">
                  DEMONSTRATION SAMPLE
                </span>
                <span className="text-xs text-slate-400">Illustrative report preview</span>
              </div>
              <h3 className="text-xl font-bold text-white mt-1">
                Sample Report: Suspicious Account Verification Domain
              </h3>
            </div>
            <button
              onClick={() => setShowDemoModal(!showDemoModal)}
              className="px-4 py-2 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors whitespace-nowrap self-start sm:self-auto"
            >
              {showDemoModal ? 'Collapse Full View' : 'Expand Full Interactive Report'}
            </button>
          </div>

          {/* Quick Snapshot Metrics */}
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
            <div className="p-4 bg-slate-950/70 border border-slate-800 rounded-lg">
              <div className="text-[11px] text-slate-400 uppercase font-semibold">Simulated Target</div>
              <div className="text-xs font-mono text-slate-200 truncate mt-1">
                apple-security-verify-login.click
              </div>
            </div>
            <div className="p-4 bg-slate-950/70 border border-slate-800 rounded-lg">
              <div className="text-[11px] text-slate-400 uppercase font-semibold">Risk Score</div>
              <div className="text-xl font-bold font-mono text-amber-400 mt-1 tabular-nums">
                75 / 100
              </div>
            </div>
            <div className="p-4 bg-slate-950/70 border border-slate-800 rounded-lg">
              <div className="text-[11px] text-slate-400 uppercase font-semibold">Category</div>
              <div className="text-xs font-bold text-amber-400 mt-1">
                Elevated Assessed Risk
              </div>
            </div>
            <div className="p-4 bg-slate-950/70 border border-slate-800 rounded-lg">
              <div className="text-[11px] text-slate-400 uppercase font-semibold">Key Detected Trigger</div>
              <div className="text-xs text-rose-300 truncate mt-1">
                Brand keyword on third-party TLD
              </div>
            </div>
          </div>

          {/* Expanded or Preview Body */}
          {showDemoModal ? (
            <div className="pt-4">
              <VerificationReport result={sampleDemoReport} />
            </div>
          ) : (
            <div className="p-4 bg-slate-950/40 border border-slate-800 rounded-lg text-xs text-slate-300 flex items-center justify-between">
              <span>This sample shows how our multi-signal engine flags lookalike domains without executing untrusted external scripts.</span>
              <button
                onClick={() => setShowDemoModal(true)}
                className="text-teal-400 hover:underline shrink-0 ml-4 font-medium"
              >
                Inspect full breakdown &rarr;
              </button>
            </div>
          )}
        </div>
      </section>

      {/* 5. Educational Section: Common Warning Signs & Legitimate Discounts */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center max-w-2xl mx-auto mb-12 space-y-3">
          <span className="text-xs uppercase font-semibold text-teal-400 tracking-wider">
            Consumer Knowledge Base
          </span>
          <h2 className="text-2xl sm:text-3xl font-bold text-white">
            Common Warning Signs &amp; Safety Realities
          </h2>
          <p className="text-sm text-slate-400">
            Learn how to distinguish genuine retail deals from high-risk deception traps.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          <div className="p-6 bg-slate-900/60 border border-slate-800 rounded-xl space-y-3">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Globe className="w-4 h-4 text-rose-400" />
              <span>Suspicious URLs &amp; Misleading Domains</span>
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              Scammers often insert trusted brand names into subdomains (e.g., <code>brand.discount-outlets.click</code>) or use leetspeak typosquatting (<code>amaz0n</code>). Look at the apex domain directly before the path.
            </p>
          </div>

          <div className="p-6 bg-slate-900/60 border border-slate-800 rounded-xl space-y-3">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Package className="w-4 h-4 text-amber-400" />
              <span>The Large Discount Reality</span>
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              <strong>Crucial truth:</strong> A 70% or 80% discount may be a 100% legitimate clearance sale on authentic stock. Never assume low price equals fake. Instead, verify if the seller is authorized and offers guaranteed returns.
            </p>
          </div>

          <div className="p-6 bg-slate-900/60 border border-slate-800 rounded-xl space-y-3">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Layers className="w-4 h-4 text-sky-400" />
              <span>Missing Seller Information</span>
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              Stores lacking a verifiable physical address, legal company registration number, customer support phone, or corporate email should be treated with heightened caution.
            </p>
          </div>

          <div className="p-6 bg-slate-900/60 border border-slate-800 rounded-xl space-y-3">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-400" />
              <span>Unusual Payment Demands</span>
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              Legitimate stores accept credit cards with chargeback rights. Any store demanding direct wire transfers, cryptocurrency, gift cards, or peer-to-peer transfers removes all buyer protections.
            </p>
          </div>

          <div className="p-6 bg-slate-900/60 border border-slate-800 rounded-xl space-y-3">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <QrCode className="w-4 h-4 text-teal-400" />
              <span>Barcode &amp; QR Code Limitations</span>
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              Scanning a valid barcode does <strong>not</strong> prove an item is genuine. Counterfeit operations routinely print legitimate GS1 numbers on fake packaging. Barcodes only verify standard numbering format.
            </p>
          </div>

          <div className="p-6 bg-slate-900/60 border border-slate-800 rounded-xl space-y-3">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <FileCheck2 className="w-4 h-4 text-emerald-400" />
              <span>Incomplete Descriptions</span>
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              Descriptions mixing contradictory specifications, using vague terminology (&ldquo;1:1 original batch&rdquo;, &ldquo;OEM clone&rdquo;), or stolen stock photography often signal unverified stock.
            </p>
          </div>
        </div>
      </section>

      {/* 6. Footer */}
      <footer className="border-t border-slate-800/80 pt-12 text-slate-400 text-xs">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-8">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
            <div className="space-y-3">
              <div className="flex items-center gap-2 text-white font-bold text-sm">
                <Shield className="w-4 h-4 text-teal-400" />
                <span>VerifyBeforeBuy AI</span>
              </div>
              <p className="text-slate-400 leading-relaxed">
                Check the Risk. Shop with Confidence. An explainable cybersecurity and shopping verification tool.
              </p>
            </div>

            <div className="space-y-2">
              <span className="font-semibold text-slate-200 block">Tools</span>
              <ul className="space-y-1">
                <li><button onClick={() => onNavigate('website')} className="hover:text-teal-400">Website Checker</button></li>
                <li><button onClick={() => onNavigate('product')} className="hover:text-teal-400">Product Listing Checker</button></li>
                <li><button onClick={() => onNavigate('scanner')} className="hover:text-teal-400">Barcode &amp; QR Scanner</button></li>
                <li><button onClick={() => onNavigate('history')} className="hover:text-teal-400">Scan History</button></li>
              </ul>
            </div>

            <div className="space-y-2">
              <span className="font-semibold text-slate-200 block">Resources</span>
              <ul className="space-y-1">
                <li><button onClick={() => onNavigate('how-it-works')} className="hover:text-teal-400">How It Works</button></li>
                <li><button onClick={() => onNavigate('about')} className="hover:text-teal-400">About &amp; Principles</button></li>
                <li><span className="text-slate-400">API Documentation (Configurable)</span></li>
                <li><span className="text-slate-400">ML Pipeline Roadmap</span></li>
              </ul>
            </div>

            <div className="space-y-2">
              <span className="font-semibold text-slate-200 block">Legal &amp; Safety</span>
              <ul className="space-y-1">
                <li><span className="text-slate-400">Privacy Policy (Local storage only)</span></li>
                <li><span className="text-slate-400">Terms of Service</span></li>
                <li><span className="text-slate-400">Responsible Disclosure</span></li>
                <li><span className="text-slate-400">Contact: support@example.com [Demo placeholder]</span></li>
              </ul>
            </div>
          </div>

          <div className="pt-6 border-t border-slate-800/60 flex flex-col sm:flex-row items-center justify-between gap-4 text-slate-400">
            <span>&copy; {new Date().getFullYear()} VerifyBeforeBuy AI. Open-access consumer protection.</span>
            <span>Preliminary risk assessment · Not physical proof of authenticity</span>
          </div>
        </div>
      </footer>
    </div>
  );
};
