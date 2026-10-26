/**
 * VerifyBeforeBuy AI — About & Principles Page
 * Project overview, consumer rights commitment, safe shopping checklist,
 * and technical boundaries.
 */

import React from 'react';
import {
  Shield,
  HeartHandshake,
  CheckCircle2,
  Lock,
  Layers,
  FileCheck2,
  AlertTriangle,
  Github,
  Mail,
} from 'lucide-react';
import { NavTab } from '../components/Navbar';

interface AboutPageProps {
  onNavigate: (tab: NavTab) => void;
}

export const AboutPage: React.FC<AboutPageProps> = ({ onNavigate }) => {
  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-12">
      {/* Header */}
      <div className="space-y-3">
        <div className="inline-flex items-center gap-2 text-xs font-semibold text-teal-400 bg-teal-950/60 px-3 py-1 rounded-full border border-teal-800/60">
          <Shield className="w-3.5 h-3.5" />
          <span>About VerifyBeforeBuy AI</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          Protecting Everyday Consumers Online
        </h1>
        <p className="text-sm text-slate-400 max-w-2xl leading-relaxed">
          Online shoppers encounter sophisticated lookalike stores, deceptive discounts, and fraudulent listings. Our mission is to democratize cybersecurity intelligence with clear, unbiased risk assessments.
        </p>
      </div>

      {/* Mission & Guiding Principles */}
      <section className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 sm:p-8 space-y-6">
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <HeartHandshake className="w-5 h-5 text-teal-400" />
          <span>Our Guiding Principles</span>
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="space-y-2">
            <h3 className="text-sm font-semibold text-teal-300">1. Evidence-Based Humility</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              We never claim that a website is 100% fraudulent or that a product is guaranteed genuine based solely on automated heuristic scores. Risk is a probabilistic indicator of caution.
            </p>
          </div>

          <div className="space-y-2">
            <h3 className="text-sm font-semibold text-sky-300">2. Anti-Bias Fairness</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Legitimate retailers run genuine 80%+ discount clearance promotions. We evaluate evidence holistically without penalizing legitimate bargain hunters.
            </p>
          </div>

          <div className="space-y-2">
            <h3 className="text-sm font-semibold text-emerald-300">3. Privacy by Default</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Scan records remain stored locally in your browser by default. We do not sell shopping telemetry, track personal browsing, or collect private cookies.
            </p>
          </div>
        </div>
      </section>

      {/* Safe Shopping Checklist */}
      <section className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 sm:p-8 space-y-6">
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <FileCheck2 className="w-5 h-5 text-teal-400" />
          <span>Practical Safe Shopping Checklist</span>
        </h2>

        <div className="space-y-3">
          {[
            'Inspect the browser address bar for the exact domain spelling immediately before the first forward slash.',
            'Always use credit cards or virtual payment cards with $0 fraud liability and formal dispute mechanisms.',
            'Confirm the presence of verifiable company registration, corporate street address, and customer phone support.',
            'Check for explicit return policies that provide at least a 14–30 day window for refund or exchange.',
            'Never send funds via peer-to-peer wire transfers, cryptocurrency, or gift cards for retail goods.',
            'Be aware that physical counterfeits can feature perfectly duplicated legitimate barcodes.',
          ].map((item, idx) => (
            <div
              key={idx}
              className="p-3.5 bg-slate-950/60 border border-slate-800 rounded-lg flex items-start gap-3 text-xs text-slate-200"
            >
              <CheckCircle2 className="w-4 h-4 text-teal-400 shrink-0 mt-0.5" />
              <span>{item}</span>
            </div>
          ))}
        </div>
      </section>

      {/* Technical Stack Overview */}
      <section className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 sm:p-8 space-y-4">
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <Layers className="w-5 h-5 text-purple-400" />
          <span>Technology &amp; Architectural Stack</span>
        </h2>

        <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 text-xs">
          <div className="p-3 bg-slate-950/70 border border-slate-800 rounded-lg">
            <span className="text-slate-400 block text-[10px] uppercase font-mono">Frontend</span>
            <span className="text-white font-semibold">React 19 &amp; TypeScript</span>
          </div>
          <div className="p-3 bg-slate-950/70 border border-slate-800 rounded-lg">
            <span className="text-slate-400 block text-[10px] uppercase font-mono">Styling</span>
            <span className="text-white font-semibold">Tailwind CSS v4</span>
          </div>
          <div className="p-3 bg-slate-950/70 border border-slate-800 rounded-lg">
            <span className="text-slate-400 block text-[10px] uppercase font-mono">Backend Engine</span>
            <span className="text-white font-semibold">Express &amp; SSRF Shield</span>
          </div>
          <div className="p-3 bg-slate-950/70 border border-slate-800 rounded-lg">
            <span className="text-slate-400 block text-[10px] uppercase font-mono">AI Explanation</span>
            <span className="text-white font-semibold">Gemini 3.8 Flash (@google/genai)</span>
          </div>
          <div className="p-3 bg-slate-950/70 border border-slate-800 rounded-lg">
            <span className="text-slate-400 block text-[10px] uppercase font-mono">Database</span>
            <span className="text-white font-semibold">Supabase PostgreSQL &amp; LocalStorage</span>
          </div>
          <div className="p-3 bg-slate-950/70 border border-slate-800 rounded-lg">
            <span className="text-slate-400 block text-[10px] uppercase font-mono">Hardware Scanning</span>
            <span className="text-white font-semibold">Html5Qrcode GS1 Engine</span>
          </div>
        </div>
      </section>

      {/* Limitations Disclaimer */}
      <div className="p-4 bg-slate-950/90 border border-slate-800 rounded-lg text-xs text-slate-400 leading-relaxed">
        <strong className="text-slate-300 block mb-1">Notice of Technical Limitations:</strong>
        VerifyBeforeBuy AI is a risk-assessment research prototype. It does not warrant or guarantee that an inspected merchant, domain, or product listing is completely secure, free of deception, fraudulent, genuine, or counterfeit. Consumers must always exercise independent prudence when executing financial transactions.
      </div>
    </div>
  );
};
