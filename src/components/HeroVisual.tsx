/**
 * Original Security & Shopping Risk CSS/SVG Illustration
 * Depicts shopping package, security shield, and risk diagnostic indicators.
 */

import React from 'react';
import { Shield, CheckCircle, AlertCircle, FileText, Lock, QrCode } from 'lucide-react';

export const HeroVisual: React.FC = () => {
  return (
    <div className="relative w-full max-w-lg mx-auto aspect-square flex items-center justify-center p-4">
      {/* Background ambient radial ring */}
      <div className="absolute inset-4 rounded-full bg-gradient-to-tr from-teal-500/10 via-sky-500/5 to-transparent blur-2xl" />

      {/* Main Structural Frame */}
      <div className="relative w-full bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-2xl backdrop-blur-sm space-y-5">
        {/* Top Simulated Applet Bar */}
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-4">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-rose-500/80" />
            <div className="w-3 h-3 rounded-full bg-amber-500/80" />
            <div className="w-3 h-3 rounded-full bg-emerald-500/80" />
          </div>
          <span className="text-[11px] font-mono text-slate-400">
            verifybeforebuy.ai / live-telemetry
          </span>
          <Lock className="w-3.5 h-3.5 text-teal-400" />
        </div>

        {/* Central Inspection Diagnostic */}
        <div className="grid grid-cols-5 gap-4 items-center">
          {/* Shopping Package Icon Box */}
          <div className="col-span-2 bg-slate-950/80 border border-slate-800 rounded-xl p-4 flex flex-col items-center justify-center text-center space-y-2">
            <div className="w-12 h-12 rounded-lg bg-teal-500/10 border border-teal-500/30 flex items-center justify-center text-teal-400">
              <QrCode className="w-6 h-6" />
            </div>
            <span className="text-xs font-semibold text-slate-200">Listing Asset</span>
            <span className="text-[10px] text-slate-500 font-mono">ID: 027242919419</span>
          </div>

          {/* Connection Vector with Shield */}
          <div className="col-span-1 flex flex-col items-center justify-center">
            <div className="w-9 h-9 rounded-full bg-teal-950 border border-teal-500/40 flex items-center justify-center text-teal-400 shadow-md">
              <Shield className="w-5 h-5 fill-teal-400/20" />
            </div>
            <div className="h-4 w-0.5 bg-slate-800 my-1" />
            <span className="text-[9px] font-mono text-teal-400 uppercase">Analyzed</span>
          </div>

          {/* Calibrated Risk Score Pill */}
          <div className="col-span-2 bg-slate-950/80 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
            <span className="text-[10px] uppercase font-semibold text-slate-400">Assessed Risk</span>
            <div className="flex items-baseline gap-1 my-1">
              <span className="text-3xl font-extrabold font-mono text-emerald-400 tabular-nums">12</span>
              <span className="text-xs text-slate-500 font-mono">/ 100</span>
            </div>
            <span className="text-[10px] text-emerald-400 font-medium">Lower Assessed Risk</span>
          </div>
        </div>

        {/* Live Indicator Signals */}
        <div className="space-y-2 pt-2 border-t border-slate-800/80">
          <div className="p-2.5 bg-slate-950/50 border border-slate-800/60 rounded-lg flex items-center justify-between text-xs">
            <div className="flex items-center gap-2">
              <CheckCircle className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              <span className="text-slate-300">Domain structure syntax</span>
            </div>
            <span className="text-[10px] font-mono text-slate-400">Standard HTTPS</span>
          </div>

          <div className="p-2.5 bg-slate-950/50 border border-slate-800/60 rounded-lg flex items-center justify-between text-xs">
            <div className="flex items-center gap-2">
              <AlertCircle className="w-3.5 h-3.5 text-sky-400 shrink-0" />
              <span className="text-slate-300">Listed price comparison</span>
            </div>
            <span className="text-[10px] font-mono text-slate-400">Clearance range</span>
          </div>

          <div className="p-2.5 bg-slate-950/50 border border-slate-800/60 rounded-lg flex items-center justify-between text-xs">
            <div className="flex items-center gap-2">
              <FileText className="w-3.5 h-3.5 text-teal-400 shrink-0" />
              <span className="text-slate-300">Buyer dispute protection</span>
            </div>
            <span className="text-[10px] font-mono text-slate-400">30-day window</span>
          </div>
        </div>

        {/* Disclaimer subtext */}
        <div className="text-[10px] text-slate-500 text-center pt-1 font-sans">
          Preliminary risk assessment · Does not guarantee product authenticity
        </div>
      </div>
    </div>
  );
};
