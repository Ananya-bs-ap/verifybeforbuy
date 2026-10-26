/**
 * VerifyBeforeBuy AI — Product Risk Checker Page
 * Multi-factor product & seller listing evaluation form.
 * Strictly adheres to rule: Steep discount != counterfeit proof.
 */

import React, { useState } from 'react';
import { Package, Search, AlertCircle, Sparkles, ArrowRight, ShieldCheck, HelpCircle } from 'lucide-react';
import { ProductAnalysisInput, AssessmentResult } from '../types';
import { ApiService } from '../lib/api';
import { HistoryService } from '../lib/supabase/historyService';
import { VerificationReport } from '../components/VerificationReport';

export const ProductCheckerPage: React.FC = () => {
  const [formData, setFormData] = useState<ProductAnalysisInput>({
    productName: '',
    brand: '',
    listingUrl: '',
    listedPrice: undefined,
    referencePrice: undefined,
    sellerName: '',
    sellerRating: undefined,
    hasReturnPolicy: true,
    productDescription: '',
    productIdentifier: '',
    sourcePlatform: 'marketplace',
  });

  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [currentResult, setCurrentResult] = useState<AssessmentResult | null>(null);

  const presets = [
    {
      label: 'Legitimate 88% Clearance Sale',
      desc: 'Authentic brand recertified liquidation with return guarantees.',
      data: {
        productName: 'Sony WH-1000XM4 Wireless Noise Cancelling Headphones (Refurbished)',
        brand: 'Sony',
        listingUrl: 'https://www.ebay.com/itm/123456789',
        listedPrice: 39.99,
        referencePrice: 349.99,
        sellerName: 'DirectRecertifiedAudio',
        sellerRating: 4.8,
        hasReturnPolicy: true,
        productDescription: 'Official factory refurbished clearance. 30-day return policy and full original accessories included.',
        productIdentifier: '027242919419',
        sourcePlatform: 'eBay Certified Refurbished',
      },
    },
    {
      label: 'Suspicious Luxury Watch Listing',
      desc: 'Steep price with replica keywords and peer-to-peer wire transfer demands.',
      data: {
        productName: 'Rolex Submariner Date 41mm Black Ceramic Oyster',
        brand: 'Rolex',
        listingUrl: 'https://luxury-outlet-deals.xyz/item/sub41',
        listedPrice: 199.00,
        referencePrice: 10250.00,
        sellerName: 'deals_king_99',
        sellerRating: 2.1,
        hasReturnPolicy: false,
        productDescription: 'Brand new 1:1 replica mirror copy original grade clone. Western Union or wire transfer only. No disputes.',
        productIdentifier: '126610LN',
        sourcePlatform: 'Independent Classifieds',
      },
    },
    {
      label: 'Incomplete Listing (Minimal Details)',
      desc: 'Shows how the engine reports low evidence coverage rather than penalizing missing data.',
      data: {
        productName: 'Handcrafted Japanese Chef Knife',
        brand: 'Artisan Workshop',
        listingUrl: '',
        listedPrice: 85.00,
        referencePrice: undefined,
        sellerName: '',
        sellerRating: undefined,
        hasReturnPolicy: true,
        productDescription: 'High carbon steel kitchen knife with wooden handle.',
        productIdentifier: '',
        sourcePlatform: 'Etsy',
      },
    },
  ];

  const handleApplyPreset = (presetData: ProductAnalysisInput) => {
    setFormData(presetData);
    setErrorMessage(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    if (!formData.productName.trim()) {
      setErrorMessage('Product name is required.');
      return;
    }

    setIsLoading(true);
    try {
      const result = await ApiService.analyzeProduct(formData);
      setCurrentResult(result);
      await HistoryService.saveRecord(result);
    } catch (err: any) {
      setErrorMessage(err.message || 'Product evaluation failed.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Page Header */}
      <div className="space-y-3">
        <div className="inline-flex items-center gap-2 text-xs font-semibold text-sky-400 bg-sky-950/60 px-3 py-1 rounded-full border border-sky-800/60">
          <Package className="w-3.5 h-3.5" />
          <span>Product Listing &amp; Seller Risk Assessor</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          Evaluate a Product Listing
        </h1>
        <p className="text-sm text-slate-400 max-w-2xl leading-relaxed">
          Screen listed pricing against reference MSRP, check seller accountability, inspect descriptions for imitation phrasing, and review dispute protections.
        </p>
      </div>

      {/* Preset Test Case Chips */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 space-y-3">
        <div className="text-xs font-semibold uppercase text-slate-400 tracking-wider">
          Quick Test Presets (Click to autofill)
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {presets.map((p, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => handleApplyPreset(p.data)}
              className="p-3 bg-slate-950/70 hover:bg-slate-800/80 border border-slate-800 rounded-lg text-left transition-colors space-y-1 group"
            >
              <div className="text-xs font-semibold text-slate-200 group-hover:text-teal-300 transition-colors">
                {p.label}
              </div>
              <div className="text-[11px] text-slate-400 leading-tight">
                {p.desc}
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Main Form */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 sm:p-8 shadow-xl">
        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* 1. Product Name */}
            <div className="space-y-1.5 md:col-span-2">
              <label className="block text-xs font-semibold uppercase text-slate-300 tracking-wider">
                Product Name <span className="text-rose-400">*</span>
              </label>
              <input
                type="text"
                required
                value={formData.productName}
                onChange={(e) => setFormData({ ...formData, productName: e.target.value })}
                placeholder="e.g., Apple AirPods Pro (2nd Generation) with MagSafe Case"
                className="w-full px-4 py-2.5 bg-slate-950 border border-slate-700 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-teal-400"
              />
            </div>

            {/* 2. Brand */}
            <div className="space-y-1.5">
              <label className="block text-xs font-semibold uppercase text-slate-300 tracking-wider">
                Brand / Manufacturer
              </label>
              <input
                type="text"
                value={formData.brand || ''}
                onChange={(e) => setFormData({ ...formData, brand: e.target.value })}
                placeholder="e.g., Sony, Apple, Nike, Dyson"
                className="w-full px-4 py-2.5 bg-slate-950 border border-slate-700 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-teal-400"
              />
            </div>

            {/* 3. Product Identifier (UPC / SKU) */}
            <div className="space-y-1.5">
              <label className="block text-xs font-semibold uppercase text-slate-300 tracking-wider">
                Product Identifier / UPC / GTIN (Optional)
              </label>
              <input
                type="text"
                value={formData.productIdentifier || ''}
                onChange={(e) => setFormData({ ...formData, productIdentifier: e.target.value })}
                placeholder="e.g., 012000000133, 190199220019"
                className="w-full px-4 py-2.5 bg-slate-950 border border-slate-700 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-teal-400 font-mono"
              />
            </div>

            {/* 4. Listed Price */}
            <div className="space-y-1.5">
              <label className="block text-xs font-semibold uppercase text-slate-300 tracking-wider">
                Listed Price (USD)
              </label>
              <input
                type="number"
                step="0.01"
                min="0"
                value={formData.listedPrice ?? ''}
                onChange={(e) =>
                  setFormData({
                    ...formData,
                    listedPrice: e.target.value ? parseFloat(e.target.value) : undefined,
                  })
                }
                placeholder="e.g., 49.99"
                className="w-full px-4 py-2.5 bg-slate-950 border border-slate-700 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-teal-400 font-mono"
              />
            </div>

            {/* 5. Reference or MSRP Price */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="block text-xs font-semibold uppercase text-slate-300 tracking-wider">
                  Typical Market / MSRP Price (Optional)
                </label>
                <span className="text-[10px] text-slate-400">Used for discount calculation</span>
              </div>
              <input
                type="number"
                step="0.01"
                min="0"
                value={formData.referencePrice ?? ''}
                onChange={(e) =>
                  setFormData({
                    ...formData,
                    referencePrice: e.target.value ? parseFloat(e.target.value) : undefined,
                  })
                }
                placeholder="e.g., 249.99"
                className="w-full px-4 py-2.5 bg-slate-950 border border-slate-700 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-teal-400 font-mono"
              />
            </div>

            {/* 6. Seller Name */}
            <div className="space-y-1.5">
              <label className="block text-xs font-semibold uppercase text-slate-300 tracking-wider">
                Seller Handle or Merchant Name
              </label>
              <input
                type="text"
                value={formData.sellerName || ''}
                onChange={(e) => setFormData({ ...formData, sellerName: e.target.value })}
                placeholder="e.g., BestBuy Direct, TechSuperStore, user_9214"
                className="w-full px-4 py-2.5 bg-slate-950 border border-slate-700 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-teal-400"
              />
            </div>

            {/* 7. Seller Rating */}
            <div className="space-y-1.5">
              <label className="block text-xs font-semibold uppercase text-slate-300 tracking-wider">
                Reported Seller Rating (0 - 5.0)
              </label>
              <input
                type="number"
                step="0.1"
                min="0"
                max="5"
                value={formData.sellerRating ?? ''}
                onChange={(e) =>
                  setFormData({
                    ...formData,
                    sellerRating: e.target.value ? parseFloat(e.target.value) : undefined,
                  })
                }
                placeholder="e.g., 4.7"
                className="w-full px-4 py-2.5 bg-slate-950 border border-slate-700 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-teal-400 font-mono"
              />
            </div>

            {/* 8. Listing URL */}
            <div className="space-y-1.5 md:col-span-2">
              <label className="block text-xs font-semibold uppercase text-slate-300 tracking-wider">
                Product Listing Web Address (Optional)
              </label>
              <input
                type="text"
                value={formData.listingUrl || ''}
                onChange={(e) => setFormData({ ...formData, listingUrl: e.target.value })}
                placeholder="https://marketplace.com/item/12345"
                className="w-full px-4 py-2.5 bg-slate-950 border border-slate-700 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-teal-400 font-mono"
              />
            </div>

            {/* 9. Description */}
            <div className="space-y-1.5 md:col-span-2">
              <label className="block text-xs font-semibold uppercase text-slate-300 tracking-wider">
                Product Description or Seller Notes
              </label>
              <textarea
                rows={3}
                value={formData.productDescription || ''}
                onChange={(e) => setFormData({ ...formData, productDescription: e.target.value })}
                placeholder="Paste the seller description, terms, warranty statements, or shipping requirements..."
                className="w-full px-4 py-2.5 bg-slate-950 border border-slate-700 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-teal-400"
              />
            </div>

            {/* 10. Return Policy Toggle */}
            <div className="space-y-1.5 md:col-span-2">
              <div className="flex items-center gap-3 p-4 bg-slate-950/70 border border-slate-800 rounded-xl">
                <input
                  type="checkbox"
                  id="return-policy-toggle"
                  checked={formData.hasReturnPolicy ?? true}
                  onChange={(e) => setFormData({ ...formData, hasReturnPolicy: e.target.checked })}
                  className="w-4 h-4 text-teal-400 bg-slate-900 border-slate-700 rounded focus:ring-teal-400"
                />
                <label htmlFor="return-policy-toggle" className="text-xs text-slate-200 cursor-pointer">
                  <span className="font-semibold block">Listing states returns or buyer guarantee are accepted</span>
                  <span className="text-slate-400">Unchecking indicates “as-is / no returns / final sale”</span>
                </label>
              </div>
            </div>
          </div>

          {errorMessage && (
            <div className="p-3 bg-rose-950/60 border border-rose-900/60 rounded-lg text-xs text-rose-300 flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
              <span>{errorMessage}</span>
            </div>
          )}

          <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-4 border-t border-slate-800">
            <div className="text-[11px] text-slate-400">
              Anti-bias policy: High discounts do not trigger counterfeit verdicts on their own.
            </div>
            <button
              type="submit"
              disabled={isLoading}
              className="w-full sm:w-auto px-8 py-3 text-sm font-semibold text-slate-950 bg-teal-400 hover:bg-teal-300 rounded-xl transition-colors disabled:opacity-50 flex items-center justify-center gap-2 shadow-sm"
            >
              <Search className="w-4 h-4" />
              <span>{isLoading ? 'Assessing Listing...' : 'Assess Product Listing'}</span>
            </button>
          </div>
        </form>
      </div>

      {/* Assessment Report View */}
      {currentResult && (
        <div className="pt-4">
          <VerificationReport
            result={currentResult}
            onReset={() => {
              setCurrentResult(null);
            }}
          />
        </div>
      )}
    </div>
  );
};
