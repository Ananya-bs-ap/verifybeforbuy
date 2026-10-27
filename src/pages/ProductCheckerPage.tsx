/**
 * VerifyBeforeBuy AI — Product Risk Checker Page
 * Redesigned with a warm, human-crafted light SaaS aesthetic.
 */

import React, { useState } from 'react';
import { Package, Search, AlertCircle, Loader2 } from 'lucide-react';
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
      desc: 'Steep price with replica keywords and wire transfer demands.',
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
      desc: 'Shows how the engine reports low evidence coverage without penalizing missing data.',
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
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Page Header */}
      <div className="space-y-3">
        <div className="inline-flex items-center gap-2 text-xs font-bold text-violet-700 bg-violet-50 px-3 py-1 rounded-full border border-violet-100">
          <Package className="w-3.5 h-3.5" />
          <span>Product Listing &amp; Seller Risk Assessor</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-slate-900 tracking-tight">
          Evaluate a Product Listing
        </h1>
        <p className="text-sm text-slate-600 max-w-2xl leading-relaxed">
          Screen listed pricing against reference MSRP, check seller accountability, inspect descriptions for imitation phrasing, and review dispute protections.
        </p>
      </div>

      {/* Preset Test Case Chips */}
      <div className="bg-white border border-slate-200/80 rounded-2xl p-6 shadow-sm space-y-3">
        <div className="text-xs font-bold uppercase text-slate-500 tracking-wider">
          Quick Test Presets (Click to autofill)
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {presets.map((p, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => handleApplyPreset(p.data)}
              className="p-3.5 bg-slate-50 hover:bg-violet-50/50 border border-slate-200 hover:border-violet-200 rounded-xl text-left transition-colors space-y-1 group"
            >
              <div className="text-xs font-bold text-slate-800 group-hover:text-violet-700 transition-colors">
                {p.label}
              </div>
              <div className="text-[11px] text-slate-500 leading-tight">
                {p.desc}
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Main Form */}
      <div className="bg-white border border-slate-200/80 rounded-2xl p-6 sm:p-8 shadow-xl shadow-slate-200/50">
        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-1.5 md:col-span-2">
              <label className="block text-xs font-bold uppercase text-slate-700 tracking-wider">
                Product Name <span className="text-rose-600">*</span>
              </label>
              <input
                type="text"
                required
                value={formData.productName}
                onChange={(e) => setFormData({ ...formData, productName: e.target.value })}
                placeholder="e.g., Apple AirPods Pro (2nd Generation)"
                className="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white"
              />
            </div>

            <div className="space-y-1.5">
              <label className="block text-xs font-bold uppercase text-slate-700 tracking-wider">
                Brand / Manufacturer
              </label>
              <input
                type="text"
                value={formData.brand || ''}
                onChange={(e) => setFormData({ ...formData, brand: e.target.value })}
                placeholder="e.g., Sony, Apple, Nike"
                className="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white"
              />
            </div>

            <div className="space-y-1.5">
              <label className="block text-xs font-bold uppercase text-slate-700 tracking-wider">
                Product Identifier / UPC / GTIN (Optional)
              </label>
              <input
                type="text"
                value={formData.productIdentifier || ''}
                onChange={(e) => setFormData({ ...formData, productIdentifier: e.target.value })}
                placeholder="e.g., 012000000133"
                className="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white font-mono"
              />
            </div>

            <div className="space-y-1.5">
              <label className="block text-xs font-bold uppercase text-slate-700 tracking-wider">
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
                className="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white font-mono"
              />
            </div>

            <div className="space-y-1.5">
              <label className="block text-xs font-bold uppercase text-slate-700 tracking-wider">
                Typical Market / MSRP Price (Optional)
              </label>
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
                className="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white font-mono"
              />
            </div>

            <div className="space-y-1.5">
              <label className="block text-xs font-bold uppercase text-slate-700 tracking-wider">
                Seller Handle or Merchant Name
              </label>
              <input
                type="text"
                value={formData.sellerName || ''}
                onChange={(e) => setFormData({ ...formData, sellerName: e.target.value })}
                placeholder="e.g., BestBuy Direct"
                className="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white"
              />
            </div>

            <div className="space-y-1.5">
              <label className="block text-xs font-bold uppercase text-slate-700 tracking-wider">
                Seller Rating (0 - 5.0)
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
                className="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white font-mono"
              />
            </div>

            <div className="space-y-1.5 md:col-span-2">
              <label className="block text-xs font-bold uppercase text-slate-700 tracking-wider">
                Product Description or Seller Notes
              </label>
              <textarea
                rows={3}
                value={formData.productDescription || ''}
                onChange={(e) => setFormData({ ...formData, productDescription: e.target.value })}
                placeholder="Paste the seller description, terms, warranty statements..."
                className="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white"
              />
            </div>

            <div className="space-y-1.5 md:col-span-2">
              <div className="flex items-center gap-3 p-4 bg-slate-50 border border-slate-200 rounded-xl">
                <input
                  type="checkbox"
                  id="return-policy-toggle"
                  checked={formData.hasReturnPolicy ?? true}
                  onChange={(e) => setFormData({ ...formData, hasReturnPolicy: e.target.checked })}
                  className="w-4 h-4 text-indigo-600 bg-white border-slate-300 rounded focus:ring-indigo-500"
                />
                <label htmlFor="return-policy-toggle" className="text-xs text-slate-700 cursor-pointer">
                  <span className="font-bold block">Listing states returns or buyer guarantee are accepted</span>
                  <span className="text-slate-500">Unchecking indicates &ldquo;as-is / no returns / final sale&rdquo;</span>
                </label>
              </div>
            </div>
          </div>

          {errorMessage && (
            <div className="p-3.5 bg-rose-50 border border-rose-200 rounded-xl text-xs text-rose-700 flex items-center gap-2 font-medium">
              <AlertCircle className="w-4 h-4 shrink-0 text-rose-600" />
              <span>{errorMessage}</span>
            </div>
          )}

          <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-4 border-t border-slate-100">
            <div className="text-[11px] text-slate-500 font-medium">
              Anti-bias rule: High discounts do not trigger counterfeit verdicts on their own.
            </div>
            <button
              type="submit"
              disabled={isLoading}
              className="w-full sm:w-auto px-8 py-3.5 text-sm font-bold text-white bg-indigo-600 hover:bg-indigo-700 rounded-xl transition-colors disabled:opacity-50 flex items-center justify-center gap-2 shadow-md shadow-indigo-500/20"
            >
              <Search className="w-4 h-4" />
              <span>{isLoading ? 'Assessing Listing...' : 'Assess Product Listing'}</span>
            </button>
          </div>
        </form>
      </div>

      {currentResult && (
        <div className="pt-4">
          <VerificationReport
            result={currentResult}
            onReset={() => setCurrentResult(null)}
          />
        </div>
      )}
    </div>
  );
};
