/**
 * VerifyBeforeBuy AI — Product Risk Checker Page
 * Redesigned with a warm, human-crafted light SaaS aesthetic.
 */

import React, { useEffect, useState } from 'react';
import {
  Package,
  Search,
  AlertCircle,
  Cpu,
  AlertTriangle,
  Loader2,
  Globe,
  CheckCircle2,
  Info,
} from 'lucide-react';
import {
  ProductAnalysisInput,
  AssessmentResult,
  ReturnPolicyStatus,
  MlModelMetrics,
  ProductFetchDetailsResponse,
} from '../types';
import { ApiService } from '../lib/api';
import { HistoryService } from '../lib/supabase/historyService';
import { VerificationReport } from '../components/VerificationReport';
import { validateProductInput } from '../lib/productValidator';
import { validateWebsiteUrl } from '../lib/urlValidator';

interface ProductModelInfoState {
  modelType: string;
  dataset: string;
  totalDatasetRows: number;
  samplesTrained: number;
  samplesTested: number;
  isSyntheticDataset: boolean;
  featureCount: number;
  metrics: MlModelMetrics;
}

const COMMON_CURRENCIES = ['USD', 'INR', 'EUR', 'GBP', 'CAD', 'AUD', 'JPY'];

export const ProductCheckerPage: React.FC = () => {
  const [formData, setFormData] = useState<ProductAnalysisInput>({
    productName: '',
    brand: '',
    listingUrl: '',
    listedPrice: undefined,
    referencePrice: undefined,
    currency: 'USD',
    referenceCurrency: 'USD',
    sellerName: '',
    sellerRating: undefined,
    returnPolicyStatus: 'unknown',
    hasReturnPolicy: undefined,
    productDescription: '',
    productIdentifier: '',
    sourcePlatform: 'marketplace',
  });

  const [isLoading, setIsLoading] = useState(false);
  const [isFetchingDetails, setIsFetchingDetails] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [fetchResult, setFetchResult] = useState<ProductFetchDetailsResponse | null>(null);
  const [fieldSources, setFieldSources] = useState<Record<string, string>>({});
  const [currentResult, setCurrentResult] = useState<AssessmentResult | null>(null);
  const [modelInfo, setModelInfo] = useState<ProductModelInfoState | null>(null);

  useEffect(() => {
    let mounted = true;
    ApiService.getProductModelInfo()
      .then((info) => {
        if (mounted && info) {
          setModelInfo(info as ProductModelInfoState);
        }
      })
      .catch((err) => {
        console.warn('Could not load product model metadata:', err);
      });
    return () => {
      mounted = false;
    };
  }, []);

  const presets: Array<{ label: string; desc: string; data: ProductAnalysisInput }> = [
    {
      label: 'Legitimate 88% Clearance Sale',
      desc: 'Authentic brand recertified liquidation with return guarantees.',
      data: {
        productName: 'Sony WH-1000XM4 Wireless Noise Cancelling Headphones (Refurbished)',
        brand: 'Sony',
        listingUrl: 'https://www.ebay.com/itm/123456789',
        listedPrice: 39.99,
        referencePrice: 349.99,
        currency: 'USD',
        referenceCurrency: 'USD',
        sellerName: 'DirectRecertifiedAudio',
        sellerRating: 4.8,
        returnPolicyStatus: 'available',
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
        currency: 'USD',
        referenceCurrency: 'USD',
        sellerName: 'deals_king_99',
        sellerRating: 2.1,
        returnPolicyStatus: 'not_available',
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
        currency: 'USD',
        referenceCurrency: 'USD',
        sellerName: '',
        sellerRating: undefined,
        returnPolicyStatus: 'unknown',
        hasReturnPolicy: undefined,
        productDescription: 'High carbon steel kitchen knife with wooden handle.',
        productIdentifier: '',
        sourcePlatform: 'Etsy',
      },
    },
  ];

  const handleApplyPreset = (presetData: ProductAnalysisInput) => {
    setFormData(presetData);
    setErrorMessage(null);
    setFetchError(null);
    setFetchResult(null);
    setFieldSources({});
  };

  const handleReturnPolicyChange = (status: ReturnPolicyStatus) => {
    setFormData((prev) => ({
      ...prev,
      returnPolicyStatus: status,
      hasReturnPolicy: status === 'available' ? true : status === 'not_available' ? false : undefined,
    }));
  };

  const updateField = <K extends keyof ProductAnalysisInput>(key: K, value: ProductAnalysisInput[K]) => {
    setFormData((prev) => ({ ...prev, [key]: value }));
    if (fieldSources[key as string]) {
      setFieldSources((prev) => ({ ...prev, [key as string]: 'Manually Edited' }));
    }
  };

  const handleFetchDetails = async () => {
    setFetchError(null);
    setFetchResult(null);
    setErrorMessage(null);

    const rawUrl = (formData.listingUrl || '').trim();
    const urlCheck = validateWebsiteUrl(rawUrl);
    if (!urlCheck.valid || !urlCheck.normalizedUrl) {
      setFetchError(
        urlCheck.error || 'Invalid URL. Please enter a valid http:// or https:// listing URL before fetching.'
      );
      return;
    }

    setIsFetchingDetails(true);
    try {
      const res = await ApiService.fetchProductDetails(urlCheck.normalizedUrl);
      setFetchResult(res);

      if (res.success && res.extracted) {
        const ext = res.extracted;
        const resolvedCurrency = ext.currency || formData.currency || 'USD';
        setFormData({
          productName: ext.productName || '',
          brand: ext.brand || '',
          listingUrl: res.finalUrl || urlCheck.normalizedUrl,
          listedPrice: ext.listedPrice,
          referencePrice: ext.referencePrice,
          currency: resolvedCurrency,
          referenceCurrency: ext.referenceCurrency || resolvedCurrency,
          sellerName: ext.sellerName || '',
          sellerRating: ext.sellerRating,
          returnPolicyStatus: ext.returnPolicyStatus || 'unknown',
          hasReturnPolicy:
            ext.returnPolicyStatus === 'available'
              ? true
              : ext.returnPolicyStatus === 'not_available'
                ? false
                : undefined,
          productDescription: ext.productDescription || '',
          productIdentifier: ext.productIdentifier || '',
          sourcePlatform: ext.sourcePlatform || res.marketplace || 'marketplace',
        });
        setFieldSources(res.fieldSources || {});
      } else {
        setFieldSources({});
      }
    } catch (err: any) {
      setFetchError(
        err?.message || 'Unable to extract product metadata from this URL. Please continue with manual entry.'
      );
      setFieldSources({});
    } finally {
      setIsFetchingDetails(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    const validation = validateProductInput(formData);
    if (!validation.valid || !validation.normalizedInput) {
      setCurrentResult(null);
      setErrorMessage(validation.error || 'Please check your product listing inputs.');
      return;
    }

    setIsLoading(true);
    try {
      const result = await ApiService.analyzeProduct(validation.normalizedInput);
      setCurrentResult(result);
      await HistoryService.saveRecord(result);
    } catch (err: any) {
      setCurrentResult(null);
      setErrorMessage(err.message || 'Product evaluation failed.');
    } finally {
      setIsLoading(false);
    }
  };

  const renderSourceBadge = (fieldKey: string) => {
    const src = fieldSources[fieldKey];
    if (!src) return null;
    const isManual = src === 'Manually Edited';
    return (
      <span
        className={`text-[10px] font-medium px-1.5 py-0.5 rounded border ${
          isManual
            ? 'bg-slate-100 text-slate-600 border-slate-200'
            : 'bg-indigo-50 text-indigo-700 border-indigo-200'
        }`}
      >
        Source: {src}
      </span>
    );
  };

  const returnPolicyStatus = formData.returnPolicyStatus ?? 'unknown';
  const activeCurrency = (formData.currency || 'USD').toUpperCase();
  const currencyOptions = COMMON_CURRENCIES.includes(activeCurrency)
    ? COMMON_CURRENCIES
    : [activeCurrency, ...COMMON_CURRENCIES];

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
          Screen listed pricing against reference MSRP, check GS1 barcode checksums, evaluate seller accountability, and screen listing URLs for phishing risk.
        </p>

        {/* Dynamic Machine Learning Subsystem Banner */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 text-white text-xs space-y-2.5 mt-2 shadow-md">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-2 font-bold text-slate-100">
              <Cpu className="w-4 h-4 text-violet-400" />
              <span>Trained ML Product Risk Classifier: Active</span>
              {modelInfo ? (
                <span className="bg-emerald-500/20 text-emerald-300 text-[10px] font-mono px-2 py-0.5 rounded border border-emerald-500/30">
                  {(modelInfo.metrics.accuracy * 100).toFixed(2)}% Holdout Accuracy
                </span>
              ) : (
                <span className="bg-slate-800 text-slate-300 text-[10px] font-mono px-2 py-0.5 rounded border border-slate-700">
                  Loading model metadata...
                </span>
              )}
              {modelInfo?.isSyntheticDataset && (
                <span className="bg-amber-500/20 text-amber-300 text-[10px] font-mono px-2 py-0.5 rounded border border-amber-500/30">
                  Synthetic Training Corpus
                </span>
              )}
            </div>
            {modelInfo && (
              <div className="flex items-center gap-2 text-[11px] font-mono text-slate-400">
                <span className="bg-slate-800 px-2 py-0.5 rounded text-violet-300">
                  Corpus: {modelInfo.totalDatasetRows.toLocaleString()} Listings ({modelInfo.samplesTrained.toLocaleString()} train / {modelInfo.samplesTested.toLocaleString()} test)
                </span>
              </div>
            )}
          </div>

          {modelInfo && (
            <p className="text-slate-400 leading-relaxed text-[11px]">
              {modelInfo.modelType} across {modelInfo.featureCount} listing features (Dataset: <code className="text-slate-300">{modelInfo.dataset}</code>; precision {(modelInfo.metrics.precision * 100).toFixed(1)}%, recall {(modelInfo.metrics.recall * 100).toFixed(1)}%). Listing URLs are also screened separately using the Website Phishing ML model.
            </p>
          )}

          {(!modelInfo || modelInfo.isSyntheticDataset) && (
            <div className="flex items-start gap-2 bg-amber-950/50 border border-amber-500/30 rounded-lg p-2.5 text-[11px] text-amber-200 leading-relaxed">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <span>
                <strong>Model Scope Notice:</strong> The current Product ML model is trained on synthetic data (<code className="text-amber-100">product_listings_dataset.csv</code>). Its reported accuracy reflects synthetic pattern consistency and does <strong>not</strong> represent verified real-world counterfeit detection performance or physical product authentication.
              </span>
            </div>
          )}
        </div>
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
        <form onSubmit={handleSubmit} noValidate className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Listing URL + Fetch Product Details */}
            <div className="space-y-2 md:col-span-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <label className="block text-xs font-bold uppercase text-slate-700 tracking-wider">
                  Listing URL (Optional)
                </label>
                <span className="text-[11px] text-slate-500">
                  Supports public Schema.org JSON-LD &amp; Open Graph metadata
                </span>
              </div>
              <div className="flex flex-col sm:flex-row gap-2.5">
                <input
                  type="text"
                  value={formData.listingUrl || ''}
                  onChange={(e) => setFormData({ ...formData, listingUrl: e.target.value })}
                  placeholder="e.g., https://www.ebay.com/itm/123456789"
                  className="flex-1 px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white font-mono"
                />
                <button
                  type="button"
                  onClick={handleFetchDetails}
                  disabled={isFetchingDetails || isLoading}
                  className="px-4 py-3 text-xs font-bold text-indigo-700 bg-indigo-50 hover:bg-indigo-100 border border-indigo-200 rounded-xl transition-colors disabled:opacity-50 flex items-center justify-center gap-2 shrink-0"
                >
                  {isFetchingDetails ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      <span>Fetching Details...</span>
                    </>
                  ) : (
                    <>
                      <Globe className="w-4 h-4" />
                      <span>Fetch Product Details</span>
                    </>
                  )}
                </button>
              </div>

              {fetchError && (
                <div className="p-3 bg-rose-50 border border-rose-200 rounded-xl text-xs text-rose-700 flex items-start gap-2 font-medium">
                  <AlertCircle className="w-4 h-4 shrink-0 text-rose-600 mt-0.5" />
                  <span>{fetchError} You can continue filling out the listing fields manually below.</span>
                </div>
              )}

              {fetchResult && (
                <div
                  className={`p-3.5 rounded-xl border text-xs space-y-2 ${
                    fetchResult.success
                      ? 'bg-indigo-50/70 border-indigo-200 text-slate-800'
                      : 'bg-amber-50 border-amber-200 text-amber-900'
                  }`}
                >
                  <div className="flex items-start gap-2 font-medium">
                    {fetchResult.success ? (
                      <CheckCircle2 className="w-4 h-4 text-indigo-600 shrink-0 mt-0.5" />
                    ) : (
                      <Info className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
                    )}
                    <div className="space-y-1">
                      <p>{fetchResult.message}</p>
                      {fetchResult.success && (
                        <p className="text-[11px] text-slate-600">
                          Metadata extraction only reads public listing fields—it does <strong>not</strong> verify physical product authenticity. All fields remain editable.
                        </p>
                      )}
                    </div>
                  </div>

                  {Object.keys(fetchResult.fieldSources).length > 0 && (
                    <div className="pt-1 border-t border-indigo-200/70 space-y-1">
                      <div className="text-[10px] font-bold uppercase tracking-wider text-indigo-700">
                        Retrieved Field Sources
                      </div>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-1 text-[11px]">
                        {Object.entries(fetchResult.fieldSources).map(([field, source]) => (
                          <div key={field} className="text-slate-700">
                            <span className="font-semibold">{field}:</span>{' '}
                            <span className="text-slate-600">{source}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {fetchResult.warnings.length > 0 && (
                    <div className="pt-1 border-t border-amber-200/70 space-y-0.5 text-[11px] text-slate-700">
                      {fetchResult.warnings.map((w, i) => (
                        <div key={i}>• {w}</div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="space-y-1.5 md:col-span-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <label className="block text-xs font-bold uppercase text-slate-700 tracking-wider">
                  Product Name <span className="text-rose-600">*</span>
                </label>
                {renderSourceBadge('productName')}
              </div>
              <input
                type="text"
                value={formData.productName}
                onChange={(e) => updateField('productName', e.target.value)}
                placeholder="e.g., Apple AirPods Pro (2nd Generation)"
                className="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white"
              />
            </div>

            <div className="space-y-1.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <label className="block text-xs font-bold uppercase text-slate-700 tracking-wider">
                  Brand / Manufacturer
                </label>
                {renderSourceBadge('brand')}
              </div>
              <input
                type="text"
                value={formData.brand || ''}
                onChange={(e) => updateField('brand', e.target.value)}
                placeholder="e.g., Sony, Apple, Nike"
                className="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white"
              />
            </div>

            <div className="space-y-1.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <label className="block text-xs font-bold uppercase text-slate-700 tracking-wider">
                  Product Identifier / UPC / GTIN (Optional)
                </label>
                {renderSourceBadge('productIdentifier')}
              </div>
              <input
                type="text"
                value={formData.productIdentifier || ''}
                onChange={(e) => updateField('productIdentifier', e.target.value)}
                placeholder="e.g., 027242919419"
                className="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white font-mono"
              />
            </div>

            <div className="space-y-1.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <label className="block text-xs font-bold uppercase text-slate-700 tracking-wider">
                  Listed Price ({activeCurrency})
                </label>
                {renderSourceBadge('listedPrice') || renderSourceBadge('currency')}
              </div>
              <div className="flex gap-2">
                <select
                  aria-label="Currency"
                  value={activeCurrency}
                  onChange={(e) => {
                    const nextCurr = e.target.value;
                    setFormData((prev) => ({
                      ...prev,
                      currency: nextCurr,
                      referenceCurrency: nextCurr,
                    }));
                  }}
                  className="px-2.5 py-3 bg-slate-50 border border-slate-200 rounded-xl text-xs font-mono font-bold text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white"
                >
                  {currencyOptions.map((c) => (
                    <option key={c} value={c}>
                      {c}
                    </option>
                  ))}
                </select>
                <input
                  type="number"
                  step="0.01"
                  value={formData.listedPrice ?? ''}
                  onChange={(e) =>
                    updateField(
                      'listedPrice',
                      e.target.value !== '' ? parseFloat(e.target.value) : undefined
                    )
                  }
                  placeholder="e.g., 49.99"
                  className="flex-1 px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white font-mono"
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <label className="block text-xs font-bold uppercase text-slate-700 tracking-wider">
                  Typical Market / MSRP Price ({formData.referenceCurrency || activeCurrency})
                </label>
                {renderSourceBadge('referencePrice')}
              </div>
              <input
                type="number"
                step="0.01"
                value={formData.referencePrice ?? ''}
                onChange={(e) =>
                  updateField(
                    'referencePrice',
                    e.target.value !== '' ? parseFloat(e.target.value) : undefined
                  )
                }
                placeholder="e.g., 249.99"
                className="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white font-mono"
              />
            </div>

            <div className="space-y-1.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <label className="block text-xs font-bold uppercase text-slate-700 tracking-wider">
                  Seller Handle or Merchant Name
                </label>
                {renderSourceBadge('sellerName')}
              </div>
              <input
                type="text"
                value={formData.sellerName || ''}
                onChange={(e) => updateField('sellerName', e.target.value)}
                placeholder="e.g., BestBuy Direct"
                className="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white"
              />
            </div>

            <div className="space-y-1.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <label className="block text-xs font-bold uppercase text-slate-700 tracking-wider">
                  Seller Rating (0 - 5.0)
                </label>
                {renderSourceBadge('sellerRating')}
              </div>
              <input
                type="number"
                step="0.1"
                value={formData.sellerRating ?? ''}
                onChange={(e) =>
                  updateField(
                    'sellerRating',
                    e.target.value !== '' ? parseFloat(e.target.value) : undefined
                  )
                }
                placeholder="e.g., 4.7"
                className="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white font-mono"
              />
            </div>

            <div className="space-y-1.5 md:col-span-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <label className="block text-xs font-bold uppercase text-slate-700 tracking-wider">
                  Product Description or Seller Notes
                </label>
                {renderSourceBadge('productDescription')}
              </div>
              <textarea
                rows={3}
                value={formData.productDescription || ''}
                onChange={(e) => updateField('productDescription', e.target.value)}
                placeholder="Paste the seller description, terms, warranty statements..."
                className="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white"
              />
            </div>

            <div className="space-y-2 md:col-span-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <label className="block text-xs font-bold uppercase text-slate-700 tracking-wider">
                  Return / Refund Policy Status
                </label>
                {renderSourceBadge('returnPolicyStatus')}
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 p-2 bg-slate-50 border border-slate-200 rounded-xl">
                {(
                  [
                    {
                      value: 'available',
                      title: 'Available',
                      subtitle: 'Returns / buyer guarantee stated',
                    },
                    {
                      value: 'not_available',
                      title: 'Not Available',
                      subtitle: 'Explicit final sale / no returns',
                    },
                    {
                      value: 'unknown',
                      title: 'Unknown',
                      subtitle: 'Not stated (neutral / unverified)',
                    },
                  ] as const
                ).map((option) => {
                  const selected = returnPolicyStatus === option.value;
                  return (
                    <button
                      key={option.value}
                      type="button"
                      onClick={() => handleReturnPolicyChange(option.value)}
                      aria-pressed={selected}
                      className={`p-3 rounded-lg border text-left transition-all ${
                        selected
                          ? 'bg-indigo-600 text-white border-indigo-600 shadow-sm'
                          : 'bg-white text-slate-700 border-slate-200 hover:border-indigo-300'
                      }`}
                    >
                      <span className="text-xs font-bold block">{option.title}</span>
                      <span
                        className={`text-[11px] block mt-0.5 ${
                          selected ? 'text-indigo-100' : 'text-slate-500'
                        }`}
                      >
                        {option.subtitle}
                      </span>
                    </button>
                  );
                })}
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
              Anti-bias rule: Missing return policy (&ldquo;Unknown&rdquo;) or high discounts alone do not trigger fraud verdicts.
            </div>
            <button
              type="submit"
              disabled={isLoading || isFetchingDetails}
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
