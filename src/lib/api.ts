/**
 * Frontend API Service
 * Communicates with full-stack Express API endpoints, with automatic client-side
 * risk engine fallback to ensure zero downtime.
 */

import {
  AssessmentResult,
  WebsiteAnalysisInput,
  ProductAnalysisInput,
  CodeAnalysisInput,
  MlPhishingResult,
  MlProductResult,
  ProductFetchDetailsResponse,
  BarcodeLookupResult,
  SellerVerificationResult,
  MarketPriceComparisonResult,
} from '../types';
import { predictPhishing, getModelMetadata } from './mlInference';
import { predictProductRisk, getProductModelMetadata } from './productMlInference';
import { RiskScoringEngine } from './riskEngine/engine';
import { validateWebsiteUrl } from './urlValidator';
import { validateProductInput } from './productValidator';

export class ApiService {
  /**
   * Request ML Phishing Prediction (Uses model trained on Kaggle malicious_phish.csv)
   */
  public static async predictPhishingWithML(url: string): Promise<MlPhishingResult> {
    const validation = validateWebsiteUrl(url);
    if (!validation.valid || !validation.normalizedUrl) {
      throw new Error(validation.error || 'Invalid URL. Please enter a valid website address.');
    }

    try {
      const response = await fetch('/api/ml/predict-phishing', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: validation.normalizedUrl }),
      });

      if (response.ok) {
        return await response.json();
      }
      if (response.status >= 400 && response.status < 500) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.error || 'Invalid URL. Please enter a valid website address.');
      }
    } catch (err: any) {
      if (err?.message && err.message.startsWith('Invalid URL')) {
        throw err;
      }
      console.warn('ML phishing server request error, running local inference:', err.message);
    }

    // Direct local inference using identical trained weights (only for validated URLs)
    return predictPhishing(validation.normalizedUrl);
  }

  /**
   * Get ML Model Training Information & Metrics
   */
  public static async getModelInfo() {
    try {
      const response = await fetch('/api/ml/model-info');
      if (response.ok) {
        return await response.json();
      }
    } catch {
      // Fallback to local metadata
    }
    return getModelMetadata();
  }

  /**
   * Request ML Product Listing Risk Prediction
   */
  public static async predictProductWithML(input: ProductAnalysisInput): Promise<MlProductResult> {
    const validation = validateProductInput(input);
    if (!validation.valid || !validation.normalizedInput) {
      throw new Error(validation.error || 'Invalid product listing input.');
    }

    let clientError: Error | null = null;
    try {
      const response = await fetch('/api/ml/predict-product', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(validation.normalizedInput),
      });

      if (response.ok) {
        return await response.json();
      }
      if (response.status >= 400 && response.status < 500) {
        const errData = await response.json().catch(() => ({}));
        clientError = new Error(errData.error || 'Invalid product listing input.');
      }
    } catch (err: any) {
      console.warn('ML product server request error, running local inference:', err.message);
    }

    if (clientError) {
      throw clientError;
    }

    return predictProductRisk(validation.normalizedInput);
  }

  /**
   * Get Product ML Model Training Information & Metrics
   */
  public static async getProductModelInfo() {
    try {
      const response = await fetch('/api/ml/product-model-info');
      if (response.ok) {
        return await response.json();
      }
    } catch {
      // Fallback to local metadata
    }
    return getProductModelMetadata();
  }
  /**
   * Analyze Website URL
   */
  public static async analyzeWebsite(input: WebsiteAnalysisInput): Promise<AssessmentResult> {
    const validation = validateWebsiteUrl(input.url);
    if (!validation.valid || !validation.normalizedUrl) {
      throw new Error(validation.error || 'Invalid URL. Please enter a valid website address.');
    }

    const normalizedInput: WebsiteAnalysisInput = {
      ...input,
      url: validation.normalizedUrl,
    };

    let clientError: Error | null = null;
    try {
      const response = await fetch('/api/analyze/website', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(normalizedInput),
      });

      if (response.ok) {
        return await response.json();
      }

      const errData = await response.json().catch(() => ({}));
      if (response.status >= 400 && response.status < 500) {
        clientError = new Error(errData.error || 'Invalid URL. Please enter a valid website address.');
      } else {
        throw new Error(errData.error || `Server error (${response.status})`);
      }
    } catch (err: any) {
      console.warn('Backend API request failed, using client engine fallback:', err.message);
    }

    if (clientError) {
      throw clientError;
    }

    // Direct client engine fallback (only reached on network/5xx unavailability, and URL is already validated)
    return RiskScoringEngine.assessWebsite(normalizedInput);
  }

  /**
   * Analyze Product Listing
   */
  public static async analyzeProduct(input: ProductAnalysisInput): Promise<AssessmentResult> {
    const validation = validateProductInput(input);
    if (!validation.valid || !validation.normalizedInput) {
      throw new Error(validation.error || 'Invalid product listing input.');
    }

    const normalizedInput = validation.normalizedInput;
    let clientError: Error | null = null;
    try {
      const response = await fetch('/api/analyze/product', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(normalizedInput),
      });

      if (response.ok) {
        return await response.json();
      }
      const errData = await response.json().catch(() => ({}));
      if (response.status >= 400 && response.status < 500) {
        clientError = new Error(errData.error || 'Invalid product listing input.');
      } else {
        throw new Error(errData.error || `Server error (${response.status})`);
      }
    } catch (err: any) {
      console.warn('Backend API request failed, using client engine fallback:', err.message);
    }

    if (clientError) {
      throw clientError;
    }

    // Direct client engine fallback (only reached on network/5xx unavailability)
    return RiskScoringEngine.assessProduct(normalizedInput);
  }

  /**
   * Retrieve public structured product metadata from a listing URL via backend endpoint
   */
  public static async fetchProductDetails(url: string): Promise<ProductFetchDetailsResponse> {
    const validation = validateWebsiteUrl(url);
    if (!validation.valid || !validation.normalizedUrl) {
      throw new Error(validation.error || 'Invalid URL. Please enter a valid website address.');
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 14_000);

    try {
      const response = await fetch('/api/product/fetch-details', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: validation.normalizedUrl }),
        signal: controller.signal,
      });
      clearTimeout(timer);

      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(data.error || `Failed to retrieve listing metadata (HTTP ${response.status}).`);
      }
      return data as ProductFetchDetailsResponse;
    } catch (err: any) {
      clearTimeout(timer);
      if (err?.name === 'AbortError') {
        throw new Error('Metadata retrieval timed out. Please try again or enter the product details manually.');
      }
      throw new Error(err?.message || 'Unable to retrieve product metadata. You can continue with manual entry.');
    }
  }

  /**
   * Verify seller information against public listing metadata via backend endpoint
   */
  public static async verifySeller(input: Partial<ProductAnalysisInput>): Promise<SellerVerificationResult> {
    const response = await fetch('/api/seller/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.error || `Seller verification failed (HTTP ${response.status}).`);
    }
    return data as SellerVerificationResult;
  }

  /**
   * Compare listed product price against real-world market reference prices
   */
  public static async compareMarketPrices(input: ProductAnalysisInput): Promise<MarketPriceComparisonResult> {
    const validation = validateProductInput(input);
    if (!validation.valid || !validation.normalizedInput) {
      throw new Error(validation.error || 'Invalid product listing input.');
    }

    const response = await fetch('/api/product/market-prices', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(validation.normalizedInput),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.error || `Market price comparison failed (HTTP ${response.status}).`);
    }
    return data as MarketPriceComparisonResult;
  }

  /**
   * Look up a barcode against live public databases via backend endpoint
   */
  public static async lookupBarcode(code: string): Promise<BarcodeLookupResult> {
    const response = await fetch('/api/barcode/lookup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.error || `Barcode lookup failed (HTTP ${response.status}).`);
    }
    return data as BarcodeLookupResult;
  }

  /**
   * Analyze Barcode / QR Code
   */
  public static async analyzeCode(input: CodeAnalysisInput): Promise<AssessmentResult> {
    try {
      const response = await fetch('/api/analyze/code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      });

      if (response.ok) {
        return await response.json();
      }
      const errData = await response.json().catch(() => ({}));
      if (errData.error) throw new Error(errData.error);
    } catch (err: any) {
      console.warn('Backend API request failed, using client engine fallback:', err.message);
    }

    // Direct client engine fallback
    return RiskScoringEngine.assessCode(input);
  }

  /**
   * Request AI Plain-Language Risk Explanation
   */
  public static async requestAiExplanation(result: AssessmentResult): Promise<{
    explanation: string;
    provider: 'gemini' | 'deterministic-fallback';
    model?: string;
    fallbackReason?: string;
  }> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 35_000);

    try {
      const response = await fetch('/api/explain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(result),
        signal: controller.signal,
      });

      if (response.ok) {
        return await response.json();
      }
      const errBody = await response.json().catch(() => ({}));
      return {
        explanation:
          `Based on the calculated risk score of ${result.score}/100 (${result.category.toUpperCase()} risk), this assessment evaluates observable signals against known risk indicators. ${result.summary} Note: risk assessment is a probability and caution index, not physical proof of authenticity or fraud. Always verify official seller channels and use payment methods with buyer dispute protection.`,
        provider: 'deterministic-fallback',
        fallbackReason: errBody?.error || `Explanation service returned HTTP ${response.status}`,
      };
    } catch (err: any) {
      const isAbort = err?.name === 'AbortError';
      console.warn('AI explanation API error:', err?.message || err);
      return {
        explanation:
          `Based on the calculated risk score of ${result.score}/100 (${result.category.toUpperCase()} risk), this assessment evaluates observable signals against known risk indicators. ${result.summary} Note: risk assessment is a probability and caution index, not physical proof of authenticity or fraud. Always verify official seller channels and use payment methods with buyer dispute protection.`,
        provider: 'deterministic-fallback',
        fallbackReason: isAbort
          ? 'Request to /api/explain timed out in browser'
          : 'Backend /api/explain endpoint unreachable; client fallback displayed',
      };
    } finally {
      clearTimeout(timer);
    }
  }
}
