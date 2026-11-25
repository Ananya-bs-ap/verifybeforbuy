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
} from '../types';
import { predictPhishing, getModelMetadata } from './mlInference';
import { predictProductRisk, getProductModelMetadata } from './productMlInference';
import { RiskScoringEngine } from './riskEngine/engine';
import { validateWebsiteUrl } from './urlValidator';

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
    try {
      const response = await fetch('/api/ml/predict-product', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      });

      if (response.ok) {
        return await response.json();
      }
    } catch (err: any) {
      console.warn('ML product server request error, running local inference:', err.message);
    }

    return predictProductRisk(input);
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
    try {
      const response = await fetch('/api/analyze/product', {
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
    return RiskScoringEngine.assessProduct(input);
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
  }> {
    try {
      const response = await fetch('/api/explain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(result),
      });

      if (response.ok) {
        return await response.json();
      }
    } catch (err: any) {
      console.warn('AI explanation API error:', err.message);
    }

    return {
      explanation:
        'This assessment evaluates observable signals against known risk indicators. A low price or unknown domain requires diligence, but risk assessment is not physical proof of counterfeiting or fraud. Always verify returns and use secure payment methods.',
      provider: 'deterministic-fallback',
    };
  }
}
