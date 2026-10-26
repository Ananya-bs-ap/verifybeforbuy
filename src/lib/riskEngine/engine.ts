/**
 * VerifyBeforeBuy AI — Core Risk Engine Orchestrator
 * 
 * Reusable, deterministic, fully explainable risk engine.
 * Computes calibrated 0–100 risk score, confidence coverage, and actionable recommendations.
 */

import {
  AssessmentResult,
  AssessmentType,
  EvidenceCoverage,
  WebsiteAnalysisInput,
  ProductAnalysisInput,
  CodeAnalysisInput,
  RiskIndicator,
  PositiveSignal,
} from '../../types';
import { getRiskCategory, COMMON_DISCLAIMER } from './rules';
import { analyzeUrlStructure } from './urlAnalyzer';
import { analyzeProductListing } from './productAnalyzer';
import { analyzeCodePayload } from './codeAnalyzer';

export class RiskScoringEngine {
  /**
   * Run Website Risk Assessment
   */
  public static assessWebsite(input: WebsiteAnalysisInput): AssessmentResult {
    const analysis = analyzeUrlStructure(input.url);
    const score = this.calculateFinalScore(analysis.indicators, analysis.positiveSignals);
    const confidence = this.calculateConfidence(analysis.evidenceWeight);
    const category = getRiskCategory(score);

    const recommendations = this.generateRecommendations('website', analysis.indicators, score);

    return {
      id: `scan-web-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      timestamp: new Date().toISOString(),
      type: 'website',
      inputSummary: {
        target: input.url,
      },
      score,
      category,
      confidence: confidence.coverage,
      confidenceScore: confidence.score,
      summary: this.generateSummary('website', category, analysis.indicators.length, analysis.positiveSignals.length),
      indicators: analysis.indicators,
      positiveSignals: analysis.positiveSignals,
      recommendations,
      unverifiedAspects: analysis.unverifiedAspects,
      disclaimer: COMMON_DISCLAIMER,
    };
  }

  /**
   * Run Product Listing Risk Assessment
   */
  public static assessProduct(input: ProductAnalysisInput): AssessmentResult {
    const analysis = analyzeProductListing(input);

    // If a listing URL is provided, also check its URL features
    if (input.listingUrl && input.listingUrl.trim().length > 0) {
      const urlAnalysis = analyzeUrlStructure(input.listingUrl);
      analysis.indicators.push(...urlAnalysis.indicators);
      analysis.positiveSignals.push(...urlAnalysis.positiveSignals);
      analysis.evidenceWeight = Math.min(analysis.evidenceWeight + 20, 100);
      analysis.unverifiedAspects.push(...urlAnalysis.unverifiedAspects);
    }

    const score = this.calculateFinalScore(analysis.indicators, analysis.positiveSignals);
    const confidence = this.calculateConfidence(analysis.evidenceWeight);
    const category = getRiskCategory(score);

    const recommendations = this.generateRecommendations('product', analysis.indicators, score);

    return {
      id: `scan-prod-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      timestamp: new Date().toISOString(),
      type: 'product',
      inputSummary: {
        target: input.productName,
        brand: input.brand,
        price: input.listedPrice,
        referencePrice: input.referencePrice,
        sellerName: input.sellerName,
        platform: input.sourcePlatform,
      },
      score,
      category,
      confidence: confidence.coverage,
      confidenceScore: confidence.score,
      summary: this.generateSummary('product', category, analysis.indicators.length, analysis.positiveSignals.length),
      indicators: analysis.indicators,
      positiveSignals: analysis.positiveSignals,
      recommendations,
      unverifiedAspects: Array.from(new Set(analysis.unverifiedAspects)),
      disclaimer: COMMON_DISCLAIMER,
    };
  }

  /**
   * Run Barcode & QR Code Assessment
   */
  public static assessCode(input: CodeAnalysisInput): AssessmentResult {
    const analysis = analyzeCodePayload(input);
    const score = this.calculateFinalScore(analysis.indicators, analysis.positiveSignals);
    const confidence = this.calculateConfidence(analysis.evidenceWeight);
    const category = getRiskCategory(score);

    const recommendations = this.generateRecommendations('code', analysis.indicators, score);

    return {
      id: `scan-code-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      timestamp: new Date().toISOString(),
      type: 'code',
      inputSummary: {
        target: input.code,
        subtarget: analysis.detectedFormat,
      },
      score,
      category,
      confidence: confidence.coverage,
      confidenceScore: confidence.score,
      summary: this.generateSummary('code', category, analysis.indicators.length, analysis.positiveSignals.length),
      indicators: analysis.indicators,
      positiveSignals: analysis.positiveSignals,
      recommendations,
      unverifiedAspects: analysis.unverifiedAspects,
      disclaimer: COMMON_DISCLAIMER,
      isDemoMode: Boolean(analysis.matchedDemoItem),
    };
  }

  /**
   * Calibrated Scoring Algorithm
   * Sums indicator impacts with category-based caps to prevent double-counting.
   */
  private static calculateFinalScore(indicators: RiskIndicator[], positiveSignals: PositiveSignal[]): number {
    if (indicators.length === 0 && positiveSignals.length === 0) {
      return 15; // neutral baseline with minimal data
    }

    // Group impacts by category to cap repetitive signals
    const categoryTotals: Record<string, number> = {
      url: 0,
      seller: 0,
      pricing: 0,
      content: 0,
      verification: 0,
      technical: 0,
    };

    const CATEGORY_CAPS: Record<string, number> = {
      url: 55,
      seller: 35,
      pricing: 25, // Rule: Pricing alone never exceeds 25 (cannot jump past Lower without other red flags!)
      content: 45,
      verification: 30,
      technical: 50,
    };

    for (const ind of indicators) {
      const cat = ind.category || 'technical';
      categoryTotals[cat] = (categoryTotals[cat] || 0) + ind.scoreImpact;
    }

    // Apply caps
    let grossScore = 5; // baseline starting point
    for (const cat in categoryTotals) {
      const cap = CATEGORY_CAPS[cat] || 40;
      grossScore += Math.min(categoryTotals[cat], cap);
    }

    // Apply positive signal deductions (capped at 35 total deduction)
    const positiveDeduction = positiveSignals.reduce((acc, sig) => acc + sig.scoreDeduction, 0);
    const cappedDeduction = Math.min(positiveDeduction, 35);

    const finalScore = Math.max(0, Math.min(100, Math.round(grossScore - cappedDeduction)));
    return finalScore;
  }

  /**
   * Derive evidence coverage bucket from raw weight
   */
  private static calculateConfidence(weight: number): { coverage: EvidenceCoverage; score: number } {
    const score = Math.max(10, Math.min(100, Math.round(weight)));
    let coverage: EvidenceCoverage = 'minimal';
    if (score >= 80) coverage = 'comprehensive';
    else if (score >= 60) coverage = 'high';
    else if (score >= 35) coverage = 'moderate';
    return { coverage, score };
  }

  /**
   * Generate practical, prioritized safety precautions
   */
  private static generateRecommendations(
    type: AssessmentType,
    indicators: RiskIndicator[],
    score: number
  ): string[] {
    const list: string[] = [];

    if (score > 50) {
      list.push('Pause before entering payment details, account passwords, or sensitive personal data.');
    }

    // Indicator-driven specific recommendations
    for (const ind of indicators) {
      if (ind.remedyOrPrecaution && !list.includes(ind.remedyOrPrecaution)) {
        list.push(ind.remedyOrPrecaution);
      }
      if (list.length >= 5) break;
    }

    // Type-specific general precautions
    if (type === 'website') {
      list.push('Pay using credit cards or virtual merchant cards that offer built-in chargeback protections.');
      list.push('Check the merchant’s contact page for a verifiable physical address and customer phone number.');
    } else if (type === 'product') {
      list.push('Review the seller’s explicit return window and verify whether return postage is covered.');
      list.push('Cross-reference the listed product specifications with the manufacturer’s official product manual.');
    } else if (type === 'code') {
      list.push('Verify that the physical packaging barcode matches the number stamped on warranty paperwork.');
      list.push('Remember that counterfeiters can copy real barcodes onto knockoff packaging; verify seller authorization.');
    }

    return Array.from(new Set(list)).slice(0, 5);
  }

  /**
   * Clean prose summary of finding
   */
  private static generateSummary(
    type: AssessmentType,
    category: string,
    indicatorCount: number,
    positiveCount: number
  ): string {
    const typeLabel = type === 'website' ? 'website' : type === 'product' ? 'product listing' : 'code payload';

    if (category === 'lower') {
      return `Preliminary inspection of this ${typeLabel} identified ${positiveCount} reassuring signals and no critical deception patterns. Available indicators suggest lower assessed risk.`;
    } else if (category === 'moderate') {
      return `Inspection of this ${typeLabel} flagged ${indicatorCount} items requiring buyer attention. We recommend verifying seller credentials before payment.`;
    } else if (category === 'elevated') {
      return `Multiple risk factors were identified on this ${typeLabel}. Proceed with caution and avoid direct debit or unrecoverable wire payments.`;
    } else {
      return `High-risk indicators detected on this ${typeLabel}. Strong signs of possible brand impersonation, spoofed address, or deceptive practices.`;
    }
  }
}
