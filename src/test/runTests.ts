/**
 * Unit Tests for Risk-Scoring Engine
 * Tests the core risk rules against key consumer protection scenarios.
 */

import { RiskScoringEngine } from '../lib/riskEngine/engine';
import { validateWebsiteUrl } from '../lib/urlValidator';

interface TestCase {
  name: string;
  run: () => { passed: boolean; message: string; details?: any };
}

const tests: TestCase[] = [
  {
    name: 'Rule 1: Genuine product with steep discount is NOT classified as High Risk',
    run: () => {
      // 88% clearance discount, but with reputable brand and clear return policy
      const result = RiskScoringEngine.assessProduct({
        productName: 'Sony WH-1000XM4 Wireless Headphones (Refurbished Clearance)',
        brand: 'Sony',
        listedPrice: 39.99,
        referencePrice: 349.99, // 88% discount
        sellerName: 'DirectAudioLiquidation',
        sellerRating: 4.8,
        hasReturnPolicy: true,
        productDescription: 'Factory recertified seasonal inventory liquidation. Includes 30-day warranty and original accessories.',
        productIdentifier: '027242919419',
      });

      // Price rule: steep discount impact is strictly capped at 20 points,
      // positive signals (high rating, returns, valid UPC) deduct points.
      // Final score must NOT be in elevated (51+) or high (76+) category!
      const isNotHigh = result.score <= 50;
      return {
        passed: isNotHigh,
        message: `Score was ${result.score} (Category: ${result.category}). Expected <= 50 (moderate or lower).`,
        details: { score: result.score, category: result.category },
      };
    },
  },

  {
    name: 'Rule 2: Phishing lookalike domain with brand typosquatting triggers High Risk',
    run: () => {
      // Evading domain mimicking Apple / PayPal with suspicious TLD and hyphen stuffing
      const result = RiskScoringEngine.assessWebsite({
        url: 'https://apple-security-verify-login.click/update-billing',
      });

      const isElevatedOrHigh = result.score >= 51;
      return {
        passed: isElevatedOrHigh,
        message: `Score was ${result.score} (Category: ${result.category}). Expected >= 51 (elevated/high).`,
        details: { score: result.score, category: result.category, indicators: result.indicators.map(i => i.name) },
      };
    },
  },

  {
    name: 'Rule 3: Missing information reduces confidence/coverage without falsely penalizing as fraud',
    run: () => {
      // Incomplete product listing with almost no fields provided
      const result = RiskScoringEngine.assessProduct({
        productName: 'Handmade Wooden Cutting Board',
      });

      // Score should remain near neutral baseline (<= 30), and confidence must be 'minimal'
      const isNeutralScore = result.score <= 35;
      const isLowConfidence = result.confidence === 'minimal' || result.confidenceScore <= 35;

      return {
        passed: isNeutralScore && isLowConfidence,
        message: `Score: ${result.score}, Confidence: ${result.confidence} (${result.confidenceScore}%). Expected low coverage and low/moderate neutral score.`,
        details: { score: result.score, confidence: result.confidence, confidenceScore: result.confidenceScore },
      };
    },
  },

  {
    name: 'Rule 4: Invalid URL protocols and syntax are safely trapped without crashing',
    run: () => {
      const resultMalformed = RiskScoringEngine.assessWebsite({
        url: 'javascript:alert(1)',
      });

      const resultNotUrl = RiskScoringEngine.assessWebsite({
        url: 'http://',
      });

      const trappedCorrectly = resultMalformed.indicators.length > 0 && resultNotUrl.indicators.length > 0;
      return {
        passed: trappedCorrectly,
        message: 'Non-standard protocols and malformed URLs were caught with safety indicators.',
        details: { malformedIndicators: resultMalformed.indicators.map(i => i.name) },
      };
    },
  },

  {
    name: 'Rule 5: Barcode checksum math correctly verifies valid GTIN and flags corrupted checksums',
    run: () => {
      // Valid UPC-A: 012000000133
      const validResult = RiskScoringEngine.assessCode({ code: '012000000133' });
      // Tampered UPC-A with corrupted check digit: 012000000139
      const tamperedResult = RiskScoringEngine.assessCode({ code: '012000000139' });

      const validHasChecksumSignal = validResult.positiveSignals.some(s => s.id === 'valid-gs1-checksum');
      const tamperedHasFlag = tamperedResult.indicators.some(i => i.id === 'invalid-gs1-checksum');

      return {
        passed: validHasChecksumSignal && tamperedHasFlag,
        message: `Valid check: ${validHasChecksumSignal}, Tampered flag: ${tamperedHasFlag}.`,
        details: {
          validScore: validResult.score,
          tamperedScore: tamperedResult.score,
        },
      };
    },
  },

  {
    name: 'Rule 6: Invalid URLs (kajsbdche, hello123, abc, www, https://, ftp://) fail validation without invoking ML; valid URLs (including suspicious domains) pass',
    run: () => {
      const cases: Array<{ input: string; expectedValid: boolean }> = [
        { input: '', expectedValid: false },
        { input: 'kajsbdche', expectedValid: false },
        { input: 'hello123', expectedValid: false },
        { input: 'abc', expectedValid: false },
        { input: 'www', expectedValid: false },
        { input: 'https://', expectedValid: false },
        { input: 'randomtext', expectedValid: false },
        { input: 'ftp://example.com', expectedValid: false },
        { input: 'google.com', expectedValid: true },
        { input: 'https://google.com', expectedValid: true },
        { input: 'http://example.com/login', expectedValid: true },
        { input: 'https://suspicious-example.xyz', expectedValid: true },
        { input: 'https://fake-login-example.xyz/verify', expectedValid: true },
      ];

      const failures: string[] = [];
      for (const tc of cases) {
        const res = validateWebsiteUrl(tc.input);
        if (res.valid !== tc.expectedValid) {
          failures.push(`${tc.input}: expected valid=${tc.expectedValid}, got ${res.valid}`);
        }
        if (!tc.expectedValid && tc.input.trim().length > 0) {
          const directEngine = RiskScoringEngine.assessWebsite({ url: tc.input });
          if (directEngine.mlPhishingPrediction !== undefined) {
            failures.push(`${tc.input}: ML model unexpectedly ran on invalid URL`);
          }
          if (directEngine.score <= 25) {
            failures.push(`${tc.input}: engine unexpectedly scored invalid URL as Low Risk (${directEngine.score})`);
          }
        }
      }

      return {
        passed: failures.length === 0,
        message: failures.length === 0 ? `All ${cases.length} URL validation & ML-skip assertions passed.` : failures.join('; '),
      };
    },
  },

  {
    name: 'Rule 7: Trained Product ML model classifies high-risk replica listing vs clean listing',
    run: () => {
      const risky = RiskScoringEngine.assessProduct({
        productName: 'Rolex Submariner Date 41mm',
        brand: 'Rolex',
        listingUrl: 'https://luxury-outlet-deals.xyz/item/sub41',
        listedPrice: 199,
        referencePrice: 10250,
        sellerName: 'deals_king_99',
        sellerRating: 2.1,
        hasReturnPolicy: false,
        productDescription: 'Brand new 1:1 replica mirror copy. Western Union or wire transfer only.',
      });

      const hasMlPrediction = Boolean(risky.mlProductPrediction && risky.mlProductPrediction.modelTrained);
      const predictedHighRisk = Boolean(risky.mlProductPrediction?.isHighRisk) && risky.score >= 60;

      return {
        passed: hasMlPrediction && predictedHighRisk,
        message: `Product ML prob=${risky.mlProductPrediction?.probability}, finalScore=${risky.score} (${risky.category})`,
      };
    },
  },
];

export function runAllTests(): { passed: number; failed: number } {
  console.log('\n=============================================');
  console.log('🧪 VERIFYBEFOREBUY AI — RISK ENGINE TEST SUITE');
  console.log('=============================================\n');

  let passed = 0;
  let failed = 0;

  for (let i = 0; i < tests.length; i++) {
    const test = tests[i];
    try {
      const res = test.run();
      if (res.passed) {
        console.log(`✅ [PASS] ${test.name}`);
        console.log(`   ${res.message}`);
        passed++;
      } else {
        console.error(`❌ [FAIL] ${test.name}`);
        console.error(`   ${res.message}`);
        if (res.details) console.error('   Details:', res.details);
        failed++;
      }
    } catch (err: any) {
      console.error(`💥 [ERROR] ${test.name}`);
      console.error(`   Exception: ${err.message}`);
      failed++;
    }
  }

  console.log('\n---------------------------------------------');
  console.log(`Summary: ${passed} passed, ${failed} failed out of ${tests.length} tests.`);
  console.log('=============================================\n');

  return { passed, failed };
}

// Execute directly if run via tsx
runAllTests();
