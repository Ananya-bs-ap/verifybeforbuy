/**
 * Unit Tests for Risk-Scoring Engine
 * Tests the core risk rules against key consumer protection scenarios.
 */

import { RiskScoringEngine } from '../lib/riskEngine/engine';
import { validateWebsiteUrl } from '../lib/urlValidator';
import { areCurrenciesCompatible, validateProductInput } from '../lib/productValidator';
import { extractProductMetadataFromHtml } from '../lib/productMetadataExtractor';
import {
  createPinnedLookup,
  isPrivateOrReservedIp,
  resolveAndPinPublicHost,
  SsrfBlockedError,
} from '../../server/ssrfFetch';
import {
  clearDomainVerificationCache,
  getRegistrableDomain,
  verifyWebsiteDomain,
} from '../../server/domainVerificationService';
import {
  clearBarcodeLookupCache,
  getDefaultTimeoutMs,
  lookupBarcodeProduct,
} from '../../server/barcodeLookupService';
import {
  clearSellerVerificationCache,
  verifySellerInfo,
} from '../../server/sellerVerificationService';
import {
  clearMarketPriceCache,
  compareMarketPrices,
} from '../../server/marketPriceService';

interface TestCase {
  name: string;
  run: () =>
    | { passed: boolean; message: string; details?: any }
    | Promise<{ passed: boolean; message: string; details?: any }>;
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
      const result = RiskScoringEngine.assessProduct({
        productName: 'Handmade Wooden Cutting Board',
      });

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
      const validResult = RiskScoringEngine.assessCode({ code: '012000000133' });
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
    name: 'Rule 6: Invalid URLs fail validation without invoking ML; valid URLs (including suspicious domains) pass',
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
    name: 'Rule 7: Trained Product ML + Website Phishing ML classify high-risk replica listing & connect listing URL without double-counting',
    run: () => {
      const risky = RiskScoringEngine.assessProduct({
        productName: 'Rolex Submariner Date 41mm',
        brand: 'Rolex',
        listingUrl: 'https://luxury-outlet-deals.xyz/item/sub41',
        listedPrice: 199,
        referencePrice: 10250,
        sellerName: 'deals_king_99',
        sellerRating: 2.1,
        returnPolicyStatus: 'not_available',
        productDescription: 'Brand new 1:1 replica mirror copy. Western Union or wire transfer only.',
      });

      const hasProductMl = Boolean(risky.mlProductPrediction && risky.mlProductPrediction.modelTrained);
      const hasPhishingMl = Boolean(risky.mlPhishingPrediction && risky.mlPhishingPrediction.modelTrained);
      const hasUnifiedPhishingFlag = risky.indicators.some(i => i.id === 'ml_listing_url_phishing');
      const noDuplicateTldFlag = !risky.indicators.some(i => i.id === 'high-abuse-tld');
      const predictedHighRisk = Boolean(risky.mlProductPrediction?.isHighRisk) && risky.score >= 60;

      return {
        passed: hasProductMl && hasPhishingMl && hasUnifiedPhishingFlag && noDuplicateTldFlag && predictedHighRisk,
        message: `Product ML prob=${risky.mlProductPrediction?.probability}, Phishing ML prob=${risky.mlPhishingPrediction?.probability}, dedupTld=${noDuplicateTldFlag}, finalScore=${risky.score}`,
      };
    },
  },

  {
    name: 'Rule 8: Product Checker validates GS1 Modulo-10 check digits (not just barcode length)',
    run: () => {
      const validUpc = RiskScoringEngine.assessProduct({
        productName: 'Sony Headphones',
        productIdentifier: '027242919419',
      });
      const invalidChecksumSameLength = RiskScoringEngine.assessProduct({
        productName: 'Sony Headphones',
        productIdentifier: '027242919410', // 12 digits, bad check digit
      });

      const validPassed =
        validUpc.positiveSignals.some(s => s.id === 'valid-identifier-format') &&
        validUpc.mlProductPrediction?.featuresExtracted?.hasValidGs1Barcode === 1;
      const invalidCaught =
        invalidChecksumSameLength.indicators.some(i => i.id === 'invalid-gs1-checksum') &&
        invalidChecksumSameLength.mlProductPrediction?.featuresExtracted?.hasValidGs1Barcode === 0;

      return {
        passed: validPassed && invalidCaught,
        message: `Valid GS1 passed=${validPassed}, Tampered 12-digit GS1 caught=${invalidCaught}`,
      };
    },
  },

  {
    name: 'Rule 9: Three-state Return Policy treats Unknown neutrally (neither positive nor negative)',
    run: () => {
      const unknownPolicy = RiskScoringEngine.assessProduct({
        productName: 'Canvas Backpack',
        returnPolicyStatus: 'unknown',
      });
      const noPolicy = RiskScoringEngine.assessProduct({
        productName: 'Canvas Backpack',
        returnPolicyStatus: 'not_available',
      });

      const unknownNeutral =
        !unknownPolicy.indicators.some(i => i.id === 'no-return-policy') &&
        !unknownPolicy.positiveSignals.some(s => s.id === 'returns-accepted') &&
        unknownPolicy.mlProductPrediction?.featuresExtracted?.noReturnPolicy === 0;

      const notAvailFlagged =
        noPolicy.indicators.some(i => i.id === 'no-return-policy') &&
        noPolicy.mlProductPrediction?.featuresExtracted?.noReturnPolicy === 1;

      return {
        passed: unknownNeutral && notAvailFlagged,
        message: `Unknown neutral=${unknownNeutral}, Not-Available flagged=${notAvailFlagged}`,
      };
    },
  },

  {
    name: 'Rule 10: Pre-analysis product validator rejects invalid ratings, prices, URLs, and barcodes',
    run: () => {
      const invalidCases = [
        validateProductInput({ productName: '' }),
        validateProductInput({ productName: 'Item', listedPrice: -5 }),
        validateProductInput({ productName: 'Item', referencePrice: 0 }),
        validateProductInput({ productName: 'Item', sellerRating: 5.5 }),
        validateProductInput({ productName: 'Item', sellerRating: -0.5 }),
        validateProductInput({ productName: 'Item', listingUrl: 'kajsbdche' }),
        validateProductInput({ productName: 'Item', listingUrl: 'ftp://example.com' }),
        validateProductInput({ productName: 'Item', productIdentifier: '12345' }),
        validateProductInput({ productName: 'Item', productIdentifier: 'bad!@#' }),
      ];

      const validCases = [
        validateProductInput({ productName: 'Item', listedPrice: 29.99, referencePrice: 59.99, sellerRating: 4.5, listingUrl: 'ebay.com/itm/123', productIdentifier: '027242919419', returnPolicyStatus: 'unknown' }),
        validateProductInput({ productName: 'Watch', productIdentifier: '126610LN' }),
      ];

      const allInvalidRejected = invalidCases.every(c => !c.valid);
      const allValidAccepted = validCases.every(c => c.valid);
      const urlNormalized = validCases[0].normalizedInput?.listingUrl === 'https://ebay.com/itm/123';

      return {
        passed: allInvalidRejected && allValidAccepted && urlNormalized,
        message: `Invalid rejected=${allInvalidRejected}, Valid accepted=${allValidAccepted}, URL normalized=${urlNormalized}`,
      };
    },
  },

  {
    name: 'Rule 11: Metadata extractor obeys anti-confusion rules (SKU vs GTIN, Product vs Seller Rating, crossed-out highPrice vs MSRP)',
    run: () => {
      const sampleHtml = `
        <html>
          <head>
            <script type="application/ld+json">
              {
                "@context": "https://schema.org",
                "@type": "Product",
                "name": "Sony WH-1000XM5 Headphones",
                "brand": { "@type": "Brand", "name": "Sony" },
                "sku": "WH1000XM5-BLK",
                "description": "Wireless noise cancelling headphones.",
                "aggregateRating": { "@type": "AggregateRating", "ratingValue": "4.8", "reviewCount": "1200" },
                "offers": {
                  "@type": "AggregateOffer",
                  "lowPrice": "299.99",
                  "highPrice": "499.99",
                  "priceCurrency": "USD",
                  "seller": { "@type": "Organization", "name": "AuthorizedAudioShop" },
                  "hasMerchantReturnPolicy": {
                    "@type": "MerchantReturnPolicy",
                    "returnPolicyCategory": "https://schema.org/MerchantReturnFiniteReturnWindow",
                    "merchantReturnDays": 30
                  }
                }
              }
            </script>
          </head>
        </html>
      `;

      const res = extractProductMetadataFromHtml(
        sampleHtml,
        'https://example-shop.com/p/sony',
        'https://example-shop.com/p/sony',
        200
      );

      const okName = res.extracted?.productName === 'Sony WH-1000XM5 Headphones';
      const okBrand = res.extracted?.brand === 'Sony';
      const okPrice = res.extracted?.listedPrice === 299.99 && res.extracted?.currency === 'USD';
      const noFalseMsrp = res.extracted?.referencePrice === undefined; // highPrice must NOT be treated as MSRP
      const noSkuInGtin = res.extracted?.productIdentifier === undefined; // SKU must NOT be put into GTIN/UPC
      const noProdRatingInSeller = res.extracted?.sellerRating === undefined; // product rating != seller rating
      const okSeller = res.extracted?.sellerName === 'AuthorizedAudioShop';
      const okReturn = res.extracted?.returnPolicyStatus === 'available';

      const captchaHtml = `<html><title>Robot Check</title><body>Sorry! We just need to make sure you're not a robot</body></html>`;
      const blocked = extractProductMetadataFromHtml(captchaHtml, 'https://amazon.com/dp/123', 'https://amazon.com/dp/123', 200);

      return {
        passed:
          res.success &&
          okName &&
          okBrand &&
          okPrice &&
          noFalseMsrp &&
          noSkuInGtin &&
          noProdRatingInSeller &&
          okSeller &&
          okReturn &&
          !blocked.success &&
          Boolean(blocked.accessRestricted),
        message: `Extracted=${res.success}, noFalseMsrp=${noFalseMsrp}, noSkuInGtin=${noSkuInGtin}, noProdRatingInSeller=${noProdRatingInSeller}, captchaBlocked=${blocked.accessRestricted}`,
      };
    },
  },

  {
    name: 'Rule 12: Currency mismatch prevents bogus discount ratio calculation',
    run: () => {
      const mismatched = RiskScoringEngine.assessProduct({
        productName: 'Bluetooth Speaker',
        listedPrice: 80,
        currency: 'USD',
        referencePrice: 7000,
        referenceCurrency: 'INR',
      });

      const hasMismatchNote = mismatched.unverifiedAspects.some(u => u.toLowerCase().includes('currency mismatch') || u.toLowerCase().includes('differs'));
      const discountZeroed = mismatched.mlProductPrediction?.featuresExtracted?.discountRatio === 0;
      const compatFalse = !areCurrenciesCompatible('USD', 'INR') && areCurrenciesCompatible('INR', 'INR');

      return {
        passed: hasMismatchNote && discountZeroed && compatFalse,
        message: `Currency mismatch skipped discount=${discountZeroed}, note=${hasMismatchNote}, compatCheck=${compatFalse}`,
      };
    },
  },

  {
    name: 'Rule 13: SSRF IP guard blocks loopback, private RFC1918, metadata, CGNAT, and private IPv4-mapped IPv6 while allowing public IPs',
    run: () => {
      const shouldBlock = [
        '127.0.0.1',
        '10.0.0.1',
        '172.16.5.4',
        '192.168.1.10',
        '169.254.169.254',
        '100.64.0.1',
        '::1',
        'fc00::1',
        'fe80::1',
        '::ffff:127.0.0.1',
        '::ffff:192.168.1.1',
      ];
      const shouldAllow = ['93.184.216.34', '142.250.190.78', '2606:4700:4700::1111'];

      const blockedOk = shouldBlock.every(ip => isPrivateOrReservedIp(ip));
      const allowedOk = shouldAllow.every(ip => !isPrivateOrReservedIp(ip));

      return {
        passed: blockedOk && allowedOk,
        message: `Blocked private/reserved=${blockedOk}, Allowed public=${allowedOk}`,
      };
    },
  },

  {
    name: 'Rule 14: QR HTTP/HTTPS URLs invoke Website Phishing ML without double-counting overlapping lexical URL rules',
    run: () => {
      const benignQr = RiskScoringEngine.assessCode({ code: 'https://www.amazon.com/dp/B09G9FPHY6', format: 'QR_CODE' });
      const suspiciousQr = RiskScoringEngine.assessCode({ code: 'https://apple-security-verify-login.click/update-billing', format: 'QR_CODE' });
      const wwwQr = RiskScoringEngine.assessCode({ code: 'www.target.com/p/item-123', format: 'QR_CODE' });

      const benignOk =
        Boolean(benignQr.mlPhishingPrediction?.modelTrained) &&
        !benignQr.mlPhishingPrediction?.isPhishing &&
        benignQr.score <= 25;

      const suspiciousHasMl =
        Boolean(suspiciousQr.mlPhishingPrediction?.isPhishing) &&
        suspiciousQr.indicators.some(i => i.id === 'ml_phishing_high_risk');
      const noOverlapDoubleCount =
        !suspiciousQr.indicators.some(i => i.id === 'high-abuse-tld') &&
        !suspiciousQr.indicators.some(i => i.id === 'hyphen-stuffing');
      const suspiciousHighRisk = suspiciousQr.score >= 51;

      const wwwNormalizedOk =
        wwwQr.inputSummary.target === 'https://www.target.com/p/item-123' &&
        Boolean(wwwQr.mlPhishingPrediction?.modelTrained);

      return {
        passed: benignOk && suspiciousHasMl && noOverlapDoubleCount && suspiciousHighRisk && wwwNormalizedOk,
        message: `Benign QR score=${benignQr.score}, Suspicious QR score=${suspiciousQr.score}, ML prob=${suspiciousQr.mlPhishingPrediction?.probability}, dedupOk=${noOverlapDoubleCount}, wwwNormalized=${wwwNormalizedOk}`,
      };
    },
  },

  {
    name: 'Rule 15: Non-URL QR content and ordinary numeric barcodes do NOT invoke Website Phishing ML',
    run: () => {
      const barcodeRes = RiskScoringEngine.assessCode({ code: '012000000133', format: 'UPC_A' });
      const unknownBarcodeRes = RiskScoringEngine.assessCode({ code: '027242919419', format: 'UPC_A' });
      const wifiQrRes = RiskScoringEngine.assessCode({ code: 'WIFI:S:StoreGuest;T:WPA;P:welcome123;;', format: 'QR_CODE' });
      const textQrRes = RiskScoringEngine.assessCode({ code: 'BATCH-2026-LOT-4491', format: 'QR_CODE' });

      const noMlOnBarcodes =
        barcodeRes.mlPhishingPrediction === undefined &&
        unknownBarcodeRes.mlPhishingPrediction === undefined &&
        barcodeRes.isDemoMode === true &&
        unknownBarcodeRes.isDemoMode === false;

      const noMlOnNonUrlQr =
        wifiQrRes.mlPhishingPrediction === undefined &&
        textQrRes.mlPhishingPrediction === undefined &&
        !wifiQrRes.indicators.some(i => i.id === 'qr-quishing-warning');

      const disclaimerNoProof =
        unknownBarcodeRes.disclaimer.toLowerCase().includes('never proves a physical product is genuine');

      return {
        passed: noMlOnBarcodes && noMlOnNonUrlQr && disclaimerNoProof,
        message: `No ML on barcodes=${noMlOnBarcodes}, No ML on non-URL QR=${noMlOnNonUrlQr}, Authenticity warning preserved=${disclaimerNoProof}`,
      };
    },
  },

  {
    name: 'Rule 16: Barcode lookup rejects invalid GS1 Modulo-10 checksums BEFORE calling any external database API',
    run: async () => {
      clearBarcodeLookupCache();
      let externalCallCount = 0;
      const countingFetch = async () => {
        externalCallCount++;
        return new Response('{}', { status: 200 });
      };

      const badChecksum = await lookupBarcodeProduct('012000000139', { fetchFn: countingFetch });
      const badLength = await lookupBarcodeProduct('12345', { fetchFn: countingFetch });

      const passed =
        externalCallCount === 0 &&
        badChecksum.status === 'invalid_checksum' &&
        !badChecksum.gs1Valid &&
        badLength.status === 'invalid_checksum';

      return {
        passed,
        message: `External HTTP calls=${externalCallCount}, checksumStatus=${badChecksum.status}, lengthStatus=${badLength.status}`,
      };
    },
  },

  {
    name: 'Rule 17: Barcode lookup parses Open Food/Beauty Facts, caches hits, and returns exact "Product not found in available databases." without counterfeit penalty',
    run: async () => {
      clearBarcodeLookupCache();
      let fetchCalls = 0;
      const mockFetch = async (url: string) => {
        fetchCalls++;
        if (url.includes('world.openbeautyfacts.org') && url.includes('3600523966097')) {
          return new Response(
            JSON.stringify({
              status: 1,
              product: {
                product_name: 'Elvital Color Vive Conditioner',
                brands: "L'Oréal Paris",
                manufacturer: "L'Oréal",
                categories: 'Hair care, Conditioners',
                countries: 'Germany',
                image_front_url: 'https://images.openbeautyfacts.org/sample.jpg',
              },
            }),
            { status: 200 }
          );
        }
        return new Response(JSON.stringify({ status: 0, status_verbose: 'product not found' }), { status: 404 });
      };

      const beautyHit = await lookupBarcodeProduct('3600523966097', { fetchFn: mockFetch });
      const callsAfterFirst = fetchCalls;
      const beautyCached = await lookupBarcodeProduct('3600523966097', { fetchFn: mockFetch });
      const cachePreventedNetworkCall = fetchCalls === callsAfterFirst && beautyCached.cached === true;

      const missingRes = await lookupBarcodeProduct('036000291452', { fetchFn: mockFetch });
      const codeAssessment = RiskScoringEngine.assessCode({ code: '036000291452', format: 'UPC_A' }, missingRes);

      const passed =
        beautyHit.found &&
        beautyHit.sourceType === 'live_database' &&
        beautyHit.product?.databaseSource === 'Open Beauty Facts' &&
        beautyHit.product?.manufacturer === "L'Oréal" &&
        cachePreventedNetworkCall &&
        missingRes.status === 'not_found' &&
        missingRes.message === 'Product not found in available databases.' &&
        codeAssessment.score <= 25;

      return {
        passed,
        message: `Beauty source=${beautyHit.product?.databaseSource}, cached=${cachePreventedNetworkCall}, missingMsg="${missingRes.message}", missingScore=${codeAssessment.score}`,
      };
    },
  },

  {
    name: 'Rule 18: Barcode lookup handles timeouts and HTTP 429 rate limits gracefully without fabricating product details',
    run: async () => {
      clearBarcodeLookupCache();
      const timeoutOrRateLimitFetch = async (url: string) => {
        if (url.includes('api.upcitemdb.com')) {
          return new Response(JSON.stringify({ code: 'EXCEED_LIMIT', message: 'Rate limit exceeded' }), { status: 429 });
        }
        const err = new Error('The operation was aborted');
        (err as any).name = 'AbortError';
        throw err;
      };

      const failedLookup = await lookupBarcodeProduct('027242919419', {
        fetchFn: timeoutOrRateLimitFetch,
        timeoutMs: 500,
        allowDemoFallback: false,
      });

      const passed =
        failedLookup.status === 'error' &&
        !failedLookup.found &&
        failedLookup.product === undefined &&
        Boolean(failedLookup.providerErrors && failedLookup.providerErrors.length >= 4) &&
        failedLookup.providerErrors!.some((e) => e.timedOut) &&
        failedLookup.providerErrors!.some((e) => e.rateLimited);

      return {
        passed,
        message: `Status=${failedLookup.status}, productOmitted=${failedLookup.product === undefined}, errorCount=${failedLookup.providerErrors?.length}`,
      };
    },
  },

  {
    name: 'Rule 19: Product Checker reuses barcode DB record to flag brand/name mismatches as warnings without claiming counterfeit',
    run: () => {
      const liveDbHit = {
        code: '3017620422003',
        gs1Valid: true,
        formatLabel: 'EAN-13 (13 digits)',
        status: 'found' as const,
        sourceType: 'live_database' as const,
        found: true,
        message: 'Product record retrieved from Open Food Facts.',
        product: {
          code: '3017620422003',
          formatLabel: 'EAN-13 (13 digits)',
          productName: 'Nutella Hazelnut Spread',
          brand: 'Ferrero, Nutella',
          category: 'Spreads',
          databaseSource: 'Open Food Facts',
        },
        queriedDatabases: ['Open Food Facts'],
        cached: false,
        fetchedAt: new Date().toISOString(),
      };

      const matchedProduct = RiskScoringEngine.assessProduct(
        {
          productName: 'Ferrero Nutella Hazelnut Spread 400g',
          brand: 'Ferrero',
          productIdentifier: '3017620422003',
          returnPolicyStatus: 'available',
        },
        liveDbHit
      );

      const mismatchedProduct = RiskScoringEngine.assessProduct(
        {
          productName: 'Wireless Gaming Mouse Pro',
          brand: 'Logitech',
          productIdentifier: '3017620422003',
          returnPolicyStatus: 'available',
        },
        liveDbHit
      );

      const alignedOk =
        matchedProduct.positiveSignals.some((s) => s.id === 'barcode-brand-match') &&
        matchedProduct.positiveSignals.some((s) => s.id === 'barcode-name-match') &&
        !matchedProduct.indicators.some((i) => i.id.startsWith('barcode-'));

      const brandWarn = mismatchedProduct.indicators.find((i) => i.id === 'barcode-brand-mismatch');
      const nameWarn = mismatchedProduct.indicators.find((i) => i.id === 'barcode-product-name-mismatch');
      const notProofClaim =
        Boolean(brandWarn?.description.includes('not definitive proof of counterfeiting')) &&
        Boolean(nameWarn?.description.includes('not definitive proof of counterfeiting'));

      return {
        passed: alignedOk && Boolean(brandWarn) && Boolean(nameWarn) && notProofClaim,
        message: `Aligned=${alignedOk}, BrandWarn=${Boolean(brandWarn)}, NameWarn=${Boolean(nameWarn)}, NonDefinitiveDisclaimer=${notProofClaim}`,
      };
    },
  },

  {
    name: 'Rule 20: Barcode lookup defaults timeout to 5000ms and uses unauthenticated UPCitemdb trial when API key env vars are unset',
    run: async () => {
      clearBarcodeLookupCache();
      const prevKey = process.env.UPCITEMDB_API_KEY;
      const prevType = process.env.UPCITEMDB_KEY_TYPE;
      const prevTimeout = process.env.BARCODE_LOOKUP_TIMEOUT_MS;

      delete process.env.UPCITEMDB_API_KEY;
      delete process.env.UPCITEMDB_KEY_TYPE;
      delete process.env.BARCODE_LOOKUP_TIMEOUT_MS;

      try {
        const defaultTimeout = getDefaultTimeoutMs();
        const calledUrls: string[] = [];
        const mockFetch = async (url: string) => {
          calledUrls.push(url);
          return new Response(JSON.stringify({ status: 0 }), { status: 404 });
        };

        const res = await lookupBarcodeProduct('036000291452', { fetchFn: mockFetch, allowDemoFallback: false });
        const usedTrialEndpoint = calledUrls.some((u) => u.includes('/prod/trial/lookup'));
        const usedOpenFacts =
          calledUrls.some((u) => u.includes('openfoodfacts.org')) &&
          calledUrls.some((u) => u.includes('openbeautyfacts.org')) &&
          calledUrls.some((u) => u.includes('openproductsfacts.org'));

        return {
          passed: defaultTimeout === 5000 && usedTrialEndpoint && usedOpenFacts && res.status === 'not_found',
          message: `DefaultTimeout=${defaultTimeout}ms, usedTrial=${usedTrialEndpoint}, usedOpenFacts=${usedOpenFacts}, status=${res.status}`,
        };
      } finally {
        if (prevKey !== undefined) process.env.UPCITEMDB_API_KEY = prevKey;
        if (prevType !== undefined) process.env.UPCITEMDB_KEY_TYPE = prevType;
        if (prevTimeout !== undefined) process.env.BARCODE_LOOKUP_TIMEOUT_MS = prevTimeout;
      }
    },
  },

  {
    name: 'Rule 21: DNS pinning blocks DNS rebinding to private IPs and catches non-existent domains cleanly',
    run: async () => {
      let ssrfCaught = false;
      try {
        await resolveAndPinPublicHost('rebind-evil.example.com', async () => [
          { address: '127.0.0.1', family: 4 },
        ]);
      } catch (err) {
        ssrfCaught = err instanceof SsrfBlockedError;
      }

      const pinned = await resolveAndPinPublicHost('shop.example.co.uk', async () => [
        { address: '93.184.216.34', family: 4 },
      ]);
      const pinnedCbResult = await new Promise<{ ip: string; family: number }>((resolve) => {
        const cb = createPinnedLookup(pinned);
        cb('shop.example.co.uk', { all: false }, (_err: any, address: string, family: number) => {
          resolve({ ip: address, family });
        });
      });

      clearDomainVerificationCache();
      const nxResult = await verifyWebsiteDomain('https://does-not-exist-vbb-test.example.com', {
        lookupFn: async () => {
          const e: any = new Error('getaddrinfo ENOTFOUND');
          e.code = 'ENOTFOUND';
          throw e;
        },
        fetchFn: async () => ({
          ok: false,
          status: 404,
          text: async () => '',
          json: async () => ({}),
        }),
      });

      const engineRes = RiskScoringEngine.assessWebsite(
        { url: 'https://does-not-exist-vbb-test.example.com' },
        nxResult
      );

      const apexOk = getRegistrableDomain('checkout.amazon.co.uk') === 'amazon.co.uk';
      const nxFlagged =
        !nxResult.dns.exists &&
        nxResult.dns.status === 'suspicious' &&
        engineRes.indicators.some((i) => i.id === 'dns-domain-not-found');

      return {
        passed: ssrfCaught && pinnedCbResult.ip === '93.184.216.34' && apexOk && nxFlagged,
        message: `SSRF-rebinding blocked=${ssrfCaught}, pinnedIP=${pinnedCbResult.ip}, apex=${apexOk}, nxFlagged=${nxFlagged}`,
      };
    },
  },

  {
    name: 'Rule 22: Real SSL/TLS verification flags expired & untrusted certs and avoids double-counting valid TLS against HTTPS',
    run: async () => {
      clearDomainVerificationCache();
      const baseLookup = async () => [{ address: '93.184.216.34', family: 4 }];
      const cleanHttp = async () => ({ statusCode: 200, headers: {}, body: '' });
      const cleanFetch = async () => ({
        ok: true,
        status: 200,
        text: async () => '',
        json: async () => ({
          events: [{ eventAction: 'registration', eventDate: '2015-01-01T00:00:00Z' }],
        }),
      });

      const expiredTlsDomain = await verifyWebsiteDomain('https://expired-shop.example.com', {
        lookupFn: baseLookup,
        httpRequestFn: cleanHttp,
        fetchFn: cleanFetch,
        tlsProbeFn: async () => ({
          authorized: false,
          authorizationError: 'CERT_HAS_EXPIRED',
          hostnameMatches: true,
          validFrom: '2020-01-01T00:00:00Z',
          validTo: '2023-01-01T00:00:00Z',
          subjectCN: 'expired-shop.example.com',
          issuer: 'Test CA',
          protocol: 'TLSv1.3',
        }),
      });

      const expiredAssessment = RiskScoringEngine.assessWebsite(
        { url: 'https://expired-shop.example.com' },
        expiredTlsDomain
      );

      const validTlsDomain = await verifyWebsiteDomain('https://valid-shop.example.com', {
        lookupFn: baseLookup,
        httpRequestFn: cleanHttp,
        fetchFn: cleanFetch,
        tlsProbeFn: async () => ({
          authorized: true,
          hostnameMatches: true,
          validFrom: new Date(Date.now() - 30 * 86_400_000).toISOString(),
          validTo: new Date(Date.now() + 90 * 86_400_000).toISOString(),
          subjectCN: 'valid-shop.example.com',
          issuer: "Let's Encrypt",
          protocol: 'TLSv1.3',
        }),
      });

      const validAssessment = RiskScoringEngine.assessWebsite(
        { url: 'https://valid-shop.example.com' },
        validTlsDomain
      );

      const expiredCaught =
        expiredTlsDomain.tls.isExpired === true &&
        expiredAssessment.indicators.some((i) => i.id === 'tls-certificate-expired') &&
        expiredAssessment.indicators.some((i) => i.id === 'tls-certificate-untrusted');

      const noHttpsDoubleCount =
        !validAssessment.positiveSignals.some((s) => s.id === 'https-enabled') &&
        validAssessment.positiveSignals.some((s) => s.id === 'tls-certificate-verified');

      return {
        passed: expiredCaught && noHttpsDoubleCount,
        message: `Expired/untrusted TLS caught=${expiredCaught}, No HTTPS double-count=${noHttpsDoubleCount}`,
      };
    },
  },

  {
    name: 'Rule 23: Redirect analyzer detects HTTP->HTTPS upgrades cleanly while blocking SSRF redirects & suspicious cross-domain targets',
    run: async () => {
      clearDomainVerificationCache();
      const publicLookup = async () => [{ address: '93.184.216.34', family: 4 }];
      const cleanFetch = async () => ({
        ok: true,
        status: 200,
        text: async () => '',
        json: async () => ({
          events: [{ eventAction: 'registration', eventDate: '2016-05-01T00:00:00Z' }],
        }),
      });
      const validTls = async () => ({
        authorized: true,
        hostnameMatches: true,
        validFrom: new Date(Date.now() - 20 * 86_400_000).toISOString(),
        validTo: new Date(Date.now() + 60 * 86_400_000).toISOString(),
        issuer: 'DigiCert Inc',
        protocol: 'TLSv1.3',
      });

      // Case A: clean HTTP -> HTTPS upgrade
      const upgradeVerify = await verifyWebsiteDomain('http://shop.example.com/deals', {
        lookupFn: publicLookup,
        tlsProbeFn: validTls,
        fetchFn: cleanFetch,
        httpRequestFn: async (parsedUrl) => {
          if (parsedUrl.protocol === 'http:') {
            return {
              statusCode: 301,
              headers: { location: 'https://shop.example.com/deals' },
              body: '',
            };
          }
          return { statusCode: 200, headers: {}, body: '' };
        },
      });
      const upgradeReport = RiskScoringEngine.assessWebsite(
        { url: 'http://shop.example.com/deals' },
        upgradeVerify
      );

      // Case B: SSRF + suspicious cross-domain redirect
      const ssrfRedirectVerify = await verifyWebsiteDomain('https://promo.example.com', {
        lookupFn: async (host) => {
          if (host.includes('internal')) return [{ address: '169.254.169.254', family: 4 }];
          return [{ address: '93.184.216.34', family: 4 }];
        },
        tlsProbeFn: validTls,
        fetchFn: cleanFetch,
        httpRequestFn: async () => ({
          statusCode: 302,
          headers: { location: 'http://internal-meta.example.net/latest/meta-data' },
          body: '',
        }),
      });
      const ssrfRedirectReport = RiskScoringEngine.assessWebsite(
        { url: 'https://promo.example.com' },
        ssrfRedirectVerify
      );

      const upgradeOk =
        upgradeVerify.redirects.httpToHttpsUpgrade &&
        upgradeVerify.tls.checked &&
        upgradeReport.positiveSignals.some((s) => s.id === 'http-to-https-upgrade') &&
        !upgradeReport.indicators.some((i) => i.id === 'insecure-http');

      const ssrfHopBlocked =
        ssrfRedirectVerify.redirects.suspiciousDestination &&
        ssrfRedirectVerify.redirects.hops.some((h) => h.blockedBySsrf) &&
        ssrfRedirectReport.indicators.some((i) => i.id === 'redirect-suspicious-destination');

      return {
        passed: upgradeOk && ssrfHopBlocked,
        message: `HTTP->HTTPS upgrade handled=${upgradeOk}, SSRF redirect hop blocked & flagged=${ssrfHopBlocked}`,
      };
    },
  },

  {
    name: 'Rule 24: Domain verification never classifies a phishing or OpenPhish-listed site as safe just because it has HTTPS + old domain',
    run: async () => {
      clearDomainVerificationCache();
      const recentDate = new Date(Date.now() - 10 * 86_400_000).toISOString();
      const oldDate = '2008-03-10T00:00:00Z';

      const baseLookup = async () => [{ address: '93.184.216.34', family: 4 }];
      const cleanHttp = async () => ({ statusCode: 200, headers: {}, body: '' });
      const validTls = async () => ({
        authorized: true,
        hostnameMatches: true,
        validFrom: new Date(Date.now() - 10 * 86_400_000).toISOString(),
        validTo: new Date(Date.now() + 80 * 86_400_000).toISOString(),
        issuer: 'Sectigo',
        protocol: 'TLSv1.3',
      });

      // Case A: Old domain + Valid HTTPS cert, BUT listed on OpenPhish!
      const oldButPhishing = await verifyWebsiteDomain('https://compromised-merchant.example.com/login', {
        lookupFn: baseLookup,
        httpRequestFn: cleanHttp,
        tlsProbeFn: validTls,
        fetchFn: async (url) => {
          if (url.includes('openphish.com')) {
            return {
              ok: true,
              status: 200,
              text: async () => 'https://compromised-merchant.example.com/login\n',
              json: async () => ({}),
            };
          }
          return {
            ok: true,
            status: 200,
            text: async () => '',
            json: async () => ({
              events: [{ eventAction: 'registration', eventDate: oldDate }],
            }),
          };
        },
      });
      const oldPhishingReport = RiskScoringEngine.assessWebsite(
        { url: 'https://compromised-merchant.example.com/login' },
        oldButPhishing
      );

      // Case B: Brand-new 10-day domain
      const youngDomain = await verifyWebsiteDomain('https://brandnew-store.example.com', {
        lookupFn: baseLookup,
        httpRequestFn: cleanHttp,
        tlsProbeFn: validTls,
        fetchFn: async (url) => {
          if (url.includes('openphish.com')) {
            return { ok: true, status: 200, text: async () => '', json: async () => ({}) };
          }
          return {
            ok: true,
            status: 200,
            text: async () => '',
            json: async () => ({
              events: [{ eventAction: 'registration', eventDate: recentDate }],
            }),
          };
        },
      });
      const youngReport = RiskScoringEngine.assessWebsite(
        { url: 'https://brandnew-store.example.com' },
        youngDomain
      );

      const phishingStillHigh =
        oldButPhishing.threatIntel.listed &&
        oldButPhishing.rdap.domainAgeDays! > 3650 &&
        oldPhishingReport.score >= 50 &&
        oldPhishingReport.category !== 'lower';

      const youngFlagged =
        youngDomain.rdap.domainAgeDays! <= 12 &&
        youngReport.indicators.some((i) => i.id === 'rdap-newly-registered-domain');

      return {
        passed: phishingStillHigh && youngFlagged,
        message: `Old+HTTPS phishing NOT classified safe (score=${oldPhishingReport.score}, cat=${oldPhishingReport.category}), youngDomainFlagged=${youngFlagged}`,
      };
    },
  },

  {
    name: 'Rule 25: Domain verification degrades gracefully to Unavailable on timeouts / 429 rate limits without fabricating ages or cert dates',
    run: async () => {
      clearDomainVerificationCache();
      const timeoutOrRateLimit = await verifyWebsiteDomain('https://slow-store.example.com', {
        lookupFn: async () => [{ address: '93.184.216.34', family: 4 }],
        httpRequestFn: async () => {
          throw new Error('Request timed out after 5s');
        },
        tlsProbeFn: async () => {
          throw new Error('TLS handshake timed out');
        },
        fetchFn: async (url) => {
          if (url.includes('openphish.com')) {
            return { ok: false, status: 429, text: async () => 'rate limited', json: async () => ({}) };
          }
          return { ok: false, status: 429, text: async () => 'rate limited', json: async () => ({}) };
        },
      });

      const passed =
        timeoutOrRateLimit.dns.exists === true &&
        timeoutOrRateLimit.tls.status === 'unavailable' &&
        timeoutOrRateLimit.tls.validTo === undefined &&
        timeoutOrRateLimit.rdap.status === 'unavailable' &&
        timeoutOrRateLimit.rdap.domainAgeDays === undefined &&
        timeoutOrRateLimit.rdap.registrationDate === undefined &&
        timeoutOrRateLimit.threatIntel.status === 'unavailable' &&
        timeoutOrRateLimit.threatIntel.listed === false;

      return {
        passed,
        message: `TLS=${timeoutOrRateLimit.tls.status}, RDAP=${timeoutOrRateLimit.rdap.status} (age=${timeoutOrRateLimit.rdap.domainAgeDays}), ThreatIntel=${timeoutOrRateLimit.threatIntel.status}`,
      };
    },
  },

  {
    name: 'Rule 26: Seller verification extracts structured merchant fields, distinguishes product vs seller ratings, and confirms official storefronts only when verified',
    run: async () => {
      clearSellerVerificationCache();
      const officialHtml = `
        <html>
          <head>
            <script type="application/ld+json">
              {
                "@context": "https://schema.org",
                "@type": "Product",
                "name": "Sony WH-1000XM5 Headphones",
                "brand": { "@type": "Brand", "name": "Sony" },
                "aggregateRating": { "@type": "AggregateRating", "ratingValue": "4.9", "reviewCount": "4200" },
                "offers": {
                  "@type": "Offer",
                  "price": "349.99",
                  "priceCurrency": "USD",
                  "hasMerchantReturnPolicy": {
                    "@type": "MerchantReturnPolicy",
                    "returnPolicyCategory": "https://schema.org/MerchantReturnFiniteReturnWindow",
                    "merchantReturnDays": 30
                  },
                  "seller": {
                    "@type": "Organization",
                    "name": "Sony Electronics",
                    "url": "https://electronics.sony.com/seller-info",
                    "legalName": "Sony Electronics Inc.",
                    "taxID": "US-95-1234567",
                    "foundingDate": "2010-04-01",
                    "aggregateRating": {
                      "@type": "AggregateRating",
                      "ratingValue": "4.7",
                      "bestRating": "5",
                      "ratingCount": "850"
                    }
                  }
                }
              }
            </script>
          </head>
        </html>
      `;

      const sv = await verifySellerInfo(
        {
          listingUrl: 'https://electronics.sony.com/audio/wh1000xm5',
          brand: 'Sony',
          sellerName: 'Sony Electronics',
          sellerRating: 4.7,
          returnPolicyStatus: 'available',
        },
        {
          fetchFn: async (url) => ({
            finalUrl: url,
            statusCode: 200,
            contentType: 'text/html',
            body: officialHtml,
          }),
        }
      );

      // Ensure third-party store without Product seller.aggregateRating NEVER uses Product.aggregateRating (4.9)
      const noSellerRatingHtml = `
        <html><head><script type="application/ld+json">
          {
            "@context": "https://schema.org",
            "@type": "Product",
            "name": "Sony WH-1000XM5",
            "aggregateRating": { "@type": "AggregateRating", "ratingValue": "4.9", "reviewCount": "500" },
            "offers": {
              "@type": "Offer",
              "price": "299.00",
              "seller": { "@type": "Organization", "name": "IndependentAudioHub" }
            }
          }
        </script></head></html>
      `;
      const thirdPartySv = await verifySellerInfo(
        {
          listingUrl: 'https://independentaudio.example.com/sony-xm5',
          brand: 'Sony',
          sellerName: 'IndependentAudioHub',
        },
        {
          fetchFn: async (url) => ({
            finalUrl: url,
            statusCode: 200,
            contentType: 'text/html',
            body: noSellerRatingHtml,
          }),
        }
      );

      const officialOk =
        sv.status === 'verified' &&
        sv.retrieved.sellerName === 'Sony Electronics' &&
        sv.retrieved.sellerProfileUrl === 'https://electronics.sony.com/seller-info' &&
        sv.retrieved.sellerRating === 4.7 &&
        sv.retrieved.sellerRatingCount === 850 &&
        Boolean(sv.retrieved.sellerAccountAgeDays && sv.retrieved.sellerAccountAgeDays > 3650) &&
        Boolean(sv.retrieved.businessRegistration?.includes('US-95-1234567')) &&
        sv.retrieved.authorizedSellerStatus === 'confirmed_official' &&
        sv.retrieved.returnPolicyStatus === 'available';

      const noProductRatingLeak =
        thirdPartySv.retrieved.sellerRating === undefined &&
        thirdPartySv.retrieved.authorizedSellerStatus === 'third_party_unverified';

      return {
        passed: officialOk && noProductRatingLeak,
        message: `Official verified=${officialOk}, Product rating isolated & 3rd-party not claimed official=${noProductRatingLeak}`,
      };
    },
  },

  {
    name: 'Rule 27: Seller verification catches mismatched seller names & low retrieved seller ratings without double-counting',
    run: async () => {
      clearSellerVerificationCache();
      const mismatchedHtml = `
        <html><head><script type="application/ld+json">
          {
            "@context": "https://schema.org",
            "@type": "Product",
            "name": "Designer Sunglasses",
            "offers": {
              "@type": "Offer",
              "price": "89.00",
              "hasMerchantReturnPolicy": {
                "@type": "MerchantReturnPolicy",
                "returnPolicyCategory": "https://schema.org/MerchantReturnNotPermitted"
              },
              "seller": {
                "@type": "Organization",
                "name": "deals_king_99",
                "aggregateRating": {
                  "@type": "AggregateRating",
                  "ratingValue": "2.2",
                  "bestRating": "5",
                  "ratingCount": "43"
                }
              }
            }
          }
        </script></head></html>
      `;

      const sv = await verifySellerInfo(
        {
          productName: 'Designer Sunglasses',
          listingUrl: 'https://shady-outlet.example.com/sunglasses',
          sellerName: 'Official Luxury Boutique',
          sellerRating: 4.9,
          returnPolicyStatus: 'available',
        },
        {
          fetchFn: async (url) => ({
            finalUrl: url,
            statusCode: 200,
            contentType: 'text/html',
            body: mismatchedHtml,
          }),
        }
      );

      // Also verify low rating submitted by user + same low retrieved rating does NOT double-count both low-seller-rating and verified-low-seller-rating
      const lowSameHtml = mismatchedHtml.replace('deals_king_99', 'deals-shop_999');
      const lowSameSv = await verifySellerInfo(
        {
          productName: 'Designer Sunglasses',
          listingUrl: 'https://shady-outlet.example.com/sunglasses',
          sellerName: 'deals-shop_999',
          sellerRating: 2.2,
          returnPolicyStatus: 'not_available',
        },
        {
          fetchFn: async (url) => ({
            finalUrl: url,
            statusCode: 200,
            contentType: 'text/html',
            body: lowSameHtml,
          }),
        }
      );

      const assessmentMismatch = RiskScoringEngine.assessProduct(
        {
          productName: 'Designer Sunglasses',
          listingUrl: 'https://shady-outlet.example.com/sunglasses',
          sellerName: 'Official Luxury Boutique',
          sellerRating: 4.9,
          returnPolicyStatus: 'available',
        },
        undefined,
        sv
      );

      const assessmentLowDedup = RiskScoringEngine.assessProduct(
        {
          productName: 'Designer Sunglasses',
          listingUrl: 'https://shady-outlet.example.com/sunglasses',
          sellerName: 'deals-shop_999',
          sellerRating: 2.2,
          returnPolicyStatus: 'not_available',
        },
        undefined,
        lowSameSv
      );

      const mismatchOk =
        sv.status === 'mismatch_or_warning' &&
        sv.comparison.sellerNameMatch === 'mismatch' &&
        sv.comparison.returnPolicyMismatch === true &&
        assessmentMismatch.indicators.some((i) => i.id === 'seller-name-mismatch') &&
        assessmentMismatch.indicators.some((i) => i.id === 'seller-rating-discrepancy') &&
        assessmentMismatch.indicators.some((i) => i.id === 'seller-return-policy-mismatch') &&
        assessmentMismatch.indicators.some((i) => i.id === 'verified-low-seller-rating');

      const noDoubleCount =
        !assessmentLowDedup.indicators.some((i) => i.id === 'low-seller-rating') &&
        assessmentLowDedup.indicators.some((i) => i.id === 'verified-low-seller-rating') &&
        !assessmentLowDedup.indicators.some((i) => i.id === 'verified-suspicious-seller-handle'); // generic-seller-handle already covered handle

      return {
        passed: mismatchOk && noDoubleCount,
        message: `Mismatch & discrepancy flagged=${mismatchOk}, No double-count=${noDoubleCount}`,
      };
    },
  },

  {
    name: 'Rule 28: Unavailable seller information (no URL, timeouts, missing metadata) never fabricates details or penalizes as fraud',
    run: async () => {
      clearSellerVerificationCache();

      const noUrlSv = await verifySellerInfo({
        productName: 'Ceramic Mug',
        sellerName: 'Pottery Studio',
      });

      const timeoutSv = await verifySellerInfo(
        {
          productName: 'Ceramic Mug',
          listingUrl: 'https://pottery.example.com/mug',
          sellerName: 'Pottery Studio',
        },
        {
          fetchFn: async () => {
            const err: any = new Error('Timed out');
            err.name = 'AbortError';
            throw err;
          },
        }
      );

      const report = RiskScoringEngine.assessProduct(
        {
          productName: 'Ceramic Mug',
          listingUrl: 'https://pottery.example.com/mug',
          sellerName: 'Pottery Studio',
          returnPolicyStatus: 'unknown',
        },
        undefined,
        timeoutSv
      );

      const passed =
        noUrlSv.status === 'unverified' &&
        timeoutSv.status === 'unavailable' &&
        timeoutSv.retrieved.sellerName === undefined &&
        timeoutSv.retrieved.sellerRating === undefined &&
        timeoutSv.retrieved.authorizedSellerStatus === 'unavailable' &&
        timeoutSv.userProvided.sellerName === 'Pottery Studio' &&
        report.score <= 25 &&
        report.category === 'lower';

      return {
        passed,
        message: `No-URL=${noUrlSv.status}, Timeout=${timeoutSv.status}, Neutral risk score=${report.score} (${report.category})`,
      };
    },
  },

  {
    name: 'Rule 29: Restricted marketplace pages (CAPTCHA / HTTP 403) do not bypass blocks, preserve user inputs, and avoid fraud penalties',
    run: async () => {
      clearSellerVerificationCache();
      const restrictedSv = await verifySellerInfo(
        {
          productName: 'Wireless Earbuds',
          listingUrl: 'https://www.amazon.com/dp/B09G9FPHY6',
          sellerName: 'SoundDirect',
          sellerRating: 4.5,
          returnPolicyStatus: 'available',
        },
        {
          fetchFn: async (url) => ({
            finalUrl: url,
            statusCode: 503,
            contentType: 'text/html',
            body: '<html><title>Robot Check</title><body>Sorry! We just need to make sure you\'re not a robot</body></html>',
          }),
        }
      );

      const assessment = RiskScoringEngine.assessProduct(
        {
          productName: 'Wireless Earbuds',
          listingUrl: 'https://www.amazon.com/dp/B09G9FPHY6',
          sellerName: 'SoundDirect',
          sellerRating: 4.5,
          returnPolicyStatus: 'available',
        },
        undefined,
        restrictedSv
      );

      const passed =
        restrictedSv.status === 'restricted' &&
        restrictedSv.accessRestricted === true &&
        restrictedSv.requiresAuthorizedApi === true &&
        restrictedSv.retrieved.sellerName === undefined &&
        restrictedSv.retrieved.authorizedSellerStatus === 'unavailable' &&
        restrictedSv.userProvided.sellerName === 'SoundDirect' &&
        assessment.score <= 25 &&
        assessment.unverifiedAspects.some((u) => u.includes('External seller verification (restricted)'));

      return {
        passed,
        message: `Status=${restrictedSv.status}, restricted=${restrictedSv.accessRestricted}, authApiNeeded=${restrictedSv.requiresAuthorizedApi}, score=${assessment.score}`,
      };
    },
  },

  {
    name: 'Rule 30: Multi-source market price comparison computes min/max/median, separates price types, avoids double-counting, and never flags counterfeit solely from low price',
    run: async () => {
      clearMarketPriceCache();
      const mpc = await compareMarketPrices(
        {
          productName: 'Bose QuietComfort Ultra Headphones',
          brand: 'Bose',
          productIdentifier: '017817846196',
          listedPrice: 49.0,
          referencePrice: 429.0,
          currency: 'USD',
          referenceCurrency: 'USD',
        },
        {
          fetchFn: async (url) => {
            if (url.includes('bose.com')) {
              return {
                finalUrl: url,
                statusCode: 200,
                contentType: 'text/html',
                body: `<html><head><script type="application/ld+json">{
                  "@context":"https://schema.org",
                  "@type":"ProductGroup",
                  "name":"Bose QuietComfort Ultra Headphones",
                  "hasVariant":[{
                    "@type":"Product",
                    "name":"Bose QuietComfort Ultra Headphones Black",
                    "offers":{
                      "@type":"Offer",
                      "price":"429.00",
                      "priceCurrency":"USD",
                      "itemCondition":"https://schema.org/NewCondition",
                      "priceSpecification":{"@type":"PriceSpecification","priceType":"https://schema.org/MSRP","price":"449.00","priceCurrency":"USD"}
                    }
                  }]
                }</script></head></html>`,
              };
            }
            if (url.includes('upcitemdb.com')) {
              return {
                finalUrl: url,
                statusCode: 200,
                contentType: 'application/json',
                body: JSON.stringify({
                  items: [
                    {
                      upc: '017817846196',
                      title: 'Bose QuietComfort Ultra Headphones',
                      offers: [
                        { merchant: 'Best Buy', price: 399.0, currency: 'USD', link: 'https://bestbuy.com/bose-qc-ultra', updated_t: 1730000000 },
                        { merchant: 'Target', price: 379.0, currency: 'USD', link: 'https://target.com/bose-qc-ultra', updated_t: 1730000100 },
                      ],
                    },
                  ],
                }),
              };
            }
            return { finalUrl: url, statusCode: 404, contentType: 'text/html', body: '' };
          },
        }
      );

      // External quotes: 379, 399, 429, 449 -> min=379, max=449, median=(399+429)/2 = 414
      const statsOk =
        mpc.status === 'verified_comparison' &&
        mpc.stats?.externalQuoteCount === 4 &&
        mpc.stats?.minPrice === 379 &&
        mpc.stats?.maxPrice === 449 &&
        mpc.stats?.medianPrice === 414 &&
        mpc.quotes.some((q) => q.priceType === 'official_msrp') &&
        mpc.quotes.some((q) => q.priceType === 'current_retail') &&
        mpc.quotes.some((q) => q.priceType === 'user_reference');

      // Low price alone must NOT double-count or classify as High Risk / counterfeit
      const assessed = RiskScoringEngine.assessProduct(
        {
          productName: 'Bose QuietComfort Ultra Headphones',
          brand: 'Bose',
          productIdentifier: '017817846196',
          listedPrice: 49.0,
          referencePrice: 429.0,
          currency: 'USD',
          referenceCurrency: 'USD',
        },
        undefined,
        undefined,
        mpc
      );

      const noDoubleCount =
        !assessed.indicators.some((i) => i.id === 'steep-discount-investigation') &&
        assessed.indicators.some((i) => i.id === 'market-price-extreme-discount');
      const neverHighFromPriceAlone = assessed.score <= 35 && assessed.category !== 'high';

      return {
        passed: statsOk && noDoubleCount && neverHighFromPriceAlone,
        message: `StatsOk=${statsOk} (min=${mpc.stats?.minPrice}, med=${mpc.stats?.medianPrice}, max=${mpc.stats?.maxPrice}), noDoubleCount=${noDoubleCount}, lowPriceScore=${assessed.score} (${assessed.category})`,
      };
    },
  },

  {
    name: 'Rule 31: Variant matcher rejects mismatched storage/model/pack/condition offers and attenuates legitimate refurbished discounts',
    run: async () => {
      clearMarketPriceCache();
      const mpc = await compareMarketPrices(
        {
          productName: 'Apple iPhone 16 Pro 128GB',
          brand: 'Apple',
          productIdentifier: '195949821233',
          listedPrice: 949,
          currency: 'USD',
        },
        {
          fetchFn: async (url) => {
            if (url.includes('upcitemdb.com')) {
              return {
                finalUrl: url,
                statusCode: 200,
                contentType: 'application/json',
                body: JSON.stringify({
                  items: [
                    {
                      upc: '195949821233',
                      title: 'Apple iPhone 16 Pro 128GB',
                      offers: [
                        { merchant: 'AuthorizedApple', price: 999, currency: 'USD', title: 'Apple iPhone 16 Pro 128GB Brand New' },
                        { merchant: 'CapacityMismatchStore', price: 1399, currency: 'USD', title: 'Apple iPhone 16 Pro 512GB Brand New' },
                        { merchant: 'TierMismatchStore', price: 1199, currency: 'USD', title: 'Apple iPhone 16 Pro Max 128GB Brand New' },
                        { merchant: 'UsedReseller', price: 650, currency: 'USD', title: 'Apple iPhone 16 Pro 128GB', condition: 'Used' },
                        { merchant: 'MultiPackStore', price: 1998, currency: 'USD', title: 'Apple iPhone 16 Pro 128GB 2-Pack' },
                      ],
                    },
                  ],
                }),
              };
            }
            return { finalUrl: url, statusCode: 404, contentType: 'text/html', body: '' };
          },
        }
      );

      const onlyExactKept =
        mpc.stats?.externalQuoteCount === 1 &&
        mpc.stats?.medianPrice === 999 &&
        mpc.excludedMismatches.length === 4;

      // Also verify refurbished listing gets attenuated discount indicator instead of extreme-discount penalty
      const refurbMpc = await compareMarketPrices(
        {
          productName: 'Sony WH-1000XM4 Wireless Headphones (Refurbished)',
          brand: 'Sony',
          listedPrice: 45,
          referencePrice: 349.99,
          currency: 'USD',
          returnPolicyStatus: 'available',
        },
        {
          fetchFn: async (url) => ({ finalUrl: url, statusCode: 404, contentType: 'text/html', body: '' }),
        }
      );

      const refurbAssessed = RiskScoringEngine.assessProduct(
        {
          productName: 'Sony WH-1000XM4 Wireless Headphones (Refurbished)',
          brand: 'Sony',
          listedPrice: 45,
          referencePrice: 349.99,
          currency: 'USD',
          returnPolicyStatus: 'available',
        },
        undefined,
        undefined,
        refurbMpc
      );

      const refurbAttenuated =
        refurbMpc.inferredCondition === 'refurbished' &&
        refurbAssessed.indicators.some((i) => i.id === 'market-price-clearance-refurb-discount') &&
        !refurbAssessed.indicators.some((i) => i.id === 'market-price-extreme-discount') &&
        refurbAssessed.score <= 25;

      return {
        passed: onlyExactKept && refurbAttenuated,
        message: `ExactOnly=${onlyExactKept} (excluded=${mpc.excludedMismatches.length}), RefurbAttenuated=${refurbAttenuated} (score=${refurbAssessed.score})`,
      };
    },
  },

  {
    name: 'Rule 32: Indian INR listings prioritize INR quotes and refuse unverified cross-currency comparisons when FX is unavailable',
    run: async () => {
      clearMarketPriceCache();
      // Case A: INR priority with mixed INR + live FX-converted USD quote
      const inrWithFx = await compareMarketPrices(
        {
          productName: 'boAt Rockerz 450 Pro',
          brand: 'boAt',
          productIdentifier: '8904130861239',
          listedPrice: 1799,
          currency: 'INR',
        },
        {
          fetchFn: async (url) => {
            if (url.includes('boat-lifestyle.com')) {
              return {
                finalUrl: url,
                statusCode: 200,
                contentType: 'application/json',
                body: JSON.stringify({
                  resources: {
                    results: {
                      products: [
                        { title: 'boAt Rockerz 450 Pro', price: '1999.00', compare_at_price_max: '3990.00', url: '/products/rockerz-450-pro' },
                      ],
                    },
                  },
                }),
              };
            }
            if (url.includes('upcitemdb.com')) {
              return {
                finalUrl: url,
                statusCode: 200,
                contentType: 'application/json',
                body: JSON.stringify({
                  items: [
                    {
                      upc: '8904130861239',
                      title: 'boAt Rockerz 450 Pro',
                      offers: [{ merchant: 'GlobalShop', price: 25, currency: 'USD', link: 'https://global.example.com/boat' }],
                    },
                  ],
                }),
              };
            }
            return { finalUrl: url, statusCode: 404, contentType: 'text/html', body: '' };
          },
          fxFetchFn: async (url) => ({
            finalUrl: url,
            statusCode: 200,
            contentType: 'application/json',
            body: JSON.stringify({ result: 'success', base_code: 'USD', rates: { INR: 84.0 } }),
          }),
        }
      );

      // Case B: Foreign currency quote when FX service fails -> must refuse comparison cleanly
      const fxUnavailable = await compareMarketPrices(
        {
          productName: 'Headphones Model Z',
          productIdentifier: '012000000133',
          listedPrice: 8000,
          currency: 'INR',
        },
        {
          fetchFn: async (url) => {
            if (url.includes('upcitemdb.com')) {
              return {
                finalUrl: url,
                statusCode: 200,
                contentType: 'application/json',
                body: JSON.stringify({
                  items: [
                    {
                      upc: '012000000133',
                      title: 'Headphones Model Z',
                      offers: [{ merchant: 'USStore', price: 100, currency: 'USD' }],
                    },
                  ],
                }),
              };
            }
            return { finalUrl: url, statusCode: 404, contentType: 'text/html', body: '' };
          },
          fxFetchFn: async () => {
            throw new Error('FX service offline');
          },
        }
      );

      const inrOk =
        inrWithFx.indianMarketPrioritized === true &&
        inrWithFx.currencyConversion?.performed === true &&
        inrWithFx.quotes[0].currency === 'INR' &&
        inrWithFx.stats?.externalQuoteCount === 3;

      const fxBlockedOk =
        fxUnavailable.status === 'currency_mismatch' &&
        fxUnavailable.quotes.length === 0 &&
        fxUnavailable.excludedMismatches.length === 1 &&
        fxUnavailable.currencyConversion?.performed === false;

      return {
        passed: inrOk && fxBlockedOk,
        message: `INR prioritized & FX converted=${inrOk}, Missing FX refused cross-currency=${fxBlockedOk}`,
      };
    },
  },

  {
    name: 'Rule 33: Restricted/unavailable market sources retain manual reference entry cleanly without fabricating prices',
    run: async () => {
      clearMarketPriceCache();
      const restricted = await compareMarketPrices(
        {
          productName: 'Artisan Desk Lamp',
          listingUrl: 'https://www.amazon.com/dp/B09G9FPHY6',
          listedPrice: 45,
          referencePrice: 60,
          currency: 'USD',
        },
        {
          fetchFn: async (url) => ({
            finalUrl: url,
            statusCode: 503,
            contentType: 'text/html',
            body: '<html><title>Robot Check</title><body>Enter the characters you see below</body></html>',
          }),
        }
      );

      const passed =
        restricted.status === 'partial_or_user_reference' &&
        restricted.manualReferenceRetained === true &&
        restricted.stats?.externalQuoteCount === 0 &&
        restricted.stats?.selectedReferencePrice === 60 &&
        restricted.stats?.selectedReferenceType === 'user_reference' &&
        restricted.stats?.minPrice === undefined &&
        restricted.sourceErrors.length > 0;

      return {
        passed,
        message: `Status=${restricted.status}, manualRetained=${restricted.manualReferenceRetained}, extCount=${restricted.stats?.externalQuoteCount}`,
      };
    },
  },
];

export async function runAllTests(): Promise<{ passed: number; failed: number }> {
  console.log('\n=============================================');
  console.log('🧪 VERIFYBEFOREBUY AI — RISK ENGINE TEST SUITE');
  console.log('=============================================\n');

  let passed = 0;
  let failed = 0;

  for (let i = 0; i < tests.length; i++) {
    const test = tests[i];
    try {
      const res = await test.run();
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

  if (failed > 0) {
    process.exitCode = 1;
  }

  return { passed, failed };
}

// Execute directly if run via tsx
runAllTests();
