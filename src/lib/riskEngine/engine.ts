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
  BarcodeLookupResult,
  DomainVerificationResult,
  SellerVerificationResult,
  MarketPriceComparisonResult,
} from '../../types';
import { getRiskCategory, COMMON_DISCLAIMER } from './rules';
import { analyzeUrlStructure } from './urlAnalyzer';
import { analyzeProductListing } from './productAnalyzer';
import { analyzeCodePayload } from './codeAnalyzer';
import { predictPhishing } from '../mlInference';
import { predictProductRisk } from '../productMlInference';
import { validateProductInput } from '../productValidator';
import { validateWebsiteUrl } from '../urlValidator';

export class RiskScoringEngine {
  /**
   * Run Website Risk Assessment
   * Merges syntactic URL rules, trained Phishing ML model, and optional live DomainVerificationResult
   * without double-counting equivalent HTTPS/TLS or redirect signals.
   */
  public static assessWebsite(
    input: WebsiteAnalysisInput,
    domainVerification?: DomainVerificationResult
  ): AssessmentResult {
    const analysis = analyzeUrlStructure(input.url);
    const hasInvalidSyntax = analysis.indicators.some(
      (i) => i.id === 'invalid-url-format' || i.id === 'unsafe-protocol'
    );

    const mlPred = hasInvalidSyntax ? undefined : predictPhishing(input.url);

    // If trained ML model predicts high phishing risk, reflect it in indicators
    if (mlPred && mlPred.isPhishing && mlPred.probability >= 0.60) {
      // Avoid double-counting overlapping lexical URL rules already scored by ML
      const overlappedIds = new Set([
        'high-abuse-tld',
        'ip-address-host',
        'hyphen-stuffing',
        'excessive-subdomains',
      ]);
      analysis.indicators = analysis.indicators.filter((ind) => !overlappedIds.has(ind.id));

      analysis.indicators.push({
        id: 'ml_phishing_high_risk',
        name: `ML Model Phishing Alert (${Math.round(mlPred.probability * 100)}% Probability)`,
        category: 'technical',
        severity: mlPred.probability >= 0.85 ? 'high' : 'medium',
        scoreImpact: Math.round(mlPred.probability * 25),
        isObserved: true,
        description: `Supervised classification model trained on 80,000 real-world malicious and legitimate URLs classified this URL structure as malicious with ${Math.round(mlPred.probability * 100)}% probability.`,
        remedyOrPrecaution: 'Do not enter passwords, credit cards, or personal credentials on this domain. Check the domain spelling carefully.',
      });
      analysis.evidenceWeight = Math.min(100, analysis.evidenceWeight + 20);
    } else if (mlPred && !mlPred.isPhishing && mlPred.probability <= 0.30) {
      analysis.positiveSignals.push({
        id: 'ml_benign_classification',
        name: `ML Model Clean Profile (${Math.round((1 - mlPred.probability) * 100)}% Benign Confidence)`,
        description: `Trained machine learning classifier found no anomalous lexical or deception markers in the URL pattern.`,
        isVerified: true,
        scoreDeduction: 15,
      });
      analysis.evidenceWeight = Math.min(100, analysis.evidenceWeight + 15);
    }

    // Merge real-time domain verification signals without double-counting syntactic checks
    if (domainVerification && !hasInvalidSyntax) {
      // Replace syntactic HTTPS assumption with real TLS / redirect verification outcome
      analysis.positiveSignals = analysis.positiveSignals.filter((s) => s.id !== 'https-enabled');

      // 1. DNS Resolution Check
      if (domainVerification.dns.exists) {
        analysis.positiveSignals.push({
          id: 'dns-resolved',
          name: 'DNS Resolution Confirmed',
          description: `Domain resolves in public DNS (${domainVerification.dns.resolvedIps.slice(0, 2).join(', ')}).`,
          isVerified: true,
          scoreDeduction: 3,
        });
        analysis.evidenceWeight = Math.min(100, analysis.evidenceWeight + 10);
      } else if (domainVerification.dns.status === 'suspicious') {
        analysis.indicators.push({
          id: 'dns-domain-not-found',
          name: 'Domain Does Not Resolve in DNS',
          category: 'technical',
          severity: 'high',
          scoreImpact: 35,
          isObserved: true,
          description: domainVerification.dns.error || `DNS lookup found no active public IP records for "${domainVerification.hostname}".`,
          remedyOrPrecaution: 'Verify the exact spelling of the website address. Non-existent domains cannot host legitimate checkouts.',
        });
        analysis.evidenceWeight = Math.min(100, analysis.evidenceWeight + 15);
      }

      // 2. HTTP -> HTTPS Upgrades & Redirect Chain Inspection
      if (domainVerification.redirects.httpToHttpsUpgrade) {
        analysis.indicators = analysis.indicators.filter((i) => i.id !== 'insecure-http');
        analysis.positiveSignals.push({
          id: 'http-to-https-upgrade',
          name: 'Automatic HTTP-to-HTTPS Upgrade',
          description: `HTTP request automatically redirected to encrypted HTTPS (${domainVerification.redirects.finalUrl}).`,
          isVerified: true,
          scoreDeduction: 4,
        });
      }

      if (domainVerification.redirects.downgradeHttpsToHttp) {
        analysis.indicators.push({
          id: 'redirect-https-downgrade',
          name: 'Insecure HTTPS-to-HTTP Redirect Downgrade',
          category: 'technical',
          severity: 'high',
          scoreImpact: 30,
          isObserved: true,
          description: 'The HTTPS URL redirected visitors down to an unencrypted HTTP destination.',
          remedyOrPrecaution: 'Do not submit login credentials or payment details after an encryption downgrade redirect.',
        });
      }

      if (domainVerification.redirects.suspiciousDestination) {
        analysis.indicators.push({
          id: 'redirect-suspicious-destination',
          name: 'Suspicious Redirect Destination Detected',
          category: 'url',
          severity: 'high',
          scoreImpact: 30,
          isObserved: true,
          description: domainVerification.redirects.suspiciousReasons.join('; ') || `URL redirected to a suspicious destination (${domainVerification.redirects.finalUrl}).`,
          remedyOrPrecaution: 'Avoid following unexpected multi-hop or cross-domain redirects away from the advertised storefront.',
        });
        analysis.evidenceWeight = Math.min(100, analysis.evidenceWeight + 12);
      } else if (domainVerification.redirects.crossDomainRedirect) {
        analysis.indicators.push({
          id: 'redirect-cross-domain',
          name: 'Cross-Domain Redirect Observed',
          category: 'url',
          severity: 'low',
          scoreImpact: 8,
          isObserved: true,
          description: `Initial URL redirected across domains to "${domainVerification.redirects.finalUrl}". Confirm this belongs to the intended merchant.`,
          remedyOrPrecaution: 'Check that the final address bar domain matches the company you intend to buy from.',
        });
      }

      // 3. Real SSL/TLS Certificate Validation (never solely classifies a site as safe)
      if (domainVerification.tls.checked) {
        analysis.unverifiedAspects = analysis.unverifiedAspects.filter(
          (u) => !u.toLowerCase().includes('tls certificate')
        );

        if (domainVerification.tls.isExpired) {
          analysis.indicators.push({
            id: 'tls-certificate-expired',
            name: 'Expired SSL/TLS Certificate',
            category: 'technical',
            severity: 'high',
            scoreImpact: 35,
            isObserved: true,
            description: `The server certificate expired on ${domainVerification.tls.validTo ? new Date(domainVerification.tls.validTo).toLocaleDateString() : 'an earlier date'}. Legitimate merchants maintain active TLS certificates.`,
            remedyOrPrecaution: 'Do not enter payment or personal information on sites with expired certificates.',
          });
        } else if (domainVerification.tls.isNotYetValid) {
          analysis.indicators.push({
            id: 'tls-certificate-not-yet-valid',
            name: 'Not-Yet-Valid SSL/TLS Certificate',
            category: 'technical',
            severity: 'medium',
            scoreImpact: 20,
            isObserved: true,
            description: 'The server presented a certificate whose validity start date is in the future.',
            remedyOrPrecaution: 'Verify certificate issuance before trusting the site with sensitive information.',
          });
        }

        if (!domainVerification.tls.isTrusted) {
          analysis.indicators.push({
            id: 'tls-certificate-untrusted',
            name: 'Untrusted or Hostname-Mismatched TLS Certificate',
            category: 'technical',
            severity: 'high',
            scoreImpact: 35,
            isObserved: true,
            description: `Certificate failed trust or hostname verification${domainVerification.tls.authorizationError ? ` (${domainVerification.tls.authorizationError})` : ''}.`,
            remedyOrPrecaution: 'Leave the site immediately; an untrusted certificate exposes traffic to spoofing or interception.',
          });
        }

        if (
          domainVerification.tls.isTrusted &&
          !domainVerification.tls.isExpired &&
          !domainVerification.tls.isNotYetValid
        ) {
          analysis.positiveSignals.push({
            id: 'tls-certificate-verified',
            name: 'Active Trusted SSL/TLS Certificate Verified',
            description: `Live TLS handshake succeeded (${domainVerification.tls.issuer || 'Trusted CA'}, expires in ${domainVerification.tls.daysRemaining ?? '?'} days). Note: TLS encrypts transit only and does not verify merchant legitimacy.`,
            isVerified: true,
            scoreDeduction: 5,
          });
        }
        analysis.evidenceWeight = Math.min(100, analysis.evidenceWeight + 15);
      } else if (domainVerification.tls.applicable) {
        analysis.unverifiedAspects = analysis.unverifiedAspects.map((u) =>
          u.toLowerCase().includes('tls certificate')
            ? `Live TLS certificate check unavailable (${domainVerification.tls.error || 'connection failed'})`
            : u
        );
      }

      // 4. Authoritative RDAP Domain Registration & Domain Age
      if (domainVerification.rdap.domainAgeDays !== undefined) {
        analysis.unverifiedAspects = analysis.unverifiedAspects.filter(
          (u) => !u.toLowerCase().includes('domain age')
        );
        const ageDays = domainVerification.rdap.domainAgeDays;
        const regDateStr = domainVerification.rdap.registrationDate
          ? new Date(domainVerification.rdap.registrationDate).toISOString().slice(0, 10)
          : 'unknown date';

        if (ageDays < 30) {
          analysis.indicators.push({
            id: 'rdap-newly-registered-domain',
            name: `Newly Registered Domain (${ageDays} Days Old)`,
            category: 'verification',
            severity: 'high',
            scoreImpact: 28,
            isObserved: true,
            description: `Authoritative RDAP records show "${domainVerification.rdap.apexDomain}" was registered on ${regDateStr} (${ageDays} days ago). Disposable scam storefronts frequently use newly created domains.`,
            remedyOrPrecaution: 'Verify independent business registration and physical contact details before ordering from brand-new domains.',
          });
        } else if (ageDays < 180) {
          analysis.indicators.push({
            id: 'rdap-young-domain',
            name: `Recently Registered Domain (${ageDays} Days Old)`,
            category: 'verification',
            severity: 'medium',
            scoreImpact: 14,
            isObserved: true,
            description: `RDAP registration date is ${regDateStr} (${ageDays} days old). Newer storefronts have limited operating history.`,
            remedyOrPrecaution: 'Confirm external buyer reviews and use a payment method with strong dispute protection.',
          });
        } else if (ageDays >= 365) {
          // Informational signal with zero deduction so age alone never masks phishing or threat-intel hits
          analysis.positiveSignals.push({
            id: 'rdap-established-domain',
            name: `Established Domain Registration (${Math.floor(ageDays / 365)}y+ · ${ageDays.toLocaleString()} Days)`,
            description: `Authoritative RDAP records show registration since ${regDateStr}. Note: Domain age alone never proves safety, as established domains can be compromised or abused.`,
            isVerified: true,
            scoreDeduction: 0,
          });
        }
        analysis.evidenceWeight = Math.min(100, analysis.evidenceWeight + 15);
      } else if (domainVerification.rdap.error) {
        analysis.unverifiedAspects = analysis.unverifiedAspects.map((u) =>
          u.toLowerCase().includes('domain age')
            ? `Domain age & RDAP lookup unavailable (${domainVerification.rdap.error})`
            : u
        );
      }

      // 5. Threat Intelligence Feed Verification
      if (domainVerification.threatIntel.listed) {
        const providerNames = domainVerification.threatIntel.matches
          .map((m) => m.provider)
          .join(', ');
        analysis.indicators.push({
          id: 'threat-intel-match',
          name: `Active Phishing / Threat Intelligence Hit (${providerNames})`,
          category: 'verification',
          severity: 'high',
          scoreImpact: 50,
          isObserved: true,
          description: domainVerification.threatIntel.matches
            .map((m) => `${m.provider}: ${m.reference || m.threatType}`)
            .join(' · '),
          remedyOrPrecaution: 'Do not visit, log in, or transact on this URL. It appears on an active phishing or malicious threat list.',
        });
        analysis.evidenceWeight = Math.min(100, analysis.evidenceWeight + 20);
      } else if (domainVerification.threatIntel.status === 'verified') {
        const checkedProviders = domainVerification.threatIntel.providers
          .filter((p) => p.checked)
          .map((p) => p.provider)
          .join(', ');
        analysis.positiveSignals.push({
          id: 'threat-intel-clean',
          name: 'Threat Intelligence Check: Not Listed',
          description: `Not listed in checked threat feeds (${checkedProviders}). Threat feeds do not catch newly launched phishing pages immediately.`,
          isVerified: true,
          scoreDeduction: 4,
        });
        analysis.evidenceWeight = Math.min(100, analysis.evidenceWeight + 10);
      }

      // Guardrail: HTTPS/TLS or old domain or clean ML URL profile must NEVER mask active severe threats
      const hasCriticalLiveRisk =
        domainVerification.threatIntel.listed ||
        domainVerification.tls.status === 'suspicious' ||
        domainVerification.redirects.suspiciousDestination ||
        domainVerification.redirects.downgradeHttpsToHttp ||
        domainVerification.dns.status === 'suspicious' ||
        (domainVerification.rdap.domainAgeDays !== undefined && domainVerification.rdap.domainAgeDays < 30) ||
        analysis.indicators.some((ind) => ind.severity === 'high');

      if (hasCriticalLiveRisk) {
        analysis.positiveSignals = analysis.positiveSignals
          .filter((s) => s.id !== 'ml_benign_classification')
          .map((s) => ({ ...s, scoreDeduction: 0 }));
      }
    }

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
      unverifiedAspects: Array.from(new Set(analysis.unverifiedAspects)),
      mlPhishingPrediction: mlPred,
      domainVerification,
      disclaimer: COMMON_DISCLAIMER,
    };
  }

  /**
   * Run Product Listing Risk Assessment
   * Combines rule-based listing metadata checks, Product ML model, and Website Phishing ML model (on listingUrl)
   * while preventing double-counting of overlapping URL risk signals.
   */
  public static assessProduct(
    input: ProductAnalysisInput,
    barcodeLookup?: BarcodeLookupResult,
    sellerVerification?: SellerVerificationResult,
    marketPriceComparison?: MarketPriceComparisonResult
  ): AssessmentResult {
    const validation = validateProductInput(input);
    const workingInput = validation.valid && validation.normalizedInput ? validation.normalizedInput : input;

    const analysis = analyzeProductListing(workingInput, barcodeLookup);
    const mlProductPred = predictProductRisk(workingInput);
    let mlPhishingPred = undefined;

    // 1. Listing URL analysis: connect trained Website Phishing Logistic Regression + structural rules
    if (workingInput.listingUrl && workingInput.listingUrl.trim().length > 0) {
      const urlCheck = validateWebsiteUrl(workingInput.listingUrl);
      const targetUrl = urlCheck.valid && urlCheck.normalizedUrl ? urlCheck.normalizedUrl : workingInput.listingUrl.trim();
      const urlAnalysis = analyzeUrlStructure(targetUrl);
      const hasInvalidUrl = urlAnalysis.indicators.some(
        (i) => i.id === 'invalid-url-format' || i.id === 'unsafe-protocol'
      );

      if (!hasInvalidUrl) {
        mlPhishingPred = predictPhishing(targetUrl);
      }

      if (mlPhishingPred && mlPhishingPred.isPhishing && mlPhishingPred.probability >= 0.60) {
        // Add unified Website Phishing ML indicator under 'url' category
        analysis.indicators.push({
          id: 'ml_listing_url_phishing',
          name: `Listing URL Phishing Risk (${Math.round(mlPhishingPred.probability * 100)}% Probability)`,
          category: 'url',
          severity: mlPhishingPred.probability >= 0.85 ? 'high' : 'medium',
          scoreImpact: Math.round(mlPhishingPred.probability * 24),
          isObserved: true,
          description: `Website Phishing Logistic Regression model classified the listing link itself as elevated phishing risk (${Math.round(mlPhishingPred.probability * 100)}% probability). This reflects URL deception risk, separate from physical product authenticity.`,
          remedyOrPrecaution: 'Do not enter payment credentials or login details on this URL; navigate independently to an official storefront.',
        });

        // Deduplicate: suppress overlapping lexical URL rule flags already scored by Phishing ML
        const overlappedIds = new Set([
          'insecure-http',
          'high-abuse-tld',
          'ip-address-host',
          'hyphen-stuffing',
          'excessive-subdomains',
        ]);
        for (const ind of urlAnalysis.indicators) {
          if (!overlappedIds.has(ind.id)) {
            analysis.indicators.push(ind);
          }
        }
      } else {
        analysis.indicators.push(...urlAnalysis.indicators);
      }

      // Only apply positive URL reassurance if URL itself had no anomalies and listing isn't already flagged high-risk
      if (urlAnalysis.indicators.length === 0 && (!mlPhishingPred || !mlPhishingPred.isPhishing)) {
        // Modest deduction capped at 10 pts so a legitimate marketplace URL never masks replica/scam copy
        const safeUrlSignalCount = urlAnalysis.positiveSignals.length;
        if (safeUrlSignalCount > 0 || (mlPhishingPred && mlPhishingPred.probability <= 0.30)) {
          const hasTrustedDomain = urlAnalysis.positiveSignals.some((s) => s.id === 'recognized-official-domain');
          analysis.positiveSignals.push({
            id: 'listing-url-phishing-clean',
            name: hasTrustedDomain
              ? 'Listing URL Check: Recognized Platform Domain (Low Phishing Risk)'
              : 'Listing URL Check: No Phishing Syntax Detected',
            description:
              'The supplied web link itself shows low URL phishing probability. Note: legitimate marketplaces can still host deceptive third-party seller listings.',
            isVerified: true,
            scoreDeduction: mlProductPred.isHighRisk ? 0 : hasTrustedDomain ? 10 : 5,
          });
        }
      }

      analysis.evidenceWeight = Math.min(analysis.evidenceWeight + 15, 100);
      analysis.unverifiedAspects.push(...urlAnalysis.unverifiedAspects);
    }

    // 2. Integrate trained Product Listing ML prediction (prevent double-counting overlapping risky URL feature)
    if (mlProductPred.isHighRisk && mlProductPred.probability >= 0.65 && analysis.evidenceWeight >= 30) {
      let mlProductImpact = Math.round(mlProductPred.probability * 22);
      const urlAlreadyCountedInPhishing =
        Boolean(mlPhishingPred && mlPhishingPred.isPhishing && mlPhishingPred.probability >= 0.60) &&
        Boolean(mlProductPred.featuresExtracted?.hasRiskyListingUrl);

      if (urlAlreadyCountedInPhishing) {
        // Reduce overlap since Listing URL phishing risk is already scored under 'url'
        mlProductImpact = Math.max(8, mlProductImpact - 6);
      }

      analysis.indicators.push({
        id: 'ml_product_high_risk',
        name: `Suspicious Listing ML Alert (${Math.round(mlProductPred.probability * 100)}% Risk Probability)`,
        category: 'verification',
        severity: mlProductPred.probability >= 0.85 ? 'high' : 'medium',
        scoreImpact: mlProductImpact,
        isObserved: true,
        description: `Product Listing Logistic Regression (synthetic training corpus) flagged combined pricing, seller, and description markers (${Math.round(mlProductPred.probability * 100)}% risk probability). This measures suspicious listing metadata—not verified physical counterfeiting.`,
        remedyOrPrecaution: 'Verify seller authorization, demand buyer-protected checkout, and cross-check manufacturer serials.',
      });
      analysis.evidenceWeight = Math.min(100, analysis.evidenceWeight + 15);
    } else if (!mlProductPred.isHighRisk && mlProductPred.probability <= 0.30 && analysis.evidenceWeight >= 35) {
      analysis.positiveSignals.push({
        id: 'ml_product_benign_classification',
        name: `Suspicious Listing ML Check: Lower-Risk Pattern (${Math.round((1 - mlProductPred.probability) * 100)}% Confidence)`,
        description: 'Product listing classifier evaluated price context, seller signals, and return terms as lower-risk metadata patterns (not proof of physical authenticity).',
        isVerified: true,
        scoreDeduction: 12,
      });
      analysis.evidenceWeight = Math.min(100, analysis.evidenceWeight + 10);
    }

    // 3. Integrate Real Seller Verification without double-counting user-submitted seller indicators
    if (sellerVerification) {
      const { retrieved, comparison } = sellerVerification;

      if (comparison.sellerNameMatch === 'mismatch') {
        analysis.indicators.push({
          id: 'seller-name-mismatch',
          name: 'Seller Name Mismatch Warning',
          category: 'seller',
          severity: 'high',
          scoreImpact: 25,
          isObserved: true,
          description: `Entered seller ("${sellerVerification.userProvided.sellerName}") does not match externally retrieved merchant identity ("${retrieved.sellerName}").`,
          remedyOrPrecaution: 'Verify the exact merchant name on checkout and order confirmation before paying.',
        });
        analysis.evidenceWeight = Math.min(100, analysis.evidenceWeight + 12);
      } else if (comparison.sellerNameMatch === 'match' && retrieved.sellerName) {
        analysis.positiveSignals.push({
          id: 'seller-identity-corroborated',
          name: `External Seller Identity Match (${retrieved.sellerName})`,
          description: `Entered seller name aligns with public listing metadata from ${sellerVerification.marketplace || 'the merchant page'}.`,
          isVerified: true,
          scoreDeduction: 4,
        });
        analysis.evidenceWeight = Math.min(100, analysis.evidenceWeight + 10);
      }

      if (retrieved.sellerRating !== undefined) {
        analysis.unverifiedAspects = analysis.unverifiedAspects.filter(
          (u) => !u.toLowerCase().includes('seller rating authenticity')
        );

        if (retrieved.sellerRating < 3.0) {
          // Deduplicate against self-reported low-seller-rating
          analysis.indicators = analysis.indicators.filter((i) => i.id !== 'low-seller-rating');
          analysis.indicators.push({
            id: 'verified-low-seller-rating',
            name: `Low External Seller Rating (${retrieved.sellerRating}/5)`,
            category: 'seller',
            severity: 'high',
            scoreImpact: 24,
            isObserved: true,
            description: `External merchant metadata reports a seller rating of ${retrieved.sellerRating}/5${
              retrieved.sellerRatingCount ? ` (${retrieved.sellerRatingCount.toLocaleString()} ratings)` : ''
            }.`,
            remedyOrPrecaution: 'Inspect recent negative seller reviews for non-delivery or refund disputes.',
          });
        } else if (
          retrieved.sellerRating >= 4.5 &&
          (retrieved.sellerRatingCount === undefined || retrieved.sellerRatingCount >= 20) &&
          comparison.sellerNameMatch !== 'mismatch'
        ) {
          // Replace self-reported rating deduction with external verified rating signal
          analysis.positiveSignals = analysis.positiveSignals.filter(
            (s) => s.id !== 'high-reported-rating'
          );
          analysis.positiveSignals.push({
            id: 'verified-seller-rating',
            name: `Verified Seller Rating (${retrieved.sellerRating}/5)`,
            description: `External listing metadata reports ${retrieved.sellerRating}/5 seller feedback${
              retrieved.sellerRatingCount ? ` across ${retrieved.sellerRatingCount.toLocaleString()} ratings` : ''
            }.`,
            isVerified: true,
            scoreDeduction: 7,
          });
        }
        analysis.evidenceWeight = Math.min(100, analysis.evidenceWeight + 10);
      }

      if (comparison.ratingDiscrepancy !== undefined && comparison.ratingDiscrepancy >= 0.8) {
        analysis.positiveSignals = analysis.positiveSignals.filter(
          (s) => s.id !== 'high-reported-rating'
        );
        analysis.indicators.push({
          id: 'seller-rating-discrepancy',
          name: 'Seller Rating Discrepancy',
          category: 'seller',
          severity: 'medium',
          scoreImpact: 18,
          isObserved: true,
          description: `User-reported seller rating (${sellerVerification.userProvided.sellerRating}/5) differs by ${comparison.ratingDiscrepancy} stars from externally retrieved rating (${retrieved.sellerRating}/5).`,
          remedyOrPrecaution: 'Rely on independently verified marketplace seller profiles rather than copied numbers.',
        });
      }

      if (comparison.returnPolicyMismatch) {
        analysis.positiveSignals = analysis.positiveSignals.filter(
          (s) => s.id !== 'returns-accepted'
        );
        analysis.indicators.push({
          id: 'seller-return-policy-mismatch',
          name: 'Return Policy Conflict With External Metadata',
          category: 'seller',
          severity: 'medium',
          scoreImpact: 20,
          isObserved: true,
          description: 'External MerchantReturnPolicy metadata states no returns / final sale, conflicting with the selected Available return status.',
          remedyOrPrecaution: 'Confirm written return eligibility inside checkout terms before ordering.',
        });
      }

      if (
        comparison.suspiciousHandleFlags.length > 0 &&
        !analysis.indicators.some((i) => i.id === 'generic-seller-handle')
      ) {
        analysis.indicators.push({
          id: 'verified-suspicious-seller-handle',
          name: 'Suspicious Seller Handle Pattern',
          category: 'seller',
          severity: 'low',
          scoreImpact: 12,
          isObserved: true,
          description: comparison.suspiciousHandleFlags.join('; '),
          remedyOrPrecaution: 'Verify whether the seller publishes a registered legal entity and physical return address.',
        });
      }

      if (
        retrieved.authorizedSellerStatus === 'confirmed_official' &&
        comparison.sellerNameMatch !== 'mismatch' &&
        !comparison.returnPolicyMismatch
      ) {
        analysis.positiveSignals.push({
          id: 'seller-official-merchant-confirmed',
          name: 'Official Storefront / Brand Source Confirmed',
          description: retrieved.authorizedSellerDetail || 'Listing resides on a verified official storefront domain.',
          isVerified: true,
          scoreDeduction: 8,
        });
        analysis.evidenceWeight = Math.min(100, analysis.evidenceWeight + 10);
      } else if (
        sellerVerification.status === 'restricted' ||
        sellerVerification.status === 'unavailable' ||
        sellerVerification.status === 'unverified'
      ) {
        // Never penalize as fraudulent simply because marketplace access is restricted or seller details are unavailable
        analysis.unverifiedAspects.push(
          `External seller verification (${sellerVerification.status}): ${sellerVerification.message}`
        );
      }

      if (comparison.sellerNameMatch === 'mismatch' || comparison.returnPolicyMismatch) {
        analysis.positiveSignals = analysis.positiveSignals
          .filter((s) => s.id !== 'high-reported-rating')
          .map((s) =>
            s.id === 'ml_product_benign_classification' || s.id === 'listing-url-phishing-clean'
              ? { ...s, scoreDeduction: 0 }
              : s
          );
      }
    }

    // 4. Integrate Real-World Market Price Comparison without double-counting manual pricing rules
    if (marketPriceComparison) {
      const mStats = marketPriceComparison.stats;
      const cond = marketPriceComparison.inferredCondition;
      const hasLegitDiscountContext =
        (cond === 'refurbished' || cond === 'used' || cond === 'clearance') &&
        workingInput.returnPolicyStatus !== 'not_available' &&
        workingInput.hasReturnPolicy !== false;

      if (mStats && mStats.externalQuoteCount > 0) {
        analysis.unverifiedAspects = analysis.unverifiedAspects.filter(
          (u) => !u.toLowerCase().includes('official manufacturer suggested retail price')
        );
        analysis.evidenceWeight = Math.min(100, analysis.evidenceWeight + 15);
      }

      if (mStats && mStats.percentageDifference !== undefined && (mStats.externalQuoteCount > 0 || hasLegitDiscountContext)) {
        // Deduplicate raw productAnalyzer discount rules so equivalent price variance is never double-counted
        analysis.indicators = analysis.indicators.filter(
          (i) => i.id !== 'steep-discount-investigation' && i.id !== 'moderate-discount-caution'
        );
        analysis.positiveSignals = analysis.positiveSignals.filter(
          (s) => s.id !== 'market-aligned-pricing'
        );

        const pctOff = mStats.percentageDifference;
        const curr = mStats.currency;
        const isExternal = mStats.externalQuoteCount > 0;
        const refPhrase = isExternal
          ? `${mStats.selectedReferenceLabel} (${curr} ${mStats.selectedReferencePrice})`
          : `user reference (${curr} ${mStats.selectedReferencePrice})`;

        if (pctOff >= 85) {
          if (hasLegitDiscountContext) {
            analysis.indicators.push({
              id: 'market-price-clearance-refurb-discount',
              name: `Steep Discount With ${cond.charAt(0).toUpperCase() + cond.slice(1)} Context (${Math.round(pctOff)}% below ${isExternal ? 'market' : 'reference'})`,
              category: 'pricing',
              severity: 'low',
              scoreImpact: 8,
              isObserved: isExternal,
              description: `Listed at ${curr} ${mStats.listedPrice} vs. ${refPhrase}. Because the listing specifies ${cond} condition with buyer return options, steep markdowns can occur legitimately; low price alone never proves counterfeiting.`,
              remedyOrPrecaution: 'Verify the seller’s warranty coverage, refurbishment grade, and return eligibility window.',
            });
          } else {
            analysis.indicators.push({
              id: 'market-price-extreme-discount',
              name: `Unusually Low Price vs. Market (${Math.round(pctOff)}% below ${isExternal ? 'market' : 'reference'})`,
              category: 'pricing',
              severity: 'medium',
              scoreImpact: 22,
              isObserved: isExternal,
              description: `Listed at ${curr} ${mStats.listedPrice} compared to ${refPhrase}. An unusually low price is a risk indicator warranting seller verification, never standalone proof of a counterfeit item.`,
              remedyOrPrecaution: 'Confirm whether the product is used, refurbished, regional grey-market, or missing accessories before purchasing.',
            });
          }
        } else if (pctOff >= 60) {
          if (hasLegitDiscountContext) {
            analysis.indicators.push({
              id: 'market-price-clearance-refurb-caution',
              name: `Promotional / ${cond.charAt(0).toUpperCase() + cond.slice(1)} Discount (${Math.round(pctOff)}% off)`,
              category: 'pricing',
              severity: 'info',
              scoreImpact: 4,
              isObserved: isExternal,
              description: `Listed at ${curr} ${mStats.listedPrice} vs. ${refPhrase}. Discount aligns with ${cond} or liquidation pricing; verify seller return guarantees.`,
              remedyOrPrecaution: 'Check condition grading and return terms.',
            });
          } else {
            analysis.indicators.push({
              id: 'market-price-significant-discount',
              name: `Significant Market Price Reduction (${Math.round(pctOff)}% below ${isExternal ? 'market' : 'reference'})`,
              category: 'pricing',
              severity: 'low',
              scoreImpact: 12,
              isObserved: isExternal,
              description: `Listed at ${curr} ${mStats.listedPrice} vs. ${refPhrase}. Promotional discounts occur legitimately, though deep markdowns warrant checking seller authorization.`,
              remedyOrPrecaution: 'Verify whether this promotion is from an authorized retailer.',
            });
          }
        } else if (pctOff <= 25 && pctOff >= -20) {
          analysis.positiveSignals.push({
            id: isExternal ? 'verified-market-aligned-pricing' : 'market-aligned-pricing',
            name: isExternal
              ? `Market-Aligned Price Verified (${mStats.externalQuoteCount} Source${mStats.externalQuoteCount === 1 ? '' : 's'})`
              : 'Market-Consistent Price Range',
            description: `Listed price (${curr} ${mStats.listedPrice}) aligns with ${refPhrase}.`,
            isVerified: isExternal,
            scoreDeduction: isExternal ? 12 : 10,
          });
        }
      } else if (marketPriceComparison.status === 'currency_mismatch') {
        analysis.unverifiedAspects.push(
          `Market price comparison skipped due to currency mismatch: ${marketPriceComparison.message}`
        );
      } else if (marketPriceComparison.status === 'unavailable') {
        analysis.unverifiedAspects.push(
          `External market price comparison unavailable: ${marketPriceComparison.message}`
        );
      }
    }

    analysis.unverifiedAspects.push(
      'Physical item in-hand authenticity & serial ownership (separate from website phishing risk and listing metadata risk)'
    );

    const score = this.calculateFinalScore(analysis.indicators, analysis.positiveSignals);
    const confidence = this.calculateConfidence(analysis.evidenceWeight);
    const category = getRiskCategory(score);

    const recommendations = this.generateRecommendations('product', analysis.indicators, score);

    return {
      id: `scan-prod-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      timestamp: new Date().toISOString(),
      type: 'product',
      inputSummary: {
        target: workingInput.productName,
        brand: workingInput.brand,
        price: workingInput.listedPrice,
        referencePrice: workingInput.referencePrice,
        currency: workingInput.currency || workingInput.referenceCurrency,
        sellerName: workingInput.sellerName,
        platform: workingInput.sourcePlatform,
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
      mlPhishingPrediction: mlPhishingPred,
      mlProductPrediction: mlProductPred,
      barcodeLookup,
      sellerVerification,
      marketPriceComparison,
      disclaimer:
        'VerifyBeforeBuy AI separates URL phishing risk, suspicious listing metadata risk, market price variance, barcode catalog alignment, seller verification, and physical product authenticity. Neither website phishing detection, synthetic-trained listing classification, low/high prices, nor barcode/seller metadata can prove genuine manufacturing.',
    };
  }

  /**
   * Run Barcode & QR Code Assessment
   * Connects Website Phishing Logistic Regression exclusively for valid HTTP/HTTPS QR URLs,
   * combining ML and URL rule analysis without double-counting overlapping lexical features.
   */
  public static assessCode(
    input: CodeAnalysisInput,
    barcodeLookup?: BarcodeLookupResult
  ): AssessmentResult {
    const analysis = analyzeCodePayload(input, barcodeLookup);
    let mlPhishingPred = undefined;

    if (analysis.payloadType === 'url' && analysis.normalizedUrl) {
      const hasInvalidSyntax = analysis.indicators.some(
        (i) => i.id === 'invalid-url-format' || i.id === 'unsafe-protocol'
      );

      if (!hasInvalidSyntax) {
        mlPhishingPred = predictPhishing(analysis.normalizedUrl);

        if (mlPhishingPred.isPhishing && mlPhishingPred.probability >= 0.60) {
          // Suppress overlapping lexical URL flags already weighed by Phishing ML
          const overlappedIds = new Set([
            'insecure-http',
            'high-abuse-tld',
            'ip-address-host',
            'hyphen-stuffing',
            'excessive-subdomains',
          ]);
          analysis.indicators = analysis.indicators.filter((ind) => !overlappedIds.has(ind.id));

          analysis.indicators.push({
            id: 'ml_phishing_high_risk',
            name: `ML Model QR URL Phishing Alert (${Math.round(mlPhishingPred.probability * 100)}% Probability)`,
            category: 'technical',
            severity: mlPhishingPred.probability >= 0.85 ? 'high' : 'medium',
            scoreImpact: Math.round(mlPhishingPred.probability * 25),
            isObserved: true,
            description: `Supervised classification model trained on 80,000 real-world malicious and legitimate URLs classified this QR code destination URL as malicious with ${Math.round(mlPhishingPred.probability * 100)}% probability.`,
            remedyOrPrecaution: 'Do not open this QR destination URL or enter passwords, credit cards, or personal credentials.',
          });
          analysis.evidenceWeight = Math.min(100, analysis.evidenceWeight + 20);
        } else if (!mlPhishingPred.isPhishing && mlPhishingPred.probability <= 0.30) {
          analysis.positiveSignals.push({
            id: 'ml_benign_classification',
            name: `ML Model Clean QR URL Profile (${Math.round((1 - mlPhishingPred.probability) * 100)}% Benign Confidence)`,
            description: 'Trained website phishing classifier found no anomalous lexical or deception markers in the scanned QR destination URL.',
            isVerified: true,
            scoreDeduction: 12,
          });
          analysis.evidenceWeight = Math.min(100, analysis.evidenceWeight + 15);
        }
      }
    }

    const score = this.calculateFinalScore(analysis.indicators, analysis.positiveSignals);
    const confidence = this.calculateConfidence(analysis.evidenceWeight);
    const category = getRiskCategory(score);

    const recommendations = this.generateRecommendations('code', analysis.indicators, score);

    return {
      id: `scan-code-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      timestamp: new Date().toISOString(),
      type: 'code',
      inputSummary: {
        target: analysis.normalizedUrl || input.code.trim(),
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
      unverifiedAspects: Array.from(new Set(analysis.unverifiedAspects)),
      mlPhishingPrediction: mlPhishingPred,
      barcodeLookup,
      disclaimer:
        analysis.payloadType === 'gtin-barcode'
          ? 'A valid GS1 Modulo-10 barcode check digit or product database match never proves a physical product is genuine. Counterfeiters routinely print copied barcodes onto replica packaging.'
          : COMMON_DISCLAIMER,
      isDemoMode: Boolean(analysis.matchedDemoItem) || barcodeLookup?.sourceType === 'synthetic_demo',
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
      verification: 55,
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
