/**
 * VerifyBeforeBuy AI — Full-Stack Server
 * Express backend with SSRF protections, risk analysis endpoints,
 * server-side Gemini AI explanations via @google/genai, and Vite middleware integration.
 */

import express, { Request, Response } from 'express';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import { GoogleGenAI } from '@google/genai';
import { RiskScoringEngine } from './src/lib/riskEngine/engine.ts';
import { AssessmentResult, WebsiteAnalysisInput, ProductAnalysisInput, CodeAnalysisInput } from './src/types/index.ts';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const isProd = process.env.NODE_ENV === 'production';
const PORT = parseInt(process.env.PORT || '3000', 10);

// Initialize Gemini client strictly on server-side if key is available
const geminiApiKey = process.env.GEMINI_API_KEY;
let ai: GoogleGenAI | null = null;

if (geminiApiKey && !geminiApiKey.includes('MY_GEMINI_API_KEY')) {
  try {
    ai = new GoogleGenAI({
      apiKey: geminiApiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  } catch (err) {
    console.warn('Failed to initialize Gemini AI client:', err);
  }
}

const app = express();
app.use(express.json({ limit: '2mb' }));

/**
 * SSRF and IP blocking helper
 * Prohibits access to loopback, private RFC1918 ranges, and cloud metadata services.
 */
function isRestrictedHost(hostname: string): boolean {
  const host = hostname.toLowerCase();
  if (
    host === 'localhost' ||
    host === '127.0.0.1' ||
    host === '::1' ||
    host === '169.254.169.254' || // Cloud metadata IP
    host.endsWith('.internal') ||
    host.endsWith('.local')
  ) {
    return true;
  }

  // IPv4 private ranges (10.x, 172.16-31.x, 192.168.x)
  const ipv4Match = host.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (ipv4Match) {
    const oct1 = parseInt(ipv4Match[1], 10);
    const oct2 = parseInt(ipv4Match[2], 10);
    if (oct1 === 10) return true;
    if (oct1 === 127) return true;
    if (oct1 === 172 && oct2 >= 16 && oct2 <= 31) return true;
    if (oct1 === 192 && oct2 === 168) return true;
    if (oct1 === 169 && oct2 === 254) return true;
  }

  return false;
}

// 1. Health & Status
app.get('/api/health', (_req: Request, res: Response) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    geminiConfigured: Boolean(ai),
    serverMode: isProd ? 'production' : 'development',
  });
});

// 2. Website Analysis Endpoint
app.post('/api/analyze/website', (req: Request, res: Response) => {
  try {
    const input: WebsiteAnalysisInput = req.body;
    if (!input || !input.url || typeof input.url !== 'string') {
      res.status(400).json({ error: 'Valid URL is required.' });
      return;
    }

    let parsed: URL;
    try {
      const sanitized = input.url.trim().startsWith('http') ? input.url.trim() : 'https://' + input.url.trim();
      parsed = new URL(sanitized);
    } catch {
      res.status(400).json({ error: 'Invalid URL format.' });
      return;
    }

    if (isRestrictedHost(parsed.hostname)) {
      res.status(403).json({
        error: 'Security restriction: Private, loopback, or metadata endpoints are blocked.',
      });
      return;
    }

    const result = RiskScoringEngine.assessWebsite(input);
    res.json(result);
  } catch (error: any) {
    console.error('Website analysis error:', error);
    res.status(500).json({ error: error.message || 'Analysis failed.' });
  }
});

// 3. Product Analysis Endpoint
app.post('/api/analyze/product', (req: Request, res: Response) => {
  try {
    const input: ProductAnalysisInput = req.body;
    if (!input || !input.productName || typeof input.productName !== 'string') {
      res.status(400).json({ error: 'Product name is required.' });
      return;
    }

    if (input.listingUrl) {
      try {
        const parsed = new URL(input.listingUrl.trim().startsWith('http') ? input.listingUrl : 'https://' + input.listingUrl);
        if (isRestrictedHost(parsed.hostname)) {
          res.status(403).json({ error: 'Security restriction: Private listing URL blocked.' });
          return;
        }
      } catch {
        // Allow evaluation with note
      }
    }

    const result = RiskScoringEngine.assessProduct(input);
    res.json(result);
  } catch (error: any) {
    console.error('Product analysis error:', error);
    res.status(500).json({ error: error.message || 'Product analysis failed.' });
  }
});

// 4. Code & Barcode Analysis Endpoint
app.post('/api/analyze/code', (req: Request, res: Response) => {
  try {
    const input: CodeAnalysisInput = req.body;
    if (!input || !input.code || typeof input.code !== 'string') {
      res.status(400).json({ error: 'Barcode or QR code data is required.' });
      return;
    }

    const result = RiskScoringEngine.assessCode(input);
    res.json(result);
  } catch (error: any) {
    console.error('Code analysis error:', error);
    res.status(500).json({ error: error.message || 'Code analysis failed.' });
  }
});

// 5. AI Risk Explanation Endpoint
app.post('/api/explain', async (req: Request, res: Response) => {
  try {
    const result: AssessmentResult = req.body;
    if (!result || typeof result.score !== 'number') {
      res.status(400).json({ error: 'Valid assessment result object is required.' });
      return;
    }

    // If Gemini client is available, generate contextual explanation
    if (ai) {
      try {
        const prompt = `
You are the VerifyBeforeBuy AI consumer protection analyst. Explain the following structured shopping risk findings in plain, objective, reassuring, and practical terms:

Assessment Type: ${result.type}
Target: ${result.inputSummary.target}
Assessed Risk Score: ${result.score}/100 (${result.category.toUpperCase()} RISK)
Evidence Coverage: ${result.confidence} (${result.confidenceScore}%)

Detected Warning Indicators:
${result.indicators.map(i => `- [${i.severity.toUpperCase()}] ${i.name}: ${i.description}`).join('\n') || 'None'}

Positive Signals:
${result.positiveSignals.map(s => `- ${s.name}: ${s.description}`).join('\n') || 'None'}

Unverified Aspects:
${result.unverifiedAspects.map(u => `- ${u}`).join('\n')}

Guidelines:
1. Explain what the findings mean in plain language (2 concise paragraphs).
2. Clearly distinguish observed technical evidence from unverified claims.
3. Crucial rule: Never declare that a product is 100% genuine or fake solely based on price, URL, or images. Explain that risk assessment is a caution index.
4. Conclude with 2-3 specific precautions the buyer should take.
`;

        const response = await ai.models.generateContent({
          model: 'gemini-3.8-flash',
          contents: prompt,
          config: {
            systemInstruction:
              'You are a cybersecurity and consumer rights analyst providing calibrated risk summaries. Avoid sensationalism. Never claim authenticity proof. Be helpful and clear.',
          },
        });

        const text = response.text || '';
        res.json({
          explanation: text,
          provider: 'gemini',
        });
        return;
      } catch (geminiError: any) {
        console.warn('Gemini explanation call failed, falling back to deterministic explanation:', geminiError.message);
      }
    }

    // Deterministic Fallback Explanation (Standardized, clear, and domain-grounded)
    const fallbackText = generateDeterministicExplanation(result);
    res.json({
      explanation: fallbackText,
      provider: 'deterministic-fallback',
    });
  } catch (error: any) {
    console.error('Explanation endpoint error:', error);
    res.status(500).json({ error: error.message || 'Failed to generate explanation.' });
  }
});

function generateDeterministicExplanation(result: AssessmentResult): string {
  const parts: string[] = [];

  if (result.category === 'lower') {
    parts.push(
      `Based on the available information for "${result.inputSummary.target}", our analysis did not identify significant deceptive indicators. The overall risk score of ${result.score}/100 places this in the lower assessed risk tier. Positive attributes such as valid standard formatting and absence of common phishing anomalies were noted.`
    );
  } else if (result.category === 'moderate') {
    parts.push(
      `Our analysis calculated a moderate risk score of ${result.score}/100 for "${result.inputSummary.target}". While there is no immediate proof of malicious intent, specific factors such as pricing variance, seller history gaps, or domain features warrant extra diligence before you proceed.`
    );
  } else if (result.category === 'elevated') {
    parts.push(
      `The evaluated listing for "${result.inputSummary.target}" returned an elevated risk score of ${result.score}/100. We identified multiple warning signals (such as unverified brand claims, suspicious web syntax, or lack of standard buyer protections). Extreme caution is recommended.`
    );
  } else {
    parts.push(
      `CRITICAL NOTICE: High-risk indicators were detected for "${result.inputSummary.target}" (Risk Score: ${result.score}/100). The patterns observed closely resemble known deception mechanisms, such as brand lookalike domains, deceptive payment methods, or direct replica disclosures.`
    );
  }

  parts.push(
    `Important context: Risk scoring evaluates probability patterns and public markers, but it is not physical proof of authenticity or guaranteed fraud. Notably, ${result.unverifiedAspects.slice(0, 2).join(' and ')} remain unverified.`
  );

  parts.push(
    `Recommended Next Steps:\n1. Use payment methods with guaranteed dispute rights (e.g. major credit cards with zero fraud liability).\n2. Independently verify the merchant contact address and phone support.\n3. Request official manufacturer serial numbers or authorized retailer proof if buying high-value goods.`
  );

  return parts.join('\n\n');
}

// Dev vs Prod Vite Integration
async function startServer() {
  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, 'dist')));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🛡️  VerifyBeforeBuy AI Server active at http://0.0.0.0:${PORT} [mode: ${isProd ? 'prod' : 'dev'}]`);
  });
}

startServer().catch((err) => {
  console.error('Server startup error:', err);
  process.exit(1);
});
