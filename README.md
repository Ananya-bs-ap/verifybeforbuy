# VerifyBeforeBuy AI 🛡️
> **“Check the Risk. Shop with Confidence.”**

VerifyBeforeBuy AI is an AI-assisted online shopping risk assessment and consumer safety platform. It evaluates available indicators about shopping websites, seller listings, and product packaging to calculate an explainable 0–100 risk score, explain contributing factors, and recommend practical safety precautions before purchasing.

---

## 🚀 Key Features

1. **Website Risk Checker**
   - Syntax validation, brand typosquatting detection (lookalikes, character substitution, leetspeak).
   - High-abuse TLD flagging (`.top`, `.xyz`, `.click`, `.buzz`, etc.).
   - Deep subdomain nesting & hyphen stuffing detection.
   - Raw IP address hostname & non-standard port screening.
   - Server-side SSRF protections blocking private subnets, loopbacks, and cloud metadata endpoints.

2. **Product Listing & Seller Assessor**
   - **Anti-Bias Pricing Engine:** Crucial rule strictly enforced — steep discounts (e.g. 80%+ clearance sales) are treated as reasons for checking, **not** proof of counterfeit.
   - Incomplete data is treated as lower evidence coverage, **never** penalized as fraud.
   - Replica & counterfeit terminology scanner (`1:1 replica`, `mirror copy`, `oem clone`).
   - Seller dispute safeguards & high-risk payment pressure flags (wire transfer, crypto, gift cards).

3. **QR & Retail Barcode Scanner**
   - Camera-based scanning via `html5-qrcode` with browser permission handling.
   - Image file drag-and-drop / upload barcode decoder.
   - Manual UPC-A / EAN-13 / GTIN number entry fallback.
   - GS1 Modulo-10 checksum algorithm verification.
   - Synthetic demonstration catalog matching with explicit disclosures.
   - **Explicit Authenticity Notice:** Clear guidance that scanning a barcode alone does not prove authenticity, as counterfeit packaging routinely copies legitimate codes.

4. **Calibrated 0–100 Risk Engine & Confidence Meter**
   - **0–25 (Lower Risk):** Nominal indicators, recognized brand domains, valid checksums.
   - **26–50 (Moderate Risk):** Minor caution flags or unverified seller handles.
   - **51–75 (Elevated Risk):** Multiple warning indicators or absence of return rights.
   - **76–100 (High Risk):** Critical deception patterns (typosquatting, wire-only traps, replica keywords).
   - Category caps prevent double-counting of related underlying concerns.
   - Evidence coverage metric (Minimal, Moderate, High, Comprehensive).

5. **AI Plain-Language Risk Explanations**
   - Server-side integration with **Gemini 3.8 Flash** via `@google/genai`.
   - Never exposes API keys to client JavaScript.
   - Structured system prompts ensure the AI explains findings without hallucinating fake database checks.
   - Standard deterministic fallback ensures rich explanations even when no external AI key is present.

6. **Dual-Mode Persistence (Local + Supabase PostgreSQL)**
   - Operates out-of-the-box using private browser `localStorage`.
   - Supports seamless sync with Supabase PostgreSQL (`profiles`, `scan_reports`, `scan_findings`) with Row Level Security (RLS) policies.
   - Search, filter by risk category, and export to CSV / JSON.

---

## 📁 Project Structure

```
├── .env.example                     # Documented configuration variables
├── index.html                       # HTML5 entry with synced metadata
├── metadata.json                    # AI Studio metadata & permissions
├── package.json                     # Scripts & dependencies
├── server.ts                        # Full-stack Express server & Gemini AI API
├── src/
│   ├── App.tsx                      # Root application & tab router
│   ├── main.tsx                     # React 19 bootstrap
│   ├── index.css                    # Tailwind CSS v4 entry
│   ├── types/
│   │   └── index.ts                 # Core TypeScript data contracts
│   ├── components/
│   │   ├── Navbar.tsx               # Top Bar Contract navigation (3-zone)
│   │   ├── HeroVisual.tsx           # Original vector/CSS security illustration
│   │   └── VerificationReport.tsx   # Reusable diagnostic report card
│   ├── pages/
│   │   ├── HomePage.tsx             # Hero, 3-step workflow, features, preview, edu
│   │   ├── WebsiteCheckerPage.tsx   # Storefront URL analysis & presets
│   │   ├── ProductCheckerPage.tsx   # Multi-attribute listing & seller checker
│   │   ├── BarcodeScannerPage.tsx   # Camera, file upload, & manual code scanner
│   │   ├── HistoryDashboardPage.tsx # Audit log, search, export, & Supabase guide
│   │   ├── HowItWorksPage.tsx       # Scoring math, anti-bias rules, ML roadmap
│   │   └── AboutPage.tsx            # Mission, shopping checklist, & limitations
│   ├── lib/
│   │   ├── api.ts                   # Frontend API client with fallback
│   │   ├── riskEngine/
│   │   │   ├── rules.ts             # Thresholds, caps, and disclaimers
│   │   │   ├── urlAnalyzer.ts       # Syntactic URL & brand typosquatting
│   │   │   ├── productAnalyzer.ts   # Pricing, seller, and description checks
│   │   │   ├── codeAnalyzer.ts      # Barcode GS1 modulo-10 & demo catalog
│   │   │   └── engine.ts            # Scoring orchestrator & recommendations
│   │   └── supabase/
│   │       ├── client.ts            # Client initializer & status detector
│   │       ├── historyService.ts    # Dual persistence (Supabase + localStorage)
│   │       └── schema.sql           # Complete PostgreSQL RLS migration script
│   └── test/
│       └── runTests.ts              # Unit test suite for risk rules
```

---

## 🛠️ Installation & Local Setup

### 1. Clone the repository
```bash
git clone https://github.com/your-username/verify-before-buy-ai.git
cd verify-before-buy-ai
```

### 2. Install dependencies
```bash
npm install
```

### 3. Configure environment variables
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Fill in the optional variables:
```env
# Optional Gemini AI API Key for server-side explanations
GEMINI_API_KEY="your-gemini-api-key"

# Optional Supabase credentials for cloud audit storage
VITE_SUPABASE_URL="https://your-project.supabase.co"
VITE_SUPABASE_ANON_KEY="your-anon-key"

# Server Port (default 3000)
PORT=3000
```

### 4. Run Unit Tests
```bash
npm test
```

### 5. Start Development Server
```bash
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 🗄️ Supabase PostgreSQL Setup

1. Create a project at [supabase.com](https://supabase.com).
2. Open the **SQL Editor** in your Supabase dashboard.
3. Paste the contents of `src/lib/supabase/schema.sql` and click **Run**.
4. Retrieve your **Project URL** and **anon public key** from **Settings > API**.
5. Set `VITE_SUPABASE_URL` and `VITE_SUPABASE_ANON_KEY` in your environment.

---

## ☁️ Deployment Instructions

### Deploy to Vercel
1. Push your repository to GitHub.
2. In the Vercel dashboard, click **Add New Project** and select the repository.
3. Configure build settings:
   - **Framework Preset:** Vite
   - **Build Command:** `npm run build`
   - **Output Directory:** `dist`
4. Under **Environment Variables**, add:
   - `GEMINI_API_KEY` (Optional)
   - `VITE_SUPABASE_URL` (Optional)
   - `VITE_SUPABASE_ANON_KEY` (Optional)
5. Click **Deploy**.

---

## 🤖 Future Machine-Learning Roadmap (Python/FastAPI)

The current version employs a transparent, explainable rule-based scoring engine. For production machine learning:

1. **Curated Datasets:**
   - Website Phishing: Tranco Top 1M benign URLs + PhishTank / OpenPhish malicious feeds.
   - Product Risk: Marketplace counterfeit dispute datasets (separate from phishing).
2. **Feature Extraction:**
   - Lexical entropy, character frequencies, Levenshtein distance against trademark registries.
3. **Training & Validation:**
   - Scikit-learn Random Forest / XGBoost with 80/20 stratified split, optimizing for $\ge 98\%$ precision to prevent false accusations.
4. **Microservice Deployment:**
   - Deploy as a Dockerized FastAPI service on Google Cloud Run or AWS ECS.
   - Configure `ML_SERVICE_URL` in Express `server.ts` to query predictions.

---

## ⚖️ Legal & Technical Disclaimer

*VerifyBeforeBuy AI provides a preliminary risk assessment based on available information. It does not warrant or guarantee that an inspected website, seller, or product is safe, fraudulent, authentic, or counterfeit. Consumers should always exercise independent caution and utilize payment methods with guaranteed dispute protections.*
