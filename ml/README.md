# VerifyBeforeBuy AI — Machine Learning Phishing Detection Subsystem

This folder contains the complete, separate Python machine learning training workflow, feature extractor, and FastAPI inference microservice for **VerifyBeforeBuy AI**.

---

## ⚠️ Important Boundary & Authenticity Disclaimer
- **Website Phishing Detection**: Evaluates domain structure, brand lookalike syntax, suspicious top-level domains (TLDs), and cyber-deception patterns.
- **Product Authenticity**: Evaluates barcodes, batch numbers, manufacturer distribution channels, and physical packaging indicators.
- **Crucial Rule**: Phishing detection does **NOT** verify whether a physical product is genuine or counterfeit. A legitimate website may still host third-party replica listings, and a newly registered domain might sell genuine handcrafted products. Risk scoring is a caution index, not physical proof.

---

## Architecture Overview

```
┌─────────────────────────────────┐
│     React Frontend (Vite)       │
│  (WebsiteCheckerPage / Reports) │
└────────────────┬────────────────┘
                 │ (1) POST /api/ml/predict-phishing
                 ▼
┌─────────────────────────────────┐
│     Express Full-Stack Server   │
│          (server.ts)            │
│  - SSRF Protection              │
│  - Heuristic Fallback           │
└────────────────┬────────────────┘
                 │ (2) Proxy to ML_SERVICE_URL
                 ▼
┌─────────────────────────────────┐
│     Python FastAPI Microservice │
│           (ml/app.py)           │
│  - Endpoint: /predict           │
│  - Feature Extractor (16 feats) │
└────────────────┬────────────────┘
                 │ (3) Applies Scikit-Learn Pipeline
                 ▼
┌─────────────────────────────────┐
│     phishing_model.joblib       │
│  (StandardScaler + RandomForest)│
└─────────────────────────────────┘
```

---

## Quick Start: Train in Google Colab (Beginner-Friendly)

1. Open [Google Colab](https://colab.research.google.com).
2. Click **File** -> **Upload notebook** and select `ml/Google_Colab_Phishing_Detection.ipynb` from this project.
3. Click **Runtime** -> **Run all** (or step through cells individually).
4. Inspect the dataset breakdown, real confusion matrix, and precision/recall scores on the unseen 20% test split.
5. Colab will download `phishing_model.joblib`.
6. Place `phishing_model.joblib` into this `/ml/` directory.

---

## Running the Python FastAPI Inference Microservice Locally

```bash
# 1. Navigate to ml folder
cd ml

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Train locally (if not using Google Colab)
python train_phishing_model.py

# 4. Start the FastAPI microservice
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

Interactive API documentation will be available at `http://localhost:8000/docs`.

---

## Connecting with the Web Application

The Node.js/Express server in `server.ts` proxies requests to the ML microservice:
- Environment variable: `ML_SERVICE_URL="http://localhost:8000"`
- API Endpoint: `/api/ml/predict-phishing`
- If the Python microservice is not yet running, the web application automatically falls back to the deterministic risk engine so that users experience zero disruption.
