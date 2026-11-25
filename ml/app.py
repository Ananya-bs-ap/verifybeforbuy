"""
VerifyBeforeBuy AI — FastAPI Machine Learning Inference Microservice
Exposes scikit-learn phishing website detection model via REST API.
"""

import os
import joblib
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from feature_extractor import extract_features_from_url, features_to_vector, FEATURE_NAMES

app = FastAPI(
    title="VerifyBeforeBuy AI — ML Phishing Detection API",
    description="Machine Learning service for predicting phishing risk based on URL lexical and structural indicators.",
    version="1.0.0"
)

# Enable CORS for frontend and Express backend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishing_model.joblib")
_loaded_model = None

def get_model():
    """Lazily loads the saved scikit-learn pipeline."""
    global _loaded_model
    if _loaded_model is None:
        if os.path.exists(MODEL_PATH):
            try:
                _loaded_model = joblib.load(MODEL_PATH)
                print(f"[*] Loaded trained model from {MODEL_PATH}")
            except Exception as e:
                print(f"[!] Error loading model artifact: {e}")
                _loaded_model = None
        else:
            print(f"[i] Model artifact not found at {MODEL_PATH}. Microservice operating in heuristic fallback mode.")
    return _loaded_model


class PredictRequest(BaseModel):
    url: str = Field(..., example="https://apple-security-verify-login.click/update-billing")


class PredictResponse(BaseModel):
    url: str
    is_phishing: bool
    phishing_probability: float
    risk_score: int
    risk_category: str
    model_trained: bool
    model_type: str
    features: Dict[str, Any]
    indicators_flagged: list[str]
    disclaimer: str


@app.get("/")
@app.get("/health")
def health_check():
    """Health and model availability status check."""
    model = get_model()
    return {
        "status": "healthy",
        "service": "VerifyBeforeBuy AI — ML Phishing Detection Service",
        "model_trained": model is not None,
        "features_tracked": len(FEATURE_NAMES),
        "target_task": "Website Phishing Risk Classification",
        "important_boundary": "Assesses cyber deception patterns; does NOT verify physical product authenticity or detect counterfeit merchandise."
    }


@app.post("/predict", response_model=PredictResponse)
@app.post("/api/predict", response_model=PredictResponse)
def predict_phishing(request: PredictRequest):
    """
    Evaluates a website URL for phishing probability using the trained
    scikit-learn classifier and feature extractor.
    """
    raw_url = request.url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    # 1. Extract lexical and structural features
    features = extract_features_from_url(raw_url)
    vector = features_to_vector(features)

    # 2. Flag specific human-readable warning indicators
    flagged = []
    if features.get("has_ip_address"):
        flagged.append("Host is a raw numerical IP address instead of a domain name")
    if features.get("is_high_risk_tld"):
        flagged.append("Domain uses a top-level domain frequently associated with disposable phishing campaigns")
    if features.get("has_suspicious_keyword"):
        flagged.append("URL contains high-risk account or urgency keywords (login/verify/free/cheap/outlet)")
    if features.get("count_subdomains", 0) >= 2:
        flagged.append("Deep subdomain nesting often used to disguise brand names")
    if features.get("has_hyphen_in_domain"):
        flagged.append("Hyphenated domain structure commonly seen in brand lookalikes")
    if not features.get("has_https"):
        flagged.append("Insecure plain HTTP protocol without SSL/TLS transport encryption")
    if features.get("url_length", 0) > 75:
        flagged.append("Excessive URL length commonly used to obfuscate destinations")

    model = get_model()
    model_type = "Scikit-Learn RandomForest Pipeline" if model else "Heuristic Rule-Based Fallback"
    model_trained = model is not None

    if model_trained:
        try:
            # Predict probability of class 1 (phishing)
            proba = float(model.predict_proba([vector])[0][1])
            is_phish = bool(proba >= 0.50)
            score = int(round(proba * 100))
        except Exception as e:
            # Fallback to feature density if error occurs
            model_trained = False
            model_type = f"Fallback (Model Error: {str(e)})"
            score = min(100, len(flagged) * 22)
            proba = round(score / 100.0, 2)
            is_phish = score >= 50
    else:
        # Transparent rule heuristic until model training is executed
        score = min(100, len(flagged) * 22)
        proba = round(score / 100.0, 2)
        is_phish = score >= 50

    if score <= 25:
        category = "lower"
    elif score <= 50:
        category = "moderate"
    elif score <= 75:
        category = "elevated"
    else:
        category = "high"

    return PredictResponse(
        url=raw_url,
        is_phishing=is_phish,
        phishing_probability=proba,
        risk_score=score,
        risk_category=category,
        model_trained=model_trained,
        model_type=model_type,
        features=features,
        indicators_flagged=flagged,
        disclaimer=(
            "Risk assessment provides a probability score based on URL structural indicators. "
            "It does NOT verify physical product authenticity, nor does it guarantee a genuine item."
        )
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
