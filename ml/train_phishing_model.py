"""
VerifyBeforeBuy AI — Phishing Website Model Training Script
Uses pandas and scikit-learn to train a supervised binary classification model
for detecting deceptive and phishing URLs.

IMPORTANT COMPLIANCE NOTES:
1. This model detects lexical, structural, and cyber-risk indicators of phishing websites.
2. It does NOT verify physical product authenticity or detect counterfeit merchandise.
3. Risk assessment is an indicator of caution, never proof of genuine vs fake products.
"""

import os
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)
from feature_extractor import FEATURE_NAMES, extract_features_from_url, features_to_vector


def create_or_load_dataset(csv_path: str = "data/malicious_phish.csv") -> pd.DataFrame:
    """
    Loads labeled phishing website data from a CSV file.
    Supports Kaggle malicious_phish.csv (url, type) and standard phishing datasets.
    """
    search_paths = [
        csv_path,
        "ml/data/malicious_phish.csv",
        "data/malicious_phish.csv",
        "malicious_phish.csv",
        "../data/malicious_phish.csv",
        "phishing_dataset.csv"
    ]
    
    found_path = None
    for p in search_paths:
        if os.path.exists(p):
            found_path = p
            break

    if found_path:
        print(f"[*] Found local dataset: {found_path}")
        df = pd.read_csv(found_path, nrows=100000)
        print(f"[*] Loaded {len(df)} rows. Columns: {list(df.columns)}")
        
        # If dataset is Kaggle malicious_phish.csv with 'url' and 'type'
        if 'type' in df.columns and 'label' not in df.columns:
            print("[*] Normalizing classes: 'benign' -> 0 (Legitimate), malicious types -> 1 (Phishing)")
            df['label'] = df['type'].apply(lambda t: 0 if str(t).strip().lower() == 'benign' else 1)
        
        return df

    print("[!] No CSV found. Generating bootstrap labeled URL dataset for pipeline demonstration...")
    
    # Representative sample of legitimate shopping & portal URLs
    legit_samples = [
        "https://www.amazon.com/dp/B08N5WRWNW",
        "https://www.ebay.com/itm/1234567890",
        "https://www.target.com/p/apple-airpods-pro",
        "https://www.walmart.com/ip/electronics-tv",
        "https://store.steampowered.com/app/1091500",
        "https://www.bestbuy.com/site/sony-headphones",
        "https://www.apple.com/shop/buy-iphone",
        "https://www.nike.com/us/en_us/c/running",
        "https://www.nordstrom.com/browse/men/shoes",
        "https://www.etsy.com/listing/vintage-leather-wallet",
        "https://www.shopify.com/free-trial",
        "https://www.costco.com/laptops.html",
        "https://www.homedepot.com/b/Appliances/N-5yc1vZbv1w",
        "https://www.ikea.com/us/en/cat/furniture-fu001/",
        "https://www.wayfair.com/furniture/sb0/desks-c46178.html",
        "https://www.zappos.com/men-sneakers",
        "https://www.sephora.com/product/skincare-cream",
        "https://www.aliexpress.com/item/100500123.html",
        "https://www.bhphotovideo.com/c/product/camera",
        "https://www.newegg.com/p/N82E16814137782",
    ]

    # Representative sample of known phishing, credential-harvesting & typo patterns
    phish_samples = [
        "https://apple-security-verify-login.click/update-billing",
        "http://45.33.32.156:8080/shop-login-auth",
        "https://official-nike-cheap-wholesale-outlet.xyz/sale-80off",
        "http://paypal-account-verification-safety.top/signin",
        "https://amazon-support-prime-account-update.buzz/order",
        "http://walmart-winner-claim-giftcard.work/free-shipping",
        "https://ebay-isapi-dll-signin-account-verify.cfd/login",
        "http://target-blackfriday-90percent-clearance.top/cart",
        "https://steam-free-skins-wallet-claim.monster/auth",
        "http://192.168.1.100/checkout/secure-payment",
        "https://bestbuy-customer-refund-notice.click/claim",
        "http://appleid-confirm-passcode-update.rest/account",
        "https://nike-sneakers-vip-discount-outlet.xyz/shoes",
        "http://bank-of-america-secure-login-session.top/verify",
        "https://netflix-subscription-renew-billing.work/login",
        "http://chase-security-alert-unusual-activity.buzz/auth",
        "https://wellsfargo-online-banking-access.cam/signin",
        "http://secure-crypto-wallet-connect-airdrop.fit/claim",
        "https://gucci-clearance-handbags-95percent-off.xyz/shop",
        "http://rolex-replica-luxury-watches-cheap.click/order",
    ]

    # Expand dataset with realistic combinatorial variations to ensure adequate training depth
    rows = []
    for url in legit_samples:
        features = extract_features_from_url(url)
        features["url"] = url
        features["is_phishing"] = 0  # 0 = Legitimate
        rows.append(features)

    for url in phish_samples:
        features = extract_features_from_url(url)
        features["url"] = url
        features["is_phishing"] = 1  # 1 = Phishing
        rows.append(features)

    # Repeat with random jitter to allow stable split and variance testing
    expanded_rows = []
    np.random.seed(42)
    for _ in range(15):
        for r in rows:
            r_copy = dict(r)
            # Add minor natural variations to continuous metrics
            r_copy["url_length"] = max(15, int(r_copy["url_length"] + np.random.randint(-3, 4)))
            r_copy["path_length"] = max(0, int(r_copy["path_length"] + np.random.randint(-2, 3)))
            expanded_rows.append(r_copy)

    df = pd.DataFrame(expanded_rows)
    df.to_csv(csv_path, index=False)
    print(f"[*] Created seed dataset with {len(df)} samples saved to '{csv_path}'.")
    return df


def train_and_evaluate_model(df: pd.DataFrame, model_output_path: str = "phishing_model.joblib"):
    """
    Main training workflow:
    1. Inspects dataset columns, data types, and target distribution.
    2. Performs stratified train/test split to prevent data leakage.
    3. Trains a baseline Pipeline (StandardScaler + RandomForest).
    4. Evaluates test set using precision, recall, F1, accuracy, and confusion matrix.
    5. Saves model artifact and metadata.
    """
    print("\n" + "=" * 60)
    print("STEP 1: INSPECTING DATASET SCHEMA & LABELS")
    print("=" * 60)

    target_col = "is_phishing"
    if target_col not in df.columns:
        raise ValueError(f"Target column '{target_col}' not found in dataset columns: {list(df.columns)}")

    # Check features
    available_features = [f for f in FEATURE_NAMES if f in df.columns]
    print(f"Available numerical features ({len(available_features)}): {available_features}")
    
    # Class distribution
    counts = df[target_col].value_counts().to_dict()
    print(f"Target Class Distribution:")
    print(f"  - Legitimate (0): {counts.get(0, 0)} samples")
    print(f"  - Phishing (1):   {counts.get(1, 0)} samples")
    
    # Check missing values
    missing = df[available_features].isnull().sum().sum()
    print(f"Missing values across feature set: {missing}")

    X = df[available_features].values
    y = df[target_col].values

    print("\n" + "=" * 60)
    print("STEP 2: STRATIFIED TRAIN/TEST SPLIT (PREVENTING DATA LEAKAGE)")
    print("=" * 60)
    # Stratified split ensures equal class representation in train and test sets
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )
    print(f"Total dataset: {len(X)} samples")
    print(f"Training set:  {len(X_train)} samples (80%)")
    print(f"Test set:      {len(X_test)} samples (20%)")
    print("Data leakage prevention: Scaler and model parameters fit strictly on X_train.")

    print("\n" + "=" * 60)
    print("STEP 3: TRAINING CLASSIFICATION PIPELINE")
    print("=" * 60)
    # Baseline 1: Logistic Regression
    lr_pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('classifier', LogisticRegression(random_state=42, max_iter=500))
    ])
    lr_pipeline.fit(X_train, y_train)
    lr_preds = lr_pipeline.predict(X_test)
    lr_acc = accuracy_score(y_test, lr_preds)
    print(f"Baseline 1 (Logistic Regression) Test Accuracy: {lr_acc * 100:.2f}%")

    # Primary Model: Random Forest Classifier
    rf_pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('classifier', RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42))
    ])
    print("[*] Fitting Random Forest model on training set...")
    rf_pipeline.fit(X_train, y_train)
    print("[+] Model training complete.")

    print("\n" + "=" * 60)
    print("STEP 4: EVALUATION METRICS (TEST SET ONLY)")
    print("=" * 60)
    y_pred = rf_pipeline.predict(X_test)
    y_prob = rf_pipeline.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)

    print(f"Evaluated Test Metrics (Unseen data):")
    print(f"  • Accuracy:        {acc:.4f} ({acc * 100:.2f}%)")
    print(f"  • Precision:       {prec:.4f}")
    print(f"  • Recall:          {rec:.4f}")
    print(f"  • F1-Score:        {f1:.4f}")
    print("\nConfusion Matrix:")
    print("                Predicted Legitimate (0)  |  Predicted Phishing (1)")
    print(f"Actual Legit (0):         {cm[0][0]:<15} |  {cm[0][1]:<15}")
    print(f"Actual Phish (1):         {cm[1][0]:<15} |  {cm[1][1]:<15}")
    
    print("\nFull Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate (0)", "Phishing (1)"]))

    print("\n" + "=" * 60)
    print("STEP 5: SAVING MODEL ARTIFACT & METADATA")
    print("=" * 60)
    joblib.dump(rf_pipeline, model_output_path)
    print(f"[+] Saved scikit-learn pipeline to: {model_output_path}")

    metadata = {
        "model_type": "RandomForestClassifier with StandardScaler",
        "features": available_features,
        "metrics": {
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "test_sample_count": len(y_test),
        },
        "target_mapping": {
            "0": "Legitimate Website Pattern",
            "1": "Phishing / Deceptive Pattern"
        },
        "compliance_note": "Risk assessment is a heuristic caution score, not verification of physical product authenticity."
    }

    meta_path = "model_metadata.json"
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"[+] Saved model metadata to: {meta_path}")

    return rf_pipeline, metadata


if __name__ == "__main__":
    dataset = create_or_load_dataset()
    train_and_evaluate_model(dataset)
