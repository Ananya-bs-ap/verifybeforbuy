"""
Feature Extractor for Phishing Website Detection
Extracts lexical and structural indicators from URLs for machine learning classification.
Based on feature definitions from the UCI Phishing Websites dataset and cybersecurity benchmarks.
"""

import re
from urllib.parse import urlparse
from typing import Dict, Any, List

# Suspicious words commonly found in deceptive shopping and account phishing URLs
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "banking", "free",
    "discount", "wholesale", "outlet", "cheap", "bonus", "winner", "signin",
    "wallet", "password", "confirm", "claim", "prize", "ebay-isapi", "paypal"
]

# High-risk TLDs frequently abused in rapid phishing campaigns
HIGH_RISK_TLDS = {
    ".xyz", ".click", ".top", ".work", ".buzz", ".cam", ".rest",
    ".fit", ".cfd", ".monster", ".gq", ".ml", ".cf", ".ga", ".tk"
}

FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "count_dots",
    "count_hyphens",
    "count_at",
    "count_question",
    "count_percent",
    "count_slash",
    "has_ip_address",
    "count_subdomains",
    "has_https",
    "has_hyphen_in_domain",
    "has_suspicious_keyword",
    "is_high_risk_tld",
    "digit_ratio_in_url"
]

def is_ip_address(hostname: str) -> int:
    """Checks if hostname is an IPv4 or IPv6 address instead of a domain name."""
    clean_host = hostname.split(":")[0].strip()
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ipv4_pattern, clean_host):
        return 1
    if ":" in clean_host and not clean_host.startswith("http"):
        return 1
    return 0

def count_subdomains(hostname: str) -> int:
    """Estimates subdomain depth excluding www and TLD."""
    host = hostname.split(":")[0].strip().lower()
    if host.startswith("www."):
        host = host[4:]
    parts = host.split(".")
    # e.g., 'sub2.sub1.example.com' has 4 parts -> 2 subdomains
    if len(parts) > 2:
        return len(parts) - 2
    return 0

def extract_features_from_url(url: str) -> Dict[str, Any]:
    """
    Extracts numerical features from a given URL for model inference.
    Returns both a dictionary of named features and a raw numerical vector.
    """
    url_clean = url.strip()
    if not (url_clean.startswith("http://") or url_clean.startswith("https://")):
        url_clean = "https://" + url_clean

    try:
        parsed = urlparse(url_clean)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
    except Exception:
        hostname = ""
        path = ""

    url_len = len(url_clean)
    host_len = len(hostname)
    path_len = len(path)
    
    digits_count = sum(c.isdigit() for c in url_clean)
    digit_ratio = round(digits_count / max(url_len, 1), 4)

    has_kw = 1 if any(kw in url_clean.lower() for kw in SUSPICIOUS_KEYWORDS) else 0
    tld_match = 1 if any(hostname.lower().endswith(tld) for tld in HIGH_RISK_TLDS) else 0

    features = {
        "url_length": url_len,
        "hostname_length": host_len,
        "path_length": path_len,
        "count_dots": url_clean.count("."),
        "count_hyphens": url_clean.count("-"),
        "count_at": 1 if "@" in url_clean else 0,
        "count_question": url_clean.count("?"),
        "count_percent": url_clean.count("%"),
        "count_slash": url_clean.count("/"),
        "has_ip_address": is_ip_address(hostname),
        "count_subdomains": count_subdomains(hostname),
        "has_https": 1 if parsed.scheme == "https" else 0,
        "has_hyphen_in_domain": 1 if "-" in hostname else 0,
        "has_suspicious_keyword": has_kw,
        "is_high_risk_tld": tld_match,
        "digit_ratio_in_url": digit_ratio,
    }

    return features

def features_to_vector(features: Dict[str, Any]) -> List[float]:
    """Converts a feature dict into an ordered vector for scikit-learn models."""
    return [float(features[name]) for name in FEATURE_NAMES]
