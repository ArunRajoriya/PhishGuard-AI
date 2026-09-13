"""
PhishGuard AI - Model Robustness Testing

Tests the trained domain-robust URL model against
realistic benign, suspicious, phishing-like, and
adversarial URL patterns.

This is a behavioral sanity test, NOT a replacement
for a properly labeled external test set.
"""

import sys
from pathlib import Path

import joblib
import pandas as pd

# ---------------------------------------------------------------------
# Project root
# ---------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent

MODEL_PATH = ROOT / "model" / "domain_url_model.pkl"
SCHEMA_PATH = ROOT / "model" / "domain_feature_schema.json"

sys.path.insert(0, str(ROOT))

from feature_extractor import extract_features


# ---------------------------------------------------------------------
# Load model
# ---------------------------------------------------------------------

print("=" * 75)
print("PhishGuard AI - Model Robustness Testing")
print("=" * 75)

if not MODEL_PATH.exists():
    raise FileNotFoundError(f"Model not found: {MODEL_PATH}")

if not SCHEMA_PATH.exists():
    raise FileNotFoundError(f"Feature schema not found: {SCHEMA_PATH}")

model = joblib.load(MODEL_PATH)

print(f"\nModel loaded: {MODEL_PATH}")
print(f"Schema loaded: {SCHEMA_PATH}")


# ---------------------------------------------------------------------
# Feature schema
# ---------------------------------------------------------------------

import json

with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
    schema = json.load(f)

FEATURES = schema["features"]

print(f"Feature count: {len(FEATURES)}")


# ---------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------

TEST_CASES = {

    "LEGITIMATE_MAJOR_SITES": [
        "https://google.com",
        "https://www.google.com",
        "https://microsoft.com",
        "https://www.microsoft.com",
        "https://github.com",
        "https://www.github.com",
        "https://apple.com",
        "https://www.apple.com",
        "https://amazon.com",
        "https://www.amazon.com",
        "https://linkedin.com",
        "https://www.linkedin.com",
        "https://python.org",
        "https://www.python.org",
        "https://oracle.com",
        "https://www.oracle.com",
        "https://wikipedia.org",
        "https://www.wikipedia.org",
    ],

    "LEGITIMATE_COMPLEX_URLS": [
        "https://github.com/user/repository/issues/123",
        "https://github.com/ArunRajoriya/PhishGuard-AI",
        "https://www.google.com/search?q=machine+learning",
        "https://stackoverflow.com/questions/tagged/python",
        "https://docs.python.org/3/library/urllib.parse.html",
        "https://learn.microsoft.com/en-us/python/",
        "https://www.amazon.com/s?k=laptop",
        "https://en.wikipedia.org/wiki/Machine_learning",
        "https://www.linkedin.com/jobs/search/?keywords=software%20engineer",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP",
    ],

    "SUSPICIOUS_SUBDOMAINS": [
        "https://paypal-login.example.com",
        "https://paypal-security.example.com",
        "https://microsoft-security.example.org",
        "https://google-verify.example.net",
        "https://amazon-account.example.com",
        "https://apple-id-verify.example.org",
        "https://github-security.example.net",
        "https://bank-login.example.com",
        "https://secure-account.example.org",
        "https://account-verification.example.net",
    ],

    "CREDENTIAL_PATTERNS": [
        "https://example.com/login",
        "https://example.com/signin",
        "https://example.com/sign-in",
        "https://example.com/account/login",
        "https://example.com/account/verify",
        "https://example.com/password/reset",
        "https://example.com/security/confirm",
        "https://example.com/authenticate",
        "https://example.com/credential/update",
        "https://example.com/billing/payment",
    ],

    "BRAND_IMPERSONATION": [
        "https://paypal-login.example.com/verify",
        "https://paypal-security.example.org/account",
        "https://microsoft-login.example.net/verify",
        "https://google-security.example.com/signin",
        "https://apple-id.example.org/verify",
        "https://amazon-security.example.net/account",
        "https://github-login.example.com/authenticate",
        "https://linkedin-security.example.org/login",
        "https://netflix-account.example.net/verify",
        "https://bank-security.example.com/login",
    ],

    "IP_BASED_URLS": [
        "http://192.168.1.100/login",
        "http://45.33.22.11/verify",
        "http://185.199.108.153/account",
        "http://142.250.72.14/login",
        "https://8.8.8.8/login",
        "http://10.0.0.1/security/verify",
    ],

    "OBFUSCATION": [
        "https://example.com/%6c%6f%67%69%6e",
        "https://example.com/%76%65%72%69%66%79",
        "https://example.com/login?redirect=%2Faccount",
        "https://example.com/%61%63%63%6f%75%6e%74",
        "https://example.com/login?next=%2Fverify%2Faccount",
    ],

    "CREDENTIALS_IN_URL": [
        "https://user:password@example.com/",
        "https://admin:admin@example.com/login",
        "https://user:pass@example.com/account",
        "https://test:123456@example.com/verify",
    ],

    "SUSPICIOUS_TLDS": [
        "https://example.xyz/login",
        "https://example.top/verify",
        "https://example.click/account",
        "https://example.tk/security",
        "https://example.work/login",
        "https://example.support/verify",
        "https://example.download/account",
        "https://example.review/login",
    ],

    "LONG_COMPLEX_URLS": [
        "https://example.com/account/login/verify/security/authentication/password/reset/confirm",
        "https://example.com/user/account/profile/security/settings/verification/login",
        "https://example.com/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t",
        "https://example.com/login?redirect=/account/security/verification/password/reset&session=123456789",
    ],

    "SUSPICIOUS_STRUCTURE": [
        "http://example.com/login",
        "http://example.com/verify/account",
        "http://example.com/security/update",
        "http://example.com/account/password",
        "https://example.com@evil.com/login",
        "https://example.com/account?verify=true&login=true",
    ],
}


# ---------------------------------------------------------------------
# Prediction helper
# ---------------------------------------------------------------------

def predict_url(url: str):
    features = extract_features(url)

    # Ensure exact schema/order expected by model
    row = {
        feature: features.get(feature, 0)
        for feature in FEATURES
    }

    X = pd.DataFrame([row], columns=FEATURES)

    prediction = int(model.predict(X)[0])

    if hasattr(model, "predict_proba"):
        probability = float(model.predict_proba(X)[0][1])
    else:
        probability = float(prediction)

    label = "PHISHING" if prediction == 1 else "LEGITIMATE"

    return label, probability


# ---------------------------------------------------------------------
# Run tests
# ---------------------------------------------------------------------

results = []

for category, urls in TEST_CASES.items():

    print("\n" + "=" * 75)
    print(category)
    print("=" * 75)

    phishing_count = 0
    legitimate_count = 0

    for url in urls:

        label, probability = predict_url(url)

        if label == "PHISHING":
            phishing_count += 1
        else:
            legitimate_count += 1

        results.append({
            "category": category,
            "url": url,
            "prediction": label,
            "probability": probability,
        })

        print(
            f"{label:<11} "
            f"{probability:>7.4f}  "
            f"{url}"
        )

    print(
        f"\nSummary: "
        f"{phishing_count} PHISHING | "
        f"{legitimate_count} LEGITIMATE | "
        f"{len(urls)} total"
    )


# ---------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------

df = pd.DataFrame(results)

print("\n" + "=" * 75)
print("OVERALL SUMMARY")
print("=" * 75)

summary = (
    df.groupby(["category", "prediction"])
    .size()
    .unstack(fill_value=0)
)

print(summary)

print("\nPrediction distribution:")
print(df["prediction"].value_counts())

print("\nAverage phishing probability by category:")
print(
    df.groupby("category")["probability"]
    .mean()
    .sort_values(ascending=False)
    .round(4)
)


# ---------------------------------------------------------------------
# Save results
# ---------------------------------------------------------------------

output_path = ROOT / "model" / "robustness_results.csv"

df.to_csv(output_path, index=False)

print("\n" + "=" * 75)
print("RESULTS SAVED")
print("=" * 75)
print(output_path)