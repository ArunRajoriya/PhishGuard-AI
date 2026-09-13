
"""
PhishGuard AI - Hostname Character Model Robustness Test

Tests the hostname character n-gram model against:
- Legitimate major websites
- Legitimate complex URLs
- Suspicious subdomains
- Brand impersonation
- Credential patterns
- IP-based URLs
- Obfuscated URLs
- Suspicious TLDs
- Long complex URLs
- Suspicious URL structures

Run:
    python model/test_hostname_model.py
"""

from pathlib import Path
import sys
import re
import json
import joblib
import pandas as pd
from urllib.parse import urlsplit


# ============================================================
# PROJECT ROOT
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================
# MODEL PATHS
# ============================================================

MODEL_PATH = PROJECT_ROOT / "model" / "hostname_char_model.pkl"
VECTORIZER_PATH = PROJECT_ROOT / "model" / "hostname_vectorizer.pkl"

RESULTS_PATH = PROJECT_ROOT / "model" / "hostname_robustness_results.csv"


# ============================================================
# LOAD MODEL
# ============================================================

print("=" * 75)
print("PHISHGUARD AI - HOSTNAME MODEL ROBUSTNESS TEST")
print("=" * 75)

print("\nLoading model...")

if not MODEL_PATH.exists():
    raise FileNotFoundError(
        f"Model not found:\n{MODEL_PATH}\n\n"
        "Run:\n"
        "python model/train_hostname_model.py"
    )

if not VECTORIZER_PATH.exists():
    raise FileNotFoundError(
        f"Vectorizer not found:\n{VECTORIZER_PATH}\n\n"
        "Run:\n"
        "python model/train_hostname_model.py"
    )

model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)

print(f"Model     : {MODEL_PATH}")
print(f"Vectorizer: {VECTORIZER_PATH}")


# ============================================================
# HOSTNAME EXTRACTION
# ============================================================

def extract_hostname(url: str) -> str:
    """
    Extract hostname from a URL.

    The hostname model should only see the hostname,
    not path/query/fragment information.
    """

    url = str(url).strip()

    if "://" not in url:
        url = "https://" + url

    parsed = urlsplit(url)

    hostname = parsed.hostname or ""

    return hostname.lower().strip(".")


# ============================================================
# PREDICTION
# ============================================================

def predict_hostname(url: str):
    hostname = extract_hostname(url)

    X = vectorizer.transform([hostname])

    probability = float(model.predict_proba(X)[0][1])
    prediction = int(model.predict(X)[0])

    return prediction, probability, hostname


# ============================================================
# TEST DATA
# ============================================================

TEST_CASES = {

    # --------------------------------------------------------
    # LEGITIMATE MAJOR WEBSITES
    # --------------------------------------------------------

    "LEGITIMATE_MAJOR_SITES": [
        ("https://google.com", 0),
        ("https://www.google.com", 0),

        ("https://microsoft.com", 0),
        ("https://www.microsoft.com", 0),

        ("https://github.com", 0),
        ("https://www.github.com", 0),

        ("https://apple.com", 0),
        ("https://www.apple.com", 0),

        ("https://amazon.com", 0),
        ("https://www.amazon.com", 0),

        ("https://linkedin.com", 0),
        ("https://www.linkedin.com", 0),

        ("https://python.org", 0),
        ("https://www.python.org", 0),

        ("https://oracle.com", 0),
        ("https://www.oracle.com", 0),

        ("https://wikipedia.org", 0),
        ("https://www.wikipedia.org", 0),
    ],


    # --------------------------------------------------------
    # LEGITIMATE COMPLEX URLS
    # --------------------------------------------------------

    "LEGITIMATE_COMPLEX_URLS": [
        (
            "https://www.google.com/search?q=machine+learning",
            0
        ),

        (
            "https://github.com/ArunRajoriya/PhishGuard-AI",
            0
        ),

        (
            "https://www.amazon.com/s?k=laptop&ref=nav_bb",
            0
        ),

        (
            "https://learn.microsoft.com/en-us/dotnet/csharp/",
            0
        ),

        (
            "https://docs.python.org/3/library/urllib.parse.html",
            0
        ),

        (
            "https://en.wikipedia.org/wiki/Computer_security",
            0
        ),

        (
            "https://www.linkedin.com/jobs/search/?keywords=software%20engineer",
            0
        ),

        (
            "https://developer.apple.com/documentation/swift",
            0
        ),

        (
            "https://docs.oracle.com/en/java/javase/21/docs/api/",
            0
        ),

        (
            "https://stackoverflow.com/questions/tagged/java",
            0
        ),
    ],


    # --------------------------------------------------------
    # SUSPICIOUS SUBDOMAINS
    # --------------------------------------------------------

    "SUSPICIOUS_SUBDOMAINS": [
        (
            "https://paypal-login.security-check.example.com/account",
            1
        ),

        (
            "https://microsoft-security.verify-account.example.com/login",
            1
        ),

        (
            "https://google-account.security-alert.example.net/verify",
            1
        ),

        (
            "https://appleid.confirm-security.example.org/login",
            1
        ),

        (
            "https://amazon.account-verification.example.com/login",
            1
        ),

        (
            "https://github.security-confirm.example.net/auth",
            1
        ),

        (
            "https://banking.secure-login.example.org/verify",
            1
        ),

        (
            "https://office365.account-security.example.com/login",
            1
        ),

        (
            "https://instagram.password-reset.example.net/login",
            1
        ),

        (
            "https://facebook.security-check.example.org/verify",
            1
        ),
    ],


    # --------------------------------------------------------
    # BRAND IMPERSONATION
    # --------------------------------------------------------

    "BRAND_IMPERSONATION": [
        (
            "https://paypal-login.com",
            1
        ),

        (
            "https://paypal-secure.com",
            1
        ),

        (
            "https://microsoft-login.net",
            1
        ),

        (
            "https://google-security.org",
            1
        ),

        (
            "https://appleid-login.net",
            1
        ),

        (
            "https://amazon-verification.com",
            1
        ),

        (
            "https://github-login.net",
            1
        ),

        (
            "https://facebook-security.org",
            1
        ),

        (
            "https://instagram-login.net",
            1
        ),

        (
            "https://netflix-account-security.com",
            1
        ),
    ],


    # --------------------------------------------------------
    # CREDENTIAL PATTERNS
    # --------------------------------------------------------

    "CREDENTIAL_PATTERNS": [
        (
            "https://user:password@example.com/login",
            1
        ),

        (
            "https://admin:admin@example.net/login",
            1
        ),

        (
            "https://user:123456@example.org/verify",
            1
        ),

        (
            "https://login:password@secure-example.com/account",
            1
        ),

        (
            "https://paypal:userpass@example.com/login",
            1
        ),

        (
            "https://admin:password@bank-example.net/login",
            1
        ),

        (
            "https://support:verify@example.org/account",
            1
        ),

        (
            "https://security:login@example.com/verify",
            1
        ),

        (
            "https://account:reset@example.net/login",
            1
        ),

        (
            "https://user:pass@example.org/security",
            1
        ),
    ],


    # --------------------------------------------------------
    # IP BASED URLS
    # --------------------------------------------------------

    "IP_BASED_URLS": [
        (
            "http://192.168.1.10/login",
            1
        ),

        (
            "http://192.168.10.25/verify",
            1
        ),

        (
            "http://10.0.0.15/account",
            1
        ),

        (
            "https://185.199.108.153/login",
            1
        ),

        (
            "https://142.250.72.14/security",
            1
        ),

        (
            "http://45.33.32.156/verify",
            1
        ),
    ],


    # --------------------------------------------------------
    # OBFUSCATION
    # --------------------------------------------------------

    "OBFUSCATION": [
        (
            "https://paypal%2Dlogin.example.com",
            1
        ),

        (
            "https://secure%2Dlogin.example.net",
            1
        ),

        (
            "https://account%2Dverify.example.org",
            1
        ),

        (
            "https://login%2Dsecurity.example.com",
            1
        ),

        (
            "https://bank%2Dverify.example.net",
            1
        ),
    ],


    # --------------------------------------------------------
    # SUSPICIOUS TLDs
    # --------------------------------------------------------

    "SUSPICIOUS_TLDS": [
        (
            "https://paypal-login.xyz",
            1
        ),

        (
            "https://microsoft-security.top",
            1
        ),

        (
            "https://google-verify.click",
            1
        ),

        (
            "https://apple-security.shop",
            1
        ),

        (
            "https://amazon-account.work",
            1
        ),

        (
            "https://bank-login.online",
            1
        ),

        (
            "https://secure-account.site",
            1
        ),

        (
            "https://password-reset.live",
            1
        ),
    ],


    # --------------------------------------------------------
    # LONG COMPLEX URLS
    # --------------------------------------------------------

    "LONG_COMPLEX_URLS": [
        (
            "https://secure-account-verification-example.com/"
            "account/login/security/verification/password/reset/"
            "confirm",
            1
        ),

        (
            "https://paypal-login-security-verification-example.net/"
            "account/verify/identity/security/password",
            1
        ),

        (
            "https://microsoft-account-security-check-example.org/"
            "login/verify/account/password/recovery",
            1
        ),

        (
            "https://google-account-security-alert-example.com/"
            "verify/login/account/recovery/password/reset",
            1
        ),
    ],


    # --------------------------------------------------------
    # SUSPICIOUS STRUCTURE
    # --------------------------------------------------------

    "SUSPICIOUS_STRUCTURE": [
        (
            "https://login-secure-account-verify.example.com",
            1
        ),

        (
            "https://secure-payment-verification.example.net",
            1
        ),

        (
            "https://account-password-confirm.example.org",
            1
        ),

        (
            "https://security-alert-login.example.com",
            1
        ),

        (
            "https://verify-identity-account.example.net",
            1
        ),

        (
            "https://urgent-security-update.example.org",
            1
        ),
    ],
}


# ============================================================
# RUN TESTS
# ============================================================

results = []

category_summary = {}

print("\n" + "=" * 75)
print("RUNNING ROBUSTNESS TESTS")
print("=" * 75)


for category, test_cases in TEST_CASES.items():

    print("\n" + "-" * 75)
    print(category)
    print("-" * 75)

    correct = 0
    total = len(test_cases)

    probabilities = []

    for url, expected in test_cases:

        prediction, probability, hostname = predict_hostname(url)

        predicted_label = (
            "PHISHING"
            if prediction == 1
            else "LEGITIMATE"
        )

        expected_label = (
            "PHISHING"
            if expected == 1
            else "LEGITIMATE"
        )

        is_correct = prediction == expected

        if is_correct:
            correct += 1

        probabilities.append(probability)

        status = "PASS" if is_correct else "FAIL"

        print(
            f"\n[{status}] "
            f"Expected: {expected_label:<10} "
            f"Predicted: {predicted_label:<10} "
            f"Probability: {probability:.4f}"
        )

        print(f"  URL      : {url}")
        print(f"  Hostname : {hostname}")

        results.append({
            "category": category,
            "url": url,
            "hostname": hostname,
            "expected": expected,
            "prediction": prediction,
            "phishing_probability": probability,
            "correct": is_correct,
        })

    accuracy = correct / total if total else 0

    category_summary[category] = {
        "correct": correct,
        "total": total,
        "accuracy": accuracy,
        "average_phishing_probability": (
            sum(probabilities) / len(probabilities)
            if probabilities
            else 0
        ),
    }

    print(
        f"\nCategory Result: "
        f"{correct}/{total} correct "
        f"({accuracy * 100:.2f}%)"
    )


# ============================================================
# SAVE RESULTS
# ============================================================

results_df = pd.DataFrame(results)

results_df.to_csv(
    RESULTS_PATH,
    index=False
)


# ============================================================
# OVERALL SUMMARY
# ============================================================

total_correct = int(results_df["correct"].sum())
total_tests = len(results_df)

overall_accuracy = (
    total_correct / total_tests
    if total_tests
    else 0
)

phishing_predictions = int(
    results_df["prediction"].sum()
)

legitimate_predictions = (
    total_tests - phishing_predictions
)


print("\n" + "=" * 75)
print("OVERALL ROBUSTNESS RESULTS")
print("=" * 75)

print(
    f"\nCorrect predictions : "
    f"{total_correct}/{total_tests}"
)

print(
    f"Overall accuracy    : "
    f"{overall_accuracy * 100:.2f}%"
)

print(
    f"Phishing predictions: "
    f"{phishing_predictions}"
)

print(
    f"Legitimate predictions: "
    f"{legitimate_predictions}"
)


# ============================================================
# CATEGORY SUMMARY
# ============================================================

print("\n" + "=" * 75)
print("CATEGORY SUMMARY")
print("=" * 75)

for category, summary in category_summary.items():

    print(
        f"\n{category}"
    )

    print(
        f"  Accuracy : "
        f"{summary['accuracy'] * 100:.2f}%"
    )

    print(
        f"  Correct  : "
        f"{summary['correct']}/{summary['total']}"
    )

    print(
        f"  Avg phishing probability: "
        f"{summary['average_phishing_probability']:.4f}"
    )


# ============================================================
# FAILURE ANALYSIS
# ============================================================

failures = results_df[
    results_df["correct"] == False
]

print("\n" + "=" * 75)
print("FAILURE ANALYSIS")
print("=" * 75)

if failures.empty:

    print("\nNo failures detected.")

else:

    print(
        f"\nTotal failures: {len(failures)}"
    )

    for _, row in failures.iterrows():

        expected_label = (
            "PHISHING"
            if row["expected"] == 1
            else "LEGITIMATE"
        )

        predicted_label = (
            "PHISHING"
            if row["prediction"] == 1
            else "LEGITIMATE"
        )

        print("\nFAIL")
        print(f"  Category  : {row['category']}")
        print(f"  URL       : {row['url']}")
        print(f"  Hostname  : {row['hostname']}")
        print(f"  Expected  : {expected_label}")
        print(f"  Predicted : {predicted_label}")
        print(
            f"  Probability: "
            f"{row['phishing_probability']:.4f}"
        )


# ============================================================
# SAVE JSON SUMMARY
# ============================================================

summary_path = (
    PROJECT_ROOT
    / "model"
    / "hostname_robustness_summary.json"
)

summary = {
    "total_tests": total_tests,
    "correct_predictions": total_correct,
    "overall_accuracy": overall_accuracy,
    "phishing_predictions": phishing_predictions,
    "legitimate_predictions": legitimate_predictions,
    "categories": category_summary,
}

with open(
    summary_path,
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        summary,
        f,
        indent=2
    )


# ============================================================
# FINAL
# ============================================================

print("\n" + "=" * 75)
print("RESULT FILES")
print("=" * 75)

print(
    f"\nCSV    : {RESULTS_PATH}"
)

print(
    f"Summary: {summary_path}"
)

print("\nNext step:")
print(
    "Paste the COMPLETE output here so we can decide "
    "whether to improve the hostname model or build "
    "the ensemble risk engine."
)

print("=" * 75)

