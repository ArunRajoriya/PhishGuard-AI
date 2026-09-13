from pathlib import Path
import sys

import joblib
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from feature_extractor import extract_features


MODEL_PATH = ROOT / "model" / "domain_url_model.pkl"


model = joblib.load(MODEL_PATH)


def predict(url):
    features = extract_features(url)
    X = pd.DataFrame([features])

    probability = float(model.predict_proba(X)[0][1])
    prediction = "PHISHING" if probability >= 0.5 else "LEGITIMATE"

    return prediction, probability


TEST_CASES = {

    "LEGITIMATE_MAJOR_SITES": [
        "https://www.google.com",
        "https://www.microsoft.com",
        "https://www.github.com",
        "https://www.apple.com",
        "https://www.amazon.com",
        "https://www.linkedin.com",
        "https://www.python.org",
        "https://www.oracle.com",
        "https://www.wikipedia.org",
    ],

    "LEGITIMATE_COMPLEX_URLS": [
        "https://github.com/torvalds/linux/issues/123",
        "https://github.com/microsoft/vscode/pull/12345",
        "https://stackoverflow.com/questions/12345678/how-do-i-fix-this-error",
        "https://docs.google.com/document/d/123456789/edit",
        "https://docs.google.com/spreadsheets/d/123456789/edit#gid=123",
        "https://www.amazon.com/s?k=wireless+headphones&ref=nav_search",
        "https://en.wikipedia.org/wiki/Artificial_intelligence",
        "https://developer.mozilla.org/en-US/docs/Web/JavaScript",
        "https://learn.microsoft.com/en-us/windows/security/",
    ],

    "SUSPICIOUS_SUBDOMAINS": [
        "https://login.security.example.org",
        "https://account.verify.example.net",
        "https://secure.payment.example.org",
        "https://authentication.portal.example.net",
    ],

    "BRAND_IMPERSONATION": [
        "https://paypal-login.security-check.example.org",
        "https://microsoft-account.verify-user.example.net",
        "https://google-security.authentication.example.org",
        "https://apple-id.verify-account.example.net",
        "https://amazon-payment.confirmation.example.org",
    ],

    "CREDENTIAL_PATTERNS": [
        "http://192.168.1.10/login",
        "http://192.168.1.10/verify/account",
        "http://10.0.0.25/secure/login",
        "http://172.16.0.10/account/password",
    ],

    "OBFUSCATION": [
        "http://example.org/%70%61%79%70%61%6c/login",
        "http://example.org/login?redirect=%68%74%74%70%73%3A%2F%2Fexample.org",
        "http://example.org/%2F%2F%2Flogin",
        "http://example.org/login%2Fverify%2Faccount",
    ],

    "LONG_COMPLEX_URLS": [
        "https://example.org/account/login/verify/security/authentication/password/reset/confirmation",
        "https://example.org/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/login",
        "https://example.org/login?user=test&account=12345&session=abcdef&redirect=/dashboard",
    ],

    "SUSPICIOUS_STRUCTURE": [
        "http://secure-login.example.org/account/verify/password",
        "http://account-security.example.net/login/confirm/identity",
        "http://payment-verification.example.org/billing/update/card",
    ],
}


def run_tests():

    print("=" * 75)
    print("PhishGuard AI - Realistic URL Evaluation")
    print("=" * 75)

    total = 0

    for category, urls in TEST_CASES.items():

        print("\n" + "=" * 75)
        print(category)
        print("=" * 75)

        for url in urls:

            prediction, probability = predict(url)

            print(
                f"[{prediction:<10}] "
                f"{probability:.4f} "
                f"{url}"
            )

            total += 1

    print("\n" + "=" * 75)
    print(f"TOTAL URLS TESTED: {total}")
    print("=" * 75)

    print(
        "\nNOTE:\n"
        "This is a behavioral evaluation, not a labeled benchmark.\n"
        "Synthetic domains are intentionally used to test model behavior,\n"
        "but they must not be treated as real-world phishing ground truth."
    )


if __name__ == "__main__":
    run_tests()