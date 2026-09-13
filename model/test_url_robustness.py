"""
PhishGuard AI - URL Model Robustness Test

Tests the production URL-only model against:
1. Clearly legitimate URLs
2. Clearly suspicious/phishing-style URLs
3. Obfuscated URLs
4. Difficult benign URLs
5. Feature sensitivity / small URL mutations

This is NOT a replacement for a real-world test set.
It is a sanity and robustness check.
"""

from pathlib import Path
import sys

import joblib
import pandas as pd

# ------------------------------------------------------------
# Project root
# ------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from feature_extractor import extract_features


# ------------------------------------------------------------
# Model
# ------------------------------------------------------------

MODEL_PATH = BASE_DIR / "model" / "domain_url_model.pkl"

model = joblib.load(MODEL_PATH)


# ------------------------------------------------------------
# Test URLs
# ------------------------------------------------------------

LEGITIMATE_URLS = [
    "https://www.google.com",
    "https://www.microsoft.com",
    "https://www.github.com",
    "https://github.com/torvalds/linux",
    "https://stackoverflow.com/questions/123456",
    "https://docs.google.com/document/d/123456789",
    "https://www.wikipedia.org/wiki/Computer_security",
    "https://www.python.org/downloads/",
    "https://www.oracle.com/java/",
    "https://www.amazon.com/",
    "https://www.linkedin.com/",
    "https://www.apple.com/",
]


PHISHING_STYLE_URLS = [
    "http://paypal-login.example.com",
    "http://paypal-security.example.com/verify",
    "http://microsoft-account.example.com/login",
    "http://google-security.example.com/verify-account",
    "http://bank-login.example.com/secure/login",
    "http://account-verification.example.com/update",
    "http://secure-login.example.com/authentication",
    "http://password-reset.example.com/verify",
    "http://billing-alert.example.com/update-payment",
    "http://wallet-security.example.com/login",
]


OBFUSCATED_URLS = [
    "http://example.com/%70%61%79%70%61%6C/login",
    "http://example.com/login?redirect=%68%74%74%70%73%3A%2F%2Fexample.com",
    "http://example.com/%2F%2F%2Flogin",
    "http://example.com/login?session=%61%62%63%31%32%33",
    "http://example.com/%6c%6f%67%69%6e",
]


DIFFICULT_BENIGN_URLS = [
    "https://github.com/user/repository/issues/123456",
    "https://github.com/org/project/pull/123/files",
    "https://stackoverflow.com/questions/12345678/how-do-i-fix-this-error",
    "https://docs.google.com/spreadsheets/d/123456789/edit#gid=123",
    "https://www.amazon.com/s?k=wireless+headphones&ref=nav_search",
    "https://en.wikipedia.org/wiki/Artificial_intelligence",
    "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference",
    "https://learn.microsoft.com/en-us/windows/security/",
]


# ------------------------------------------------------------
# Prediction helper
# ------------------------------------------------------------

def predict_url(url):
    features = extract_features(url)

    X = pd.DataFrame([features])

    probability = float(
        model.predict_proba(X)[0][1]
    )

    prediction = int(
        model.predict(X)[0]
    )

    return prediction, probability


def print_results(title, urls):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)

    results = []

    for url in urls:

        try:
            prediction, probability = predict_url(url)

            label = (
                "PHISHING"
                if prediction == 1
                else "LEGITIMATE"
            )

            results.append(
                {
                    "url": url,
                    "prediction": label,
                    "phishing_probability": probability,
                }
            )

            print(
                f"\n[{label:<10}] "
                f"{probability:.4f} "
                f"{url}"
            )

        except Exception as exc:

            print(
                f"\n[ERROR] {url}"
            )

            print(
                f"        {exc}"
            )

    return results


# ------------------------------------------------------------
# Mutation test
# ------------------------------------------------------------

def mutation_test():

    print("\n" + "=" * 70)
    print("URL MUTATION / SENSITIVITY TEST")
    print("=" * 70)

    base_url = "https://example.com/login"

    mutations = [
        base_url,
        "http://example.com/login",
        "https://example.com/login/",
        "https://example.com/login?user=test",
        "https://example.com/login?user=test&session=123456",
        "https://example.com/login/%61%62%63",
        "http://example.com/login?redirect=https://example.com",
        "http://example.com/@login",
        "http://example.com/login/verify/account/password/reset",
    ]

    for url in mutations:

        try:

            prediction, probability = predict_url(url)

            label = (
                "PHISHING"
                if prediction == 1
                else "LEGITIMATE"
            )

            print(
                f"{probability:.4f}  "
                f"{label:<10}  "
                f"{url}"
            )

        except Exception as exc:

            print(
                f"ERROR      {url}"
            )

            print(
                f"           {exc}"
            )


# ------------------------------------------------------------
# Summary
# ------------------------------------------------------------

def summarize(results, expected_label):

    total = len(results)

    if total == 0:
        return

    correct = sum(
        1
        for result in results
        if (
            result["prediction"] == expected_label
        )
    )

    accuracy = correct / total

    print(
        f"\nExpected: {expected_label}"
    )

    print(
        f"Correct:  {correct}/{total}"
    )

    print(
        f"Accuracy: {accuracy:.2%}"
    )


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main():

    print("=" * 70)
    print("PhishGuard AI - URL Model Robustness Testing")
    print("=" * 70)

    print(
        f"\nModel: {MODEL_PATH}"
    )

    # --------------------------------------------------------
    # Legitimate
    # --------------------------------------------------------

    legitimate_results = print_results(
        "LEGITIMATE URL TESTS",
        LEGITIMATE_URLS,
    )

    summarize(
        legitimate_results,
        "LEGITIMATE",
    )

    # --------------------------------------------------------
    # Phishing-style
    # --------------------------------------------------------

    phishing_results = print_results(
        "PHISHING-STYLE URL TESTS",
        PHISHING_STYLE_URLS,
    )

    summarize(
        phishing_results,
        "PHISHING",
    )

    # --------------------------------------------------------
    # Obfuscation
    # --------------------------------------------------------

    obfuscated_results = print_results(
        "OBFUSCATED URL TESTS",
        OBFUSCATED_URLS,
    )

    print(
        "\nNote: These URLs use intentionally synthetic "
        "obfuscation patterns."
    )

    # --------------------------------------------------------
    # Difficult benign
    # --------------------------------------------------------

    difficult_results = print_results(
        "DIFFICULT BENIGN URL TESTS",
        DIFFICULT_BENIGN_URLS,
    )

    summarize(
        difficult_results,
        "LEGITIMATE",
    )

    # --------------------------------------------------------
    # Mutation
    # --------------------------------------------------------

    mutation_test()

    # --------------------------------------------------------
    # Overall
    # --------------------------------------------------------

    all_results = (
        legitimate_results
        + phishing_results
        + difficult_results
    )

    print("\n" + "=" * 70)
    print("ROBUSTNESS TEST COMPLETE")
    print("=" * 70)

    print(
        f"Total manually defined URLs tested: "
        f"{len(all_results)}"
    )

    print(
        "\nIMPORTANT:"
    )

    print(
        "These tests are sanity checks, not a substitute "
        "for an independent real-world phishing dataset."
    )


if __name__ == "__main__":
    main()