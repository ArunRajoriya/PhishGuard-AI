import sys
from pathlib import Path

import pandas as pd

# Add project root to Python path
PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from feature_extractor import extract_features


OUTPUT = Path("data/processed/adversarial_urls.csv")


# ---------------------------------------------------------
# IMPORTANT:
# These are behavioral training examples.
# They supplement the large public dataset.
# ---------------------------------------------------------

LEGITIMATE_URLS = [
    # Major websites
    "https://www.google.com/",
    "https://www.microsoft.com/",
    "https://www.apple.com/",
    "https://www.amazon.com/",
    "https://www.github.com/",
    "https://www.linkedin.com/",
    "https://www.python.org/",
    "https://www.oracle.com/",
    "https://www.wikipedia.org/",

    # Legitimate deep paths
    "https://www.google.com/search?q=python",
    "https://github.com/ArunRajoriya/PhishGuard-AI",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://learn.microsoft.com/en-us/dotnet/",
    "https://www.amazon.com/s?k=laptop",
    "https://www.linkedin.com/jobs/search/?keywords=software%20engineer",
    "https://en.wikipedia.org/wiki/Computer_science",

    # Legitimate query strings
    "https://www.google.com/search?q=hello",
    "https://www.youtube.com/results?search_query=python",
    "https://github.com/search?q=machine+learning",
    "https://stackoverflow.com/questions/tagged/python",

    # Legitimate long paths
    "https://docs.python.org/3/library/http/client.html",
    "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference",
    "https://learn.microsoft.com/en-us/windows/",
]


PHISHING_URLS = [
    # Brand impersonation
    "https://paypal-login.example.com/verify",
    "https://microsoft-security.example.com/login",
    "https://apple-id.example.com/account/verify",
    "https://google-account.example.com/security",
    "https://amazon-payment.example.com/confirm",
    "https://github-security.example.com/login",

    # Suspicious subdomains
    "https://login.verify.account.example.com/",
    "https://secure.authentication.example.com/",
    "https://account.security.verify.example.com/",
    "https://payment.confirmation.example.com/",
    "https://wallet.recovery.example.com/",

    # Credential harvesting
    "https://example.com/login/password",
    "https://example.com/account/verify/password",
    "https://example.com/secure/authenticate",
    "https://example.com/credential/update",
    "https://example.com/signin/confirm",

    # IP-based phishing
    "http://192.168.1.100/login",
    "http://10.0.0.25/verify/account",
    "http://172.16.0.10/security/login",

    # URL credentials
    "https://user:password@example.com/login",
    "https://admin:password@example.com/verify",

    # Obfuscation / encoding
    "https://example.com/%6c%6f%67%69%6e",
    "https://example.com/login%3Fverify",
    "https://example.com/%70%61%79%70%61%6c/account",

    # Suspicious TLDs
    "https://paypal-login.xyz/verify",
    "https://account-security.top/login",
    "https://secure-payment.click/confirm",
    "https://microsoft-support.zip/account",
    "https://wallet-recovery.work/login",

    # Suspicious structures
    "https://secure-login-account.example.com/verify/payment",
    "https://account-confirmation-security.example.com/login",
    "https://update-billing-payment.example.com/verify",
]


def build_dataset():

    rows = []

    for url in LEGITIMATE_URLS:
        features = extract_features(url)

        rows.append({
            **features,
            "url": url,
            "label": 0,
            "source": "adversarial_legitimate",
        })

    for url in PHISHING_URLS:
        features = extract_features(url)

        rows.append({
            **features,
            "url": url,
            "label": 1,
            "source": "adversarial_phishing",
        })

    df = pd.DataFrame(rows)

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    df.to_csv(
        OUTPUT,
        index=False,
    )

    print("=" * 80)
    print("ADVERSARIAL DATASET")
    print("=" * 80)

    print("Total URLs:", len(df))
    print("Legitimate:", int((df["label"] == 0).sum()))
    print("Phishing:", int((df["label"] == 1).sum()))

    print("\nFeature count:", len([
        c for c in df.columns
        if c not in {"url", "label", "source"}
    ]))

    print("\nSaved:")
    print(OUTPUT)


if __name__ == "__main__":
    build_dataset()