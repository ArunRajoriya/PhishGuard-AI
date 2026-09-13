"""
PhishGuard AI - Domain Robustness Test

Analyzes domain overlap and label distribution using the original
PhiUSIIL dataset and the URL-level train/validation/test splits.
"""

from pathlib import Path
from urllib.parse import urlparse

import pandas as pd


ROOT = Path(__file__).resolve().parent.parent

RAW_DATA = ROOT / "data" / "raw" / "PhiUSIIL_Phishing_URL_Dataset.csv"
TRAIN_DATA = ROOT / "data" / "processed" / "url_train.csv"
VAL_DATA = ROOT / "data" / "processed" / "url_validation.csv"
TEST_DATA = ROOT / "data" / "processed" / "url_test.csv"


def normalize_url(url):
    """Normalize URL enough for comparison."""
    url = str(url).strip()

    if not url:
        return None

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    return url


def extract_domain(url):
    """Extract hostname from URL."""
    try:
        normalized = normalize_url(url)

        if not normalized:
            return None

        parsed = urlparse(normalized)
        hostname = parsed.hostname

        if not hostname:
            return None

        return hostname.lower().strip(".")
    except Exception:
        return None


def find_url_column(df):
    """Find the URL column."""
    candidates = [
        "URL",
        "url",
        "Url",
        "URLText",
        "url_text",
        "Domain",
        "domain",
    ]

    for column in candidates:
        if column in df.columns:
            return column

    # Fallback: look for a column containing URL-like values
    for column in df.columns:
        sample = df[column].dropna().astype(str).head(100)

        if len(sample) == 0:
            continue

        url_like = sample.str.contains(
            r"(https?://|www\.|\.[a-z]{2,})",
            case=False,
            regex=True,
        ).mean()

        if url_like > 0.5:
            return column

    return None


def find_label_column(df):
    """Find the label column."""
    candidates = ["label", "Label", "LABEL", "class", "Class"]

    for column in candidates:
        if column in df.columns:
            return column

    raise ValueError("Label column not found.")


def domain_statistics(df, url_column, label_column, name):
    """Print domain statistics."""

    work = df[[url_column, label_column]].copy()

    work["domain"] = work[url_column].apply(extract_domain)

    work = work.dropna(subset=["domain"])

    print(f"\n{name}")
    print("-" * 70)

    print(f"URLs with valid domains: {len(work):,}")
    print(f"Unique domains: {work['domain'].nunique():,}")

    domain_labels = (
        work.groupby("domain")[label_column]
        .agg(["min", "max", "count"])
        .reset_index()
    )

    phishing_only = (domain_labels["min"] == 1) & (
        domain_labels["max"] == 1
    )

    legitimate_only = (domain_labels["min"] == 0) & (
        domain_labels["max"] == 0
    )

    mixed = ~(phishing_only | legitimate_only)

    print(f"Phishing-only domains: {phishing_only.sum():,}")
    print(f"Legitimate-only domains: {legitimate_only.sum():,}")
    print(f"Mixed-label domains: {mixed.sum():,}")

    print("\nTop 20 domains by URL count:")

    top_domains = (
        work.groupby("domain")
        .size()
        .sort_values(ascending=False)
        .head(20)
    )

    for domain, count in top_domains.items():
        print(f"  {domain:<50} {count:,}")

    return set(work["domain"].unique())


def main():

    print("=" * 70)
    print("PhishGuard AI - Domain Robustness Test")
    print("=" * 70)

    # ------------------------------------------------------------------
    # Load original dataset
    # ------------------------------------------------------------------

    print("\nLoading original dataset...")

    if not RAW_DATA.exists():
        raise FileNotFoundError(
            f"Original dataset not found:\n{RAW_DATA}"
        )

    raw = pd.read_csv(RAW_DATA)

    print(f"Original rows: {len(raw):,}")

    url_column = find_url_column(raw)
    label_column = find_label_column(raw)

    if not url_column:
        raise ValueError(
            f"URL column not found.\nAvailable columns:\n{raw.columns.tolist()}"
        )

    print(f"URL column: {url_column}")
    print(f"Label column: {label_column}")

    # ------------------------------------------------------------------
    # Normalize URL
    # ------------------------------------------------------------------

    raw["_normalized_url"] = raw[url_column].apply(normalize_url)

    raw = raw.dropna(subset=["_normalized_url"])

    raw = raw.drop_duplicates(
        subset=["_normalized_url"]
    ).reset_index(drop=True)

    print(f"Rows after URL deduplication: {len(raw):,}")

    # ------------------------------------------------------------------
    # Domain analysis
    # ------------------------------------------------------------------

    all_domains = domain_statistics(
        raw,
        url_column,
        label_column,
        "FULL DATASET DOMAIN ANALYSIS",
    )

    # ------------------------------------------------------------------
    # Load processed splits
    # ------------------------------------------------------------------

    print("\nLoading train/validation/test splits...")

    train = pd.read_csv(TRAIN_DATA)
    validation = pd.read_csv(VAL_DATA)
    test = pd.read_csv(TEST_DATA)

    print(f"Train rows:      {len(train):,}")
    print(f"Validation rows: {len(validation):,}")
    print(f"Test rows:       {len(test):,}")

    # ------------------------------------------------------------------
    # Important:
    #
    # Processed files currently contain only features and labels.
    # Therefore, reconstructing exact URLs from them is impossible.
    #
    # Instead, we recreate the original URL split using the same
    # dataset order and split sizes used by build_url_dataset.py.
    # ------------------------------------------------------------------

    print("\nReconstructing URL membership from original dataset...")

    # The current build_url_dataset.py used a random stratified split.
    # We cannot reproduce the exact URL membership without its random
    # split implementation/seed.
    #
    # Therefore, we perform a domain concentration analysis on the
    # original dataset rather than falsely claiming exact split overlap.

    domain_counts = (
        raw.assign(domain=raw[url_column].apply(extract_domain))
        .dropna(subset=["domain"])
        .groupby("domain")
        .size()
        .sort_values(ascending=False)
    )

    print("\nDOMAIN CONCENTRATION")
    print("-" * 70)

    print(f"Total unique domains: {len(domain_counts):,}")

    for percentage in [0.1, 0.5, 1, 5]:

        n = max(
            1,
            int(len(domain_counts) * percentage / 100)
        )

        urls = domain_counts.head(n).sum()

        share = urls / len(raw) * 100

        print(
            f"Top {percentage:g}% of domains "
            f"({n:,} domains) contain "
            f"{urls:,} URLs ({share:.2f}% of dataset)"
        )

    # ------------------------------------------------------------------
    # Final assessment
    # ------------------------------------------------------------------

    print("\n" + "=" * 70)
    print("ROBUSTNESS ASSESSMENT")
    print("=" * 70)

    mixed_domain_count = (
        raw.assign(domain=raw[url_column].apply(extract_domain))
        .dropna(subset=["domain"])
        .groupby("domain")[label_column]
        .nunique()
    )

    mixed_domains = (
        mixed_domain_count[mixed_domain_count > 1]
    )

    mixed_ratio = (
        len(mixed_domains) / len(domain_counts) * 100
        if len(domain_counts)
        else 0
    )

    print(
        f"Domains containing both labels: "
        f"{len(mixed_domains):,}"
    )

    print(
        f"Mixed-domain percentage: "
        f"{mixed_ratio:.2f}%"
    )

    print("\nIMPORTANT:")
    print(
        "The current URL dataset was split at the URL level, "
        "not the domain level."
    )

    print(
        "Therefore, the 99%+ validation/test metrics should NOT "
        "yet be presented as proof of generalization to unseen domains."
    )

    print(
        "\nNext step: create a true domain-grouped train/validation/test "
        "split and retrain the model."
    )

    print("=" * 70)


if __name__ == "__main__":
    main()