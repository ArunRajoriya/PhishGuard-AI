"""
Build a robustness-aware training dataset for PhishGuard AI.

Input:
    data/processed/domain_train.csv
    data/processed/domain_validation.csv
    data/processed/domain_test.csv

Output:
    data/processed/robust_train.csv
    data/processed/robust_validation.csv
    data/processed/robust_test.csv

Important:
- Original domain-based train/validation/test splits are preserved.
- Augmentation is applied independently within each split.
- No generated samples are moved between splits.
- Mutations are label-preserving.
- Synthetic hard examples have explicit labels.
"""

from __future__ import annotations

import hashlib
import random
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import pandas as pd
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from feature_extractor import FEATURE_NAMES, extract_features
from utils.url_normalizer import normalize_url


# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------

RANDOM_SEED = 42

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data" / "processed"

TRAIN_INPUT = DATA_DIR / "domain_train.csv"
VALIDATION_INPUT = DATA_DIR / "domain_validation.csv"
TEST_INPUT = DATA_DIR / "domain_test.csv"

TRAIN_OUTPUT = DATA_DIR / "robust_train.csv"
VALIDATION_OUTPUT = DATA_DIR / "robust_validation.csv"
TEST_OUTPUT = DATA_DIR / "robust_test.csv"

# Keep augmentation controlled. We don't want the generated dataset
# to become unnecessarily huge.
TRAIN_MUTATIONS_PER_URL = 2
VALIDATION_MUTATIONS_PER_URL = 1
TEST_MUTATIONS_PER_URL = 1

MAX_SYNTHETIC_HARD_NEGATIVES = 10000
MAX_SYNTHETIC_HARD_POSITIVES = 5000

random.seed(RANDOM_SEED)


# ---------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------

def stable_seed(value: str) -> int:
    """Generate a deterministic integer seed from a string."""
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return int(digest[:8], 16)


def safe_normalize(url: str) -> str | None:
    """Normalize a URL without crashing the augmentation pipeline."""
    try:
        return normalize_url(url)
    except (TypeError, ValueError):
        return None


def mutate_url(url: str, mutation: str) -> str | None:
    """
    Apply a label-preserving URL mutation.

    These mutations should not change whether the underlying URL/domain
    belongs to the original class.
    """
    normalized = safe_normalize(url)

    if normalized is None:
        return None

    parsed = urlsplit(normalized)

    scheme = parsed.scheme
    netloc = parsed.netloc
    path = parsed.path
    query = parsed.query
    fragment = parsed.fragment

    if mutation == "toggle_scheme":
        scheme = "http" if scheme == "https" else "https"

    elif mutation == "add_www":
        hostname = parsed.hostname or ""

        if hostname and not hostname.startswith("www."):
            username = parsed.username
            password = parsed.password
            port = parsed.port

            userinfo = ""
            if username is not None:
                userinfo = username
                if password is not None:
                    userinfo += f":{password}"
                userinfo += "@"

            host = f"www.{hostname}"

            if ":" in host and not host.startswith("["):
                host = f"[{host}]"

            if port is not None:
                host = f"{host}:{port}"

            netloc = userinfo + host

    elif mutation == "remove_www":
        hostname = parsed.hostname or ""

        if hostname.startswith("www."):
            hostname = hostname[4:]

            username = parsed.username
            password = parsed.password
            port = parsed.port

            userinfo = ""
            if username is not None:
                userinfo = username
                if password is not None:
                    userinfo += f":{password}"
                userinfo += "@"

            host = hostname

            if ":" in host and not host.startswith("["):
                host = f"[{host}]"

            if port is not None:
                host = f"{host}:{port}"

            netloc = userinfo + host

    elif mutation == "trailing_slash":
        if path:
            if not path.endswith("/"):
                path += "/"
            elif path != "/":
                path = path.rstrip("/")

        else:
            path = "/"

    elif mutation == "simple_query":
        params = parse_qsl(query, keep_blank_values=True)

        if not any(key == "ref" for key, _ in params):
            params.append(("ref", "phishguard"))

        query = urlencode(params)

    elif mutation == "fragment":
        fragment = "section"

    elif mutation == "safe_path":
        if not path or path == "/":
            path = "/home"
        elif path.endswith("/"):
            path = path + "home"
        else:
            path = path + "/home"

    elif mutation == "remove_query":
        query = ""

    elif mutation == "remove_fragment":
        fragment = ""

    else:
        return None

    mutated = urlunsplit(
        (
            scheme,
            netloc,
            path,
            query,
            fragment,
        )
    )

    return safe_normalize(mutated)


# ---------------------------------------------------------------------
# Label-preserving mutations
# ---------------------------------------------------------------------

MUTATIONS = [
    "toggle_scheme",
    "add_www",
    "remove_www",
    "trailing_slash",
    "simple_query",
    "fragment",
    "safe_path",
    "remove_query",
    "remove_fragment",
]


def generate_mutations(
    url: str,
    number: int,
    seed: int,
) -> list[str]:
    """Generate deterministic unique mutations for a URL."""
    if not isinstance(url, str):
        return []

    rng = random.Random(seed)

    candidates = MUTATIONS.copy()
    rng.shuffle(candidates)

    results: list[str] = []
    original = safe_normalize(url)

    if original is None:
        return results

    for mutation in candidates:
        mutated = mutate_url(original, mutation)

        if not mutated:
            continue

        if mutated == original:
            continue

        if mutated not in results:
            results.append(mutated)

        if len(results) >= number:
            break

    return results


# ---------------------------------------------------------------------
# Synthetic hard negatives
# ---------------------------------------------------------------------

LEGITIMATE_DOMAINS = [
    # Major technology
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "github.com",
    "linkedin.com",
    "oracle.com",
    "cloudflare.com",
    "mozilla.org",
    "ubuntu.com",
    "debian.org",
    "docker.com",
    "kubernetes.io",

    # Developer / technical
    "python.org",
    "pypi.org",
    "npmjs.com",
    "stackoverflow.com",
    "postgresql.org",
    "mysql.com",
    "redis.io",
    "nodejs.org",
    "rust-lang.org",
    "golang.org",
    "java.com",

    # Education / knowledge
    "mit.edu",
    "stanford.edu",
    "harvard.edu",
    "berkeley.edu",
    "cmu.edu",
    "wikipedia.org",
    "archive.org",
    "ietf.org",
    "w3.org",

    # Productivity / collaboration
    "slack.com",
    "zoom.us",
    "dropbox.com",
    "notion.so",
    "trello.com",
    "atlassian.com",
    "figma.com",
    "canva.com",

    # Payments / finance
    "paypal.com",
    "stripe.com",
    "visa.com",
    "mastercard.com",

    # Popular services
    "reddit.com",
    "discord.com",
    "spotify.com",
    "netflix.com",
    "youtube.com",
]


LEGITIMATE_PATHS = [
    "/",
    "/login",
    "/signin",
    "/sign-in",
    "/account",
    "/account/login",
    "/account/security",
    "/security",
    "/security/verify",
    "/authentication",
    "/password/reset",
    "/support",
    "/support/security",
    "/help",
    "/help/account",
    "/settings",
    "/settings/security",
    "/profile",
    "/user/account",
    "/billing",
    "/billing/verify",
    "/checkout",
    "/checkout/verify",
    "/privacy",
    "/terms",
    "/about",
    "/contact",
    "/docs",
    "/documentation",
    "/search",
    "/products",
    "/services",
]

def build_hard_negative_urls(limit: int) -> list[tuple[str, int, str]]:
    """
    Create legitimate URLs that intentionally contain phishing-like
    lexical and structural patterns.

    These examples are explicitly labeled legitimate because their
    registered domains belong to a controlled trusted-domain set.

    The goal is to teach the ML model that:

        HTTPS != phishing
        /login != phishing
        /verify != phishing
        /security/verify != phishing
        /account/security != phishing

    when the underlying domain is legitimate.
    """

    results: list[tuple[str, int, str]] = []

    for domain in LEGITIMATE_DOMAINS:

        for path in LEGITIMATE_PATHS:

            variants = [
                f"https://{domain}{path}",
                f"https://www.{domain}{path}",
                f"https://{domain}{path}?verify=true",
                f"https://www.{domain}{path}?account=12345",
                f"https://{domain}{path}?page=2",
                f"https://www.{domain}{path}?page=2&sort=latest",
            ]

            for url in variants:

                normalized = safe_normalize(url)

                if normalized is None:
                    continue

                results.append(
                    (
                        normalized,
                        0,
                        "hard_negative_legitimate_domain",
                    )
                )

                if len(results) >= limit:
                    return results

    return results
# ---------------------------------------------------------------------
# Synthetic hard positives
# ---------------------------------------------------------------------

PHISHING_DOMAINS = [
    "paypal-security.example.com",
    "microsoft-account.example.com",
    "google-login.example.com",
    "apple-id.example.com",
    "amazon-security.example.com",
    "github-auth.example.com",
    "linkedin-login.example.com",
    "bank-verification.example.com",
    "secure-account.example.com",
    "account-confirm.example.com",
]


PHISHING_PATHS = [
    "/login",
    "/signin",
    "/verify",
    "/account/verify",
    "/security/verify",
    "/password/reset",
    "/billing/verify",
    "/payment/confirm",
    "/identity/check",
    "/session/validate",
]


def build_hard_positive_urls(limit: int) -> list[tuple[str, int, str]]:
    """
    Create controlled phishing-style URLs.

    Label = 1 because the hostname intentionally represents a
    third-party impersonation domain.
    """
    results: list[tuple[str, int, str]] = []

    for domain in PHISHING_DOMAINS:
        for path in PHISHING_PATHS:
            urls = [
                f"http://{domain}{path}",
                f"https://{domain}{path}",
                f"https://www.{domain}{path}",
                f"https://{domain}{path}?token=123456",
                f"https://{domain}{path}?verify=true&account=12345",
            ]

            for url in urls:
                results.append(
                    (
                        normalize_url(url),
                        1,
                        "hard_positive_impersonation_domain",
                    )
                )

                if len(results) >= limit:
                    return results

    return results


# ---------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------

def extract_feature_row(url: str) -> dict:
    """Extract the same 40 features used by the production model."""
    features = extract_features(url)

    if set(features.keys()) != set(FEATURE_NAMES):
        missing = set(FEATURE_NAMES) - set(features.keys())
        extra = set(features.keys()) - set(FEATURE_NAMES)

        raise ValueError(
            f"Feature schema mismatch. Missing={missing}, Extra={extra}"
        )

    return features


def create_record(
    url: str,
    label: int,
    source: str,
    original_url: str | None = None,
) -> dict | None:
    """Create a complete training row."""
    normalized = safe_normalize(url)

    if normalized is None:
        return None

    try:
        features = extract_feature_row(normalized)
    except Exception as exc:
        print(f"[WARN] Feature extraction failed for {normalized}: {exc}")
        return None

    record = dict(features)

    record["label"] = int(label)
    record["url"] = normalized

    if original_url is None:
        original_url = normalized

    record["original_url"] = original_url
    record["augmentation_source"] = source

    return record


# ---------------------------------------------------------------------
# Robust split builder
# ---------------------------------------------------------------------

def build_robust_split(
    input_path: Path,
    output_path: Path,
    mutation_count: int,
    add_synthetic_examples: bool,
) -> None:
    print()
    print("=" * 80)
    print(f"Building: {output_path.name}")
    print("=" * 80)

    df = pd.read_csv(input_path)

    required_columns = set(FEATURE_NAMES + ["label", "url", "domain"])

    missing = required_columns - set(df.columns)

    if missing:
        raise ValueError(
            f"{input_path} is missing required columns: {sorted(missing)}"
        )

    print(f"Original rows: {len(df):,}")

    records: list[dict] = []
    seen_urls: set[str] = set()

    # ---------------------------------------------------------------
    # 1. Preserve original samples
    # ---------------------------------------------------------------

    for row in df.itertuples(index=False):
        url = getattr(row, "url")
        label = int(getattr(row, "label"))

        normalized = safe_normalize(url)

        if normalized is None:
            continue

        if normalized in seen_urls:
            continue

        record = create_record(
            normalized,
            label,
            "original",
            normalized,
        )

        if record is not None:
            records.append(record)
            seen_urls.add(normalized)

    print(f"Original valid unique URLs: {len(records):,}")

    # ---------------------------------------------------------------
    # 2. Generate label-preserving mutations
    # ---------------------------------------------------------------

    mutation_records = 0

    for row in df.itertuples(index=False):
        url = getattr(row, "url")
        label = int(getattr(row, "label"))

        normalized = safe_normalize(url)

        if normalized is None:
            continue

        seed = stable_seed(normalized)

        mutations = generate_mutations(
            normalized,
            mutation_count,
            seed,
        )

        for mutated_url in mutations:
            if mutated_url in seen_urls:
                continue

            record = create_record(
                mutated_url,
                label,
                "label_preserving_mutation",
                normalized,
            )

            if record is None:
                continue

            records.append(record)
            seen_urls.add(mutated_url)
            mutation_records += 1

    print(f"Mutation rows added: {mutation_records:,}")

    # ---------------------------------------------------------------
    # 3. Controlled hard examples
    # ---------------------------------------------------------------

    if add_synthetic_examples:
        hard_negatives = build_hard_negative_urls(
            MAX_SYNTHETIC_HARD_NEGATIVES
        )

        hard_positives = build_hard_positive_urls(
            MAX_SYNTHETIC_HARD_POSITIVES
        )

        synthetic_added = 0

        for url, label, source in hard_negatives + hard_positives:
            if url in seen_urls:
                continue

            record = create_record(
                url,
                label,
                source,
                url,
            )

            if record is None:
                continue

            records.append(record)
            seen_urls.add(url)
            synthetic_added += 1

        print(f"Synthetic hard examples added: {synthetic_added:,}")

    # ---------------------------------------------------------------
    # 4. Build final dataframe
    # ---------------------------------------------------------------

    robust_df = pd.DataFrame(records)

    if robust_df.empty:
        raise RuntimeError("No training records were generated.")

    # Ensure the exact production feature order.
    final_columns = (
        FEATURE_NAMES
        + [
            "label",
            "url",
            "original_url",
            "augmentation_source",
        ]
    )

    robust_df = robust_df[final_columns]

    # Final deduplication.
    robust_df = robust_df.drop_duplicates(
        subset=["url"],
        keep="first",
    ).reset_index(drop=True)

    # Shuffle deterministically.
    robust_df = robust_df.sample(
        frac=1.0,
        random_state=RANDOM_SEED,
    ).reset_index(drop=True)

    # ---------------------------------------------------------------
    # 5. Validation checks
    # ---------------------------------------------------------------

    if list(robust_df.columns[: len(FEATURE_NAMES)]) != FEATURE_NAMES:
        raise ValueError("Feature column order does not match FEATURE_NAMES.")

    if robust_df[FEATURE_NAMES].isnull().any().any():
        raise ValueError("NaN values detected in feature matrix.")

    if robust_df["url"].duplicated().any():
        raise ValueError("Duplicate URLs remain after deduplication.")

    print()
    print("Final dataset:")
    print(f"Rows: {len(robust_df):,}")
    print(
        "Label distribution:"
    )
    print(
        robust_df["label"]
        .value_counts()
        .sort_index()
        .rename(index={0: "Legitimate", 1: "Phishing"})
    )

    print()
    print("Augmentation distribution:")
    print(robust_df["augmentation_source"].value_counts())

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    robust_df.to_csv(
        output_path,
        index=False,
    )

    print()
    print(f"Saved: {output_path}")


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def main() -> None:
    print("=" * 80)
    print("PHISHGUARD AI — ROBUST TRAINING DATA BUILDER")
    print("=" * 80)

    print(f"Project root: {BASE_DIR}")
    print(f"Data directory: {DATA_DIR}")

    required_inputs = [
        TRAIN_INPUT,
        VALIDATION_INPUT,
        TEST_INPUT,
    ]

    for path in required_inputs:
        if not path.exists():
            raise FileNotFoundError(
                f"Required dataset not found: {path}"
            )

    # ---------------------------------------------------------------
    # Training
    # ---------------------------------------------------------------

    build_robust_split(
        input_path=TRAIN_INPUT,
        output_path=TRAIN_OUTPUT,
        mutation_count=TRAIN_MUTATIONS_PER_URL,
        add_synthetic_examples=True,
    )

    # ---------------------------------------------------------------
    # Validation
    # ---------------------------------------------------------------

    build_robust_split(
        input_path=VALIDATION_INPUT,
        output_path=VALIDATION_OUTPUT,
        mutation_count=VALIDATION_MUTATIONS_PER_URL,
        add_synthetic_examples=False,
    )

    # ---------------------------------------------------------------
    # Test
    # ---------------------------------------------------------------

    build_robust_split(
        input_path=TEST_INPUT,
        output_path=TEST_OUTPUT,
        mutation_count=TEST_MUTATIONS_PER_URL,
        add_synthetic_examples=False,
    )

    print()
    print("=" * 80)
    print("ROBUST DATASET BUILD COMPLETE")
    print("=" * 80)

    print()
    print("Generated files:")
    print(f"  {TRAIN_OUTPUT}")
    print(f"  {VALIDATION_OUTPUT}")
    print(f"  {TEST_OUTPUT}")

    print()
    print("Next step:")
    print("  python model/train_domain_models.py")


if __name__ == "__main__":
    main()

