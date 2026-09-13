import sys
from pathlib import Path

import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

# Add project root to Python path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from feature_extractor import extract_features


RAW_DATA = PROJECT_ROOT / "data" / "raw" / "PhiUSIIL_Phishing_URL_Dataset.csv"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"

URL_COLUMN = "URL"
LABEL_COLUMN = "label"


def normalize_url(url):
    if not isinstance(url, str):
        return ""

    return url.strip().lower()


def get_domain(url):
    from urllib.parse import urlparse

    try:
        normalized = url

        if "://" not in normalized:
            normalized = "https://" + normalized

        hostname = urlparse(normalized).hostname

        if not hostname:
            return ""

        return hostname.lower().rstrip(".")

    except Exception:
        return ""


def build_features(df):
    rows = []

    for index, url in enumerate(df[URL_COLUMN]):
        if index % 25000 == 0:
            print(f"Extracting features: {index:,}/{len(df):,}")

        try:
            features = extract_features(url)
            rows.append(features)
        except Exception:
            rows.append(None)

    feature_df = pd.DataFrame(rows)

    valid_mask = feature_df.notna().all(axis=1)

    feature_df = feature_df.loc[valid_mask].reset_index(drop=True)

    labels = df.loc[valid_mask, LABEL_COLUMN].reset_index(drop=True)

    urls = df.loc[valid_mask, URL_COLUMN].reset_index(drop=True)

    domains = urls.map(get_domain)

    result = feature_df.copy()
    result["label"] = labels.astype(int)
    result["url"] = urls
    result["domain"] = domains

    return result


def main():

    print("=" * 75)
    print("PhishGuard AI - Production URL Dataset Builder")
    print("=" * 75)

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    print("\nLoading dataset...")

    df = pd.read_csv(RAW_DATA)

    print(f"Original rows: {len(df):,}")

    # Keep only required columns.
    df = df[[URL_COLUMN, LABEL_COLUMN]].copy()

    # Normalize URLs.
    df[URL_COLUMN] = df[URL_COLUMN].astype(str).map(normalize_url)

    # Remove empty URLs.
    df = df[df[URL_COLUMN] != ""].copy()

    # Remove duplicate URLs.
    before = len(df)

    df = df.drop_duplicates(
        subset=[URL_COLUMN]
    ).reset_index(drop=True)

    print(
        f"Duplicate URLs removed: "
        f"{before - len(df):,}"
    )

    print(
        f"Rows after URL deduplication: "
        f"{len(df):,}"
    )

    print("\nBuilding production features...")

    data = build_features(df)

    print(
        f"\nFinal usable rows: "
        f"{len(data):,}"
    )

    print(
        f"Feature count: "
        f"{len([
            c for c in data.columns
            if c not in {'label', 'url', 'domain'}
        ])}"
    )

    print("\nLabel distribution:")

    print(
        data["label"]
        .value_counts()
        .sort_index()
        .rename(
            index={
                0: "Legitimate",
                1: "Phishing",
            }
        )
    )

    # Remove rows without a valid domain.
    data = data[data["domain"] != ""].reset_index(drop=True)

    print(
        f"\nRows with valid domains: "
        f"{len(data):,}"
    )

    # ---------------------------------------------------------
    # DOMAIN-GROUPED SPLIT
    # ---------------------------------------------------------

    X = data.drop(
        columns=["label", "url", "domain"]
    )

    y = data["label"]

    groups = data["domain"]

    # First: train 70%, temp 30%.
    splitter_1 = GroupShuffleSplit(
        n_splits=1,
        test_size=0.30,
        random_state=42,
    )

    train_idx, temp_idx = next(
        splitter_1.split(
            X,
            y,
            groups=groups,
        )
    )

    train = data.iloc[train_idx].copy()
    temp = data.iloc[temp_idx].copy()

    # Second: validation/test = 15% / 15%.
    splitter_2 = GroupShuffleSplit(
        n_splits=1,
        test_size=0.50,
        random_state=42,
    )

    val_idx, test_idx = next(
        splitter_2.split(
            temp.drop(columns=["label", "url", "domain"]),
            temp["label"],
            groups=temp["domain"],
        )
    )

    validation = temp.iloc[val_idx].copy()
    test = temp.iloc[test_idx].copy()

    # Save datasets.
    train.to_csv(
        PROCESSED_DIR / "domain_train.csv",
        index=False,
    )

    validation.to_csv(
        PROCESSED_DIR / "domain_validation.csv",
        index=False,
    )

    test.to_csv(
        PROCESSED_DIR / "domain_test.csv",
        index=False,
    )

    # Also save the complete production feature dataset.
    data.to_csv(
        PROCESSED_DIR / "url_features.csv",
        index=False,
    )

    print("\n" + "=" * 75)
    print("DOMAIN SPLIT")
    print("=" * 75)

    for name, split in [
        ("Train", train),
        ("Validation", validation),
        ("Test", test),
    ]:

        print(
            f"{name:12s}: "
            f"{len(split):,} rows | "
            f"{split['domain'].nunique():,} domains"
        )

        print(
            split["label"]
            .value_counts(normalize=True)
            .sort_index()
            .rename(
                index={
                    0: "Legitimate",
                    1: "Phishing",
                }
            )
            .round(4)
            .to_dict()
        )

    # Verify domain isolation.
    train_domains = set(train["domain"])
    validation_domains = set(validation["domain"])
    test_domains = set(test["domain"])

    print("\nDomain overlap checks:")

    print(
        "Train ↔ Validation:",
        len(train_domains & validation_domains),
    )

    print(
        "Train ↔ Test:",
        len(train_domains & test_domains),
    )

    print(
        "Validation ↔ Test:",
        len(validation_domains & test_domains),
    )

    print("\nFiles saved:")

    print(PROCESSED_DIR / "domain_train.csv")
    print(PROCESSED_DIR / "domain_validation.csv")
    print(PROCESSED_DIR / "domain_test.csv")
    print(PROCESSED_DIR / "url_features.csv")


if __name__ == "__main__":
    main()