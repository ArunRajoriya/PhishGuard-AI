"""
PhishGuard AI - URL-only Dataset Builder

Converts the raw PhiUSIIL dataset into a dataset containing only
features that can be calculated directly from a URL.

Important:
- No webpage features are used.
- Duplicate normalized URLs are removed before splitting.
- Train/validation/test are split after deduplication.
"""

import os
import sys

import pandas as pd
from sklearn.model_selection import train_test_split

# Allow importing feature_extractor.py from project root.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from feature_extractor import extract_features


RAW_DATA = os.path.join(
    PROJECT_ROOT,
    "data",
    "raw",
    "PhiUSIIL_Phishing_URL_Dataset.csv",
)

OUTPUT_DIR = os.path.join(
    PROJECT_ROOT,
    "data",
    "processed",
)


def normalize_url(url: str) -> str:
    """
    Normalize URL for duplicate detection.

    This is NOT used as the model input.
    """

    url = str(url).strip().lower()

    # Remove trailing slash.
    if url.endswith("/"):
        url = url[:-1]

    return url


def main():
    print("=" * 70)
    print("PhishGuard AI - URL-only Dataset Builder")
    print("=" * 70)

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("\nLoading raw dataset...")

    df = pd.read_csv(RAW_DATA)

    print(f"Original rows: {len(df):,}")

    # Validate required columns.
    required_columns = {"URL", "label"}

    missing = required_columns - set(df.columns)

    if missing:
        raise ValueError(
            f"Missing required columns: {sorted(missing)}"
        )

    # Keep only required columns.
    df = df[["URL", "label"]].copy()

    # Remove missing URLs.
    df["URL"] = df["URL"].astype(str).str.strip()

    df = df[
        (df["URL"] != "")
        & (df["URL"].str.lower() != "nan")
    ].copy()

    print(f"After removing invalid URLs: {len(df):,}")

    # Normalize only for duplicate detection.
    df["normalized_url"] = df["URL"].apply(normalize_url)

    before_duplicates = len(df)

    df = df.drop_duplicates(
        subset=["normalized_url"],
        keep="first",
    ).copy()

    print(
        f"Duplicate URLs removed: "
        f"{before_duplicates - len(df):,}"
    )

    # Validate labels.
    df["label"] = pd.to_numeric(
        df["label"],
        errors="coerce",
    )

    df = df[df["label"].isin([0, 1])].copy()

    df["label"] = df["label"].astype(int)

    print(f"Final URLs: {len(df):,}")

    print("\nLabel distribution:")

    print(
        df["label"]
        .value_counts()
        .sort_index()
        .rename(
            index={
                0: "Legitimate",
                1: "Phishing",
            }
        )
    )

    # ------------------------------------------------------------
    # Feature extraction
    # ------------------------------------------------------------

    print("\nExtracting URL-only features...")
    print("This may take a little while...")

    feature_rows = []

    total = len(df)

    for index, url in enumerate(df["URL"], start=1):

        features = extract_features(url)

        feature_rows.append(features)

        if index % 10000 == 0 or index == total:
            print(
                f"  Processed {index:,}/{total:,}"
            )

    features_df = pd.DataFrame(feature_rows)

    # Add labels.
    features_df["label"] = df["label"].values

    # Save complete URL-only dataset.
    full_output = os.path.join(
        OUTPUT_DIR,
        "url_only.csv",
    )

    features_df.to_csv(
        full_output,
        index=False,
    )

    print(
        f"\nSaved URL-only dataset:\n"
        f"{full_output}"
    )

    print(
        f"Feature count: "
        f"{len(features_df.columns) - 1}"
    )

    # ------------------------------------------------------------
    # Train / validation / test split
    # ------------------------------------------------------------

    X = features_df.drop(columns=["label"])
    y = features_df["label"]

    # 70% train, 15% validation, 15% test.
    X_train, X_temp, y_train, y_temp = train_test_split(
        X,
        y,
        test_size=0.30,
        random_state=42,
        stratify=y,
    )

    X_validation, X_test, y_validation, y_test = train_test_split(
        X_temp,
        y_temp,
        test_size=0.50,
        random_state=42,
        stratify=y_temp,
    )

    train_df = X_train.copy()
    train_df["label"] = y_train.values

    validation_df = X_validation.copy()
    validation_df["label"] = y_validation.values

    test_df = X_test.copy()
    test_df["label"] = y_test.values

    train_path = os.path.join(
        OUTPUT_DIR,
        "url_train.csv",
    )

    validation_path = os.path.join(
        OUTPUT_DIR,
        "url_validation.csv",
    )

    test_path = os.path.join(
        OUTPUT_DIR,
        "url_test.csv",
    )

    train_df.to_csv(
        train_path,
        index=False,
    )

    validation_df.to_csv(
        validation_path,
        index=False,
    )

    test_df.to_csv(
        test_path,
        index=False,
    )

    print("\nDataset split:")
    print(f"Train      : {len(train_df):,}")
    print(f"Validation : {len(validation_df):,}")
    print(f"Test       : {len(test_df):,}")

    print("\nSaved:")
    print(f"  {train_path}")
    print(f"  {validation_path}")
    print(f"  {test_path}")

    print("\n" + "=" * 70)
    print("Dataset preparation completed successfully.")
    print("=" * 70)


if __name__ == "__main__":
    main()