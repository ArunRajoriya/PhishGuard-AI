from pathlib import Path
import pandas as pd
from sklearn.model_selection import train_test_split


# --------------------------------------------------
# Configuration
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = BASE_DIR / "data" / "raw" / "PhiUSIIL_Phishing_URL_Dataset.csv"
OUTPUT_DIR = BASE_DIR / "data" / "processed"

RANDOM_STATE = 42


# --------------------------------------------------
# Load dataset
# --------------------------------------------------

def load_dataset():
    print("Loading dataset...")
    df = pd.read_csv(INPUT_FILE)

    print(f"Initial shape: {df.shape}")
    return df


# --------------------------------------------------
# Basic cleaning
# --------------------------------------------------

def clean_dataset(df):
    print("\nCleaning dataset...")

    # Remove completely empty rows
    df = df.dropna(how="all")

    # Remove duplicate rows
    before = len(df)
    df = df.drop_duplicates()
    print(f"Removed duplicate rows: {before - len(df)}")

    # Normalize column names
    df.columns = (
        df.columns
        .str.strip()
        .str.replace(" ", "_")
    )

    # Ensure label exists
    if "label" not in df.columns:
        raise ValueError("Dataset must contain a 'label' column.")

    # Convert label to numeric
    df["label"] = pd.to_numeric(df["label"], errors="coerce")

    # Remove invalid labels
    df = df[df["label"].isin([0, 1])]

    # Convert feature columns to numeric where possible
    feature_columns = [c for c in df.columns if c != "label"]

    for column in feature_columns:
        df[column] = pd.to_numeric(df[column], errors="coerce")

    # Replace infinite values
    df = df.replace([float("inf"), float("-inf")], pd.NA)

    # Remove columns that are completely empty
    empty_columns = [
        column
        for column in df.columns
        if df[column].isna().all()
    ]

    if empty_columns:
        print("Removing empty columns:", empty_columns)
        df = df.drop(columns=empty_columns)

    # Fill numerical missing values using median
    numerical_columns = df.select_dtypes(
        include=["number"]
    ).columns

    for column in numerical_columns:
        if column != "label":
            df[column] = df[column].fillna(
                df[column].median()
            )

    print(f"Final cleaned shape: {df.shape}")

    return df


# --------------------------------------------------
# Remove constant features
# --------------------------------------------------

def remove_constant_features(df):
    feature_columns = [
        column for column in df.columns
        if column != "label"
    ]

    constant_columns = [
        column
        for column in feature_columns
        if df[column].nunique(dropna=False) <= 1
    ]

    if constant_columns:
        print("\nRemoving constant features:")
        for column in constant_columns:
            print(f"  - {column}")

        df = df.drop(columns=constant_columns)

    return df


# --------------------------------------------------
# Train / validation / test split
# --------------------------------------------------

def split_dataset(df):

    X = df.drop(columns=["label"])
    y = df["label"].astype(int)

    print("\nClass distribution:")
    print(y.value_counts())
    print("\nClass percentages:")
    print(y.value_counts(normalize=True) * 100)

    # First split:
    # 70% train
    # 30% temporary
    X_train, X_temp, y_train, y_temp = train_test_split(
        X,
        y,
        test_size=0.30,
        random_state=RANDOM_STATE,
        stratify=y
    )

    # Split temporary:
    # 15% validation
    # 15% test
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp,
        y_temp,
        test_size=0.50,
        random_state=RANDOM_STATE,
        stratify=y_temp
    )

    train = X_train.copy()
    train["label"] = y_train

    validation = X_val.copy()
    validation["label"] = y_val

    test = X_test.copy()
    test["label"] = y_test

    return train, validation, test


# --------------------------------------------------
# Save datasets
# --------------------------------------------------

def save_datasets(train, validation, test):

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    train_file = OUTPUT_DIR / "train.csv"
    validation_file = OUTPUT_DIR / "validation.csv"
    test_file = OUTPUT_DIR / "test.csv"

    train.to_csv(train_file, index=False)
    validation.to_csv(validation_file, index=False)
    test.to_csv(test_file, index=False)

    print("\nSaved:")
    print(f"Train      : {train_file}")
    print(f"Validation : {validation_file}")
    print(f"Test       : {test_file}")

    print("\nDataset sizes:")
    print(f"Train      : {len(train):,}")
    print(f"Validation : {len(validation):,}")
    print(f"Test       : {len(test):,}")


# --------------------------------------------------
# Main
# --------------------------------------------------

def main():

    print("=" * 60)
    print("PhishGuard AI - URL Dataset Preparation")
    print("=" * 60)

    df = load_dataset()

    df = clean_dataset(df)

    df = remove_constant_features(df)

    train, validation, test = split_dataset(df)

    save_datasets(
        train,
        validation,
        test
    )

    print("\nData preparation completed successfully.")


if __name__ == "__main__":
    main()