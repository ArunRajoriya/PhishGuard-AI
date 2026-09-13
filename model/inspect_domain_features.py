import pandas as pd

TRAIN_PATH = "data/processed/domain_train.csv"
VAL_PATH = "data/processed/domain_validation.csv"
TEST_PATH = "data/processed/domain_test.csv"

META_COLUMNS = {"url", "domain", "label"}


def inspect(path):
    df = pd.read_csv(path)

    feature_columns = [
        c for c in df.columns
        if c not in META_COLUMNS
    ]

    print("=" * 80)
    print(path)
    print("=" * 80)

    print("Rows:", len(df))
    print("Features:", len(feature_columns))
    print("Missing values:", int(df.isna().sum().sum()))
    print("Duplicate URLs:", int(df["url"].duplicated().sum()))
    print("Duplicate domains:", int(df["domain"].duplicated().sum()))

    print("\nLabel distribution:")
    print(df["label"].value_counts().sort_index())

    print("\nFeature statistics:")
    print(
        df[feature_columns]
        .describe()
        .T[
            [
                "min",
                "mean",
                "50%",
                "max",
            ]
        ]
        .round(4)
    )

    print("\nUnique values:")
    unique_counts = df[feature_columns].nunique().sort_values()
    print(unique_counts)

    print("\nPotential constant features:")
    constant = unique_counts[unique_counts <= 1]

    if len(constant):
        print(constant)
    else:
        print("None")

    print()


if __name__ == "__main__":
    inspect(TRAIN_PATH)
    inspect(VAL_PATH)
    inspect(TEST_PATH)