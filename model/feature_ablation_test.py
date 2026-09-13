from pathlib import Path
import json
import time

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
)
from xgboost import XGBClassifier


ROOT = Path(__file__).resolve().parents[1]

TRAIN_FILE = ROOT / "data" / "processed" / "domain_train.csv"
VAL_FILE = ROOT / "data" / "processed" / "domain_validation.csv"
TEST_FILE = ROOT / "data" / "processed" / "domain_test.csv"

MODEL_DIR = ROOT / "model"


def load_data():
    print("Loading domain-grouped datasets...")

    train = pd.read_csv(TRAIN_FILE)
    val = pd.read_csv(VAL_FILE)
    test = pd.read_csv(TEST_FILE)

    print(f"Train: {train.shape}")
    print(f"Validation: {val.shape}")
    print(f"Test: {test.shape}")

    return train, val, test


def prepare_features(df):
    """
    Reproduce the exact 40 production URL-only features
    using the shared feature extractor.
    """

    import sys
    sys.path.insert(0, str(ROOT))

    from feature_extractor import extract_features

    features = df["URL"].apply(extract_features)

    return pd.DataFrame(features.tolist())


def evaluate_model(model, X, y):
    predictions = model.predict(X)

    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(X)[:, 1]
    else:
        probabilities = predictions

    return {
        "accuracy": accuracy_score(y, predictions),
        "precision": precision_score(y, predictions, zero_division=0),
        "recall": recall_score(y, predictions, zero_division=0),
        "f1": f1_score(y, predictions, zero_division=0),
        "roc_auc": roc_auc_score(y, probabilities),
    }


def train_model(model_name, X_train, y_train):
    if model_name == "Logistic Regression":
        return LogisticRegression(
            max_iter=2000,
            class_weight="balanced",
            random_state=42,
        )

    if model_name == "Random Forest":
        return RandomForestClassifier(
            n_estimators=300,
            max_depth=None,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )

    if model_name == "XGBoost":
        return XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.05,
            subsample=0.9,
            colsample_bytree=0.9,
            objective="binary:logistic",
            eval_metric="logloss",
            random_state=42,
            n_jobs=-1,
        )

    raise ValueError(f"Unknown model: {model_name}")


def main():

    print("=" * 75)
    print("PhishGuard AI - Feature Ablation Experiment")
    print("=" * 75)

    train, val, test = load_data()

    print("\nExtracting production URL-only features...")

    X_train = prepare_features(train)
    X_val = prepare_features(val)
    X_test = prepare_features(test)

    y_train = train["label"].astype(int)
    y_val = val["label"].astype(int)
    y_test = test["label"].astype(int)

    print(f"Feature count: {len(X_train.columns)}")

    feature_sets = {
        "ALL_FEATURES": list(X_train.columns),

        "NO_HTTPS": [
            c for c in X_train.columns
            if c != "has_https"
        ],

        "NO_HTTPS_PATH": [
            c for c in X_train.columns
            if c not in {
                "has_https",
                "path_length",
            }
        ],

        "NO_SHORTCUTS": [
            c for c in X_train.columns
            if c not in {
                "has_https",
                "path_length",
                "slash_count",
            }
        ],
    }

    results = []

    for feature_set_name, features in feature_sets.items():

        print("\n" + "=" * 75)
        print(f"FEATURE SET: {feature_set_name}")
        print("=" * 75)

        print(f"Features used: {len(features)}")

        Xtr = X_train[features]
        Xv = X_val[features]

        for model_name in [
            "Logistic Regression",
            "Random Forest",
            "XGBoost",
        ]:

            print(f"\nTraining {model_name}...")

            model = train_model(
                model_name,
                Xtr,
                y_train,
            )

            start = time.time()

            model.fit(Xtr, y_train)

            train_time = time.time() - start

            metrics = evaluate_model(
                model,
                Xv,
                y_val,
            )

            print(
                f"Accuracy : {metrics['accuracy']:.4f}\n"
                f"Precision: {metrics['precision']:.4f}\n"
                f"Recall   : {metrics['recall']:.4f}\n"
                f"F1       : {metrics['f1']:.4f}\n"
                f"ROC-AUC  : {metrics['roc_auc']:.4f}\n"
                f"Train    : {train_time:.2f}s"
            )

            results.append({
                "feature_set": feature_set_name,
                "model": model_name,
                **metrics,
                "train_time": train_time,
            })

    results_df = pd.DataFrame(results)

    print("\n")
    print("=" * 75)
    print("ABLATION RESULTS")
    print("=" * 75)

    print(
        results_df[
            [
                "feature_set",
                "model",
                "accuracy",
                "precision",
                "recall",
                "f1",
                "roc_auc",
            ]
        ].to_string(index=False)
    )

    print("\n")
    print("=" * 75)
    print("BEST CONFIGURATIONS")
    print("=" * 75)

    best_f1 = results_df.sort_values(
        "f1",
        ascending=False,
    ).head(10)

    print(
        best_f1[
            [
                "feature_set",
                "model",
                "f1",
                "precision",
                "recall",
                "roc_auc",
            ]
        ].to_string(index=False)
    )

    output_file = MODEL_DIR / "feature_ablation_results.json"

    with open(output_file, "w") as f:
        json.dump(
            results,
            f,
            indent=2,
        )

    print(f"\nResults saved to:")
    print(output_file)

    print("\n")
    print("=" * 75)
    print("IMPORTANT")
    print("=" * 75)

    print(
        "This experiment only evaluates validation performance.\n"
        "Do NOT replace the production model yet.\n"
        "We will use the best feature configuration and then evaluate it\n"
        "on the untouched unseen-domain test set."
    )


if __name__ == "__main__":
    main()