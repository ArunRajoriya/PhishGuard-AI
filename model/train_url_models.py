import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
)

from xgboost import XGBClassifier


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data" / "processed"
MODEL_DIR = BASE_DIR / "model"

TRAIN_FILE = DATA_DIR / "url_train.csv"
VALIDATION_FILE = DATA_DIR / "url_validation.csv"
TEST_FILE = DATA_DIR / "url_test.csv"

MODEL_FILE = MODEL_DIR / "url_model.pkl"
SCHEMA_FILE = MODEL_DIR / "feature_schema.json"
METRICS_FILE = MODEL_DIR / "metrics.json"


def load_dataset(path):
    df = pd.read_csv(path)

    if "label" not in df.columns:
        raise ValueError(f"'label' column missing from {path}")

    if "url" in df.columns:
        df = df.drop(columns=["url"])

    X = df.drop(columns=["label"])
    y = df["label"].astype(int)

    return X, y


def evaluate_model(name, model, X, y):
    start = time.perf_counter()

    predictions = model.predict(X)
    probabilities = model.predict_proba(X)[:, 1]

    elapsed = time.perf_counter() - start

    metrics = {
        "accuracy": float(accuracy_score(y, predictions)),
        "precision": float(
            precision_score(y, predictions, zero_division=0)
        ),
        "recall": float(
            recall_score(y, predictions, zero_division=0)
        ),
        "f1": float(
            f1_score(y, predictions, zero_division=0)
        ),
        "roc_auc": float(
            roc_auc_score(y, probabilities)
        ),
        "prediction_time_seconds": float(elapsed),
    }

    print(f"\n{'=' * 70}")
    print(name)
    print(f"{'=' * 70}")

    print(f"Accuracy  : {metrics['accuracy']:.4f}")
    print(f"Precision : {metrics['precision']:.4f}")
    print(f"Recall    : {metrics['recall']:.4f}")
    print(f"F1 Score  : {metrics['f1']:.4f}")
    print(f"ROC-AUC   : {metrics['roc_auc']:.4f}")
    print(f"Predict   : {elapsed:.4f} seconds")

    print("\nClassification Report:")
    print(
        classification_report(
            y,
            predictions,
            target_names=["Legitimate", "Phishing"],
            zero_division=0,
        )
    )

    return metrics


def main():
    print("=" * 70)
    print("PhishGuard AI - URL Model Training")
    print("=" * 70)

    print("\nLoading datasets...")

    X_train, y_train = load_dataset(TRAIN_FILE)
    X_val, y_val = load_dataset(VALIDATION_FILE)
    X_test, y_test = load_dataset(TEST_FILE)

    print(f"Train      : {len(X_train):,}")
    print(f"Validation : {len(X_val):,}")
    print(f"Test       : {len(X_test):,}")
    print(f"Features   : {X_train.shape[1]}")

    feature_names = list(X_train.columns)

    # Make absolutely sure all splits have identical feature order.
    if list(X_val.columns) != feature_names:
        raise ValueError("Validation feature schema does not match training.")

    if list(X_test.columns) != feature_names:
        raise ValueError("Test feature schema does not match training.")

    print("\nFeature schema:")
    for i, feature in enumerate(feature_names, start=1):
        print(f"{i:2d}. {feature}")

    models = {
        "Logistic Regression": LogisticRegression(
            max_iter=2000,
            class_weight="balanced",
            random_state=42,
            n_jobs=None,
        ),

        "Random Forest": RandomForestClassifier(
            n_estimators=300,
            max_depth=18,
            min_samples_leaf=2,
            class_weight="balanced_subsample",
            random_state=42,
            n_jobs=-1,
        ),

        "XGBoost": XGBClassifier(
            n_estimators=400,
            max_depth=8,
            learning_rate=0.08,
            subsample=0.9,
            colsample_bytree=0.9,
            min_child_weight=2,
            reg_lambda=1.0,
            objective="binary:logistic",
            eval_metric="logloss",
            random_state=42,
            n_jobs=-1,
            tree_method="hist",
        ),
    }

    validation_results = {}

    print("\nTraining models...")

    for name, model in models.items():
        print(f"\nTraining {name}...")

        start = time.perf_counter()

        model.fit(X_train, y_train)

        train_time = time.perf_counter() - start

        metrics = evaluate_model(
            name,
            model,
            X_val,
            y_val,
        )

        metrics["training_time_seconds"] = float(train_time)

        validation_results[name] = metrics

    print("\n" + "=" * 70)
    print("MODEL COMPARISON - VALIDATION SET")
    print("=" * 70)

    comparison = []

    for name, metrics in validation_results.items():
        comparison.append(
            {
                "model": name,
                "accuracy": metrics["accuracy"],
                "precision": metrics["precision"],
                "recall": metrics["recall"],
                "f1": metrics["f1"],
                "roc_auc": metrics["roc_auc"],
                "training_time": metrics["training_time_seconds"],
            }
        )

    comparison_df = pd.DataFrame(comparison)
    comparison_df = comparison_df.sort_values(
        "f1",
        ascending=False,
    )

    print(
        comparison_df.to_string(
            index=False,
            float_format=lambda x: f"{x:.4f}",
        )
    )

    best_model_name = comparison_df.iloc[0]["model"]

    print(
        f"\nBest validation model: {best_model_name}"
    )

    # ---------------------------------------------------------
    # Refit the selected model on TRAIN + VALIDATION.
    # The TEST set remains untouched until final evaluation.
    # ---------------------------------------------------------

    print("\nRefitting best model on Train + Validation...")

    X_train_full = pd.concat(
        [X_train, X_val],
        ignore_index=True,
    )

    y_train_full = pd.concat(
        [y_train, y_val],
        ignore_index=True,
    )

    best_model = models[best_model_name]

    start = time.perf_counter()

    best_model.fit(
        X_train_full,
        y_train_full,
    )

    refit_time = time.perf_counter() - start

    # ---------------------------------------------------------
    # FINAL TEST EVALUATION
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("FINAL TEST EVALUATION")
    print("=" * 70)

    test_metrics = evaluate_model(
        best_model_name,
        best_model,
        X_test,
        y_test,
    )

    test_metrics["refit_training_time_seconds"] = float(
        refit_time
    )

    # ---------------------------------------------------------
    # Save model
    # ---------------------------------------------------------

    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump(
        best_model,
        MODEL_FILE,
    )

    print(f"\nSaved model:")
    print(MODEL_FILE)

    # ---------------------------------------------------------
    # Save feature schema
    # ---------------------------------------------------------

    schema = {
        "model_name": best_model_name,
        "feature_count": len(feature_names),
        "features": feature_names,
        "positive_class": "Phishing",
        "negative_class": "Legitimate",
    }

    with open(
        SCHEMA_FILE,
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            schema,
            f,
            indent=2,
        )

    print(f"Saved schema:")
    print(SCHEMA_FILE)

    # ---------------------------------------------------------
    # Save metrics
    # ---------------------------------------------------------

    all_metrics = {
        "validation": validation_results,
        "selected_model": best_model_name,
        "test": test_metrics,
        "dataset": {
            "train_rows": int(len(X_train)),
            "validation_rows": int(len(X_val)),
            "test_rows": int(len(X_test)),
            "train_full_rows": int(len(X_train_full)),
            "feature_count": int(len(feature_names)),
        },
    }

    with open(
        METRICS_FILE,
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            all_metrics,
            f,
            indent=2,
        )

    print(f"Saved metrics:")
    print(METRICS_FILE)

    print("\n" + "=" * 70)
    print("TRAINING COMPLETED")
    print("=" * 70)


if __name__ == "__main__":
    main()