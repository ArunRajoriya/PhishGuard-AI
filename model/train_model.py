from pathlib import Path
import json
import time

import joblib
import pandas as pd

from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
)
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline


BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "data" / "processed"
MODEL_DIR = BASE_DIR / "model"

TRAIN_FILE = DATA_DIR / "train.csv"
VAL_FILE = DATA_DIR / "validation.csv"
TEST_FILE = DATA_DIR / "test.csv"

MODEL_FILE = MODEL_DIR / "url_model.pkl"
METRICS_FILE = MODEL_DIR / "metrics.json"
FEATURE_FILE = MODEL_DIR / "feature_schema.json"

RANDOM_STATE = 42


def load_data():
    print("Loading prepared datasets...")

    train = pd.read_csv(TRAIN_FILE)
    validation = pd.read_csv(VAL_FILE)
    test = pd.read_csv(TEST_FILE)

    X_train = train.drop(columns=["label"])
    y_train = train["label"].astype(int)

    X_val = validation.drop(columns=["label"])
    y_val = validation["label"].astype(int)

    X_test = test.drop(columns=["label"])
    y_test = test["label"].astype(int)

    print(f"Train      : {len(train):,}")
    print(f"Validation : {len(validation):,}")
    print(f"Test       : {len(test):,}")
    print(f"Features   : {X_train.shape[1]}")

    return X_train, y_train, X_val, y_val, X_test, y_test


def evaluate_model(model, X, y):
    start = time.perf_counter()

    predictions = model.predict(X)

    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(X)[:, 1]
    else:
        probabilities = predictions

    latency = time.perf_counter() - start

    tn, fp, fn, tp = confusion_matrix(
        y,
        predictions,
        labels=[0, 1]
    ).ravel()

    return {
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
        "pr_auc": float(
            average_precision_score(y, probabilities)
        ),
        "true_negative": int(tn),
        "false_positive": int(fp),
        "false_negative": int(fn),
        "true_positive": int(tp),
        "inference_seconds": float(latency),
        "inference_ms_per_1000": float(
            latency / len(X) * 1000
        ),
    }


def main():

    print("=" * 70)
    print("PhishGuard AI - URL Model Training")
    print("=" * 70)

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    (
        X_train,
        y_train,
        X_val,
        y_val,
        X_test,
        y_test
    ) = load_data()

    models = {

        "logistic_regression": Pipeline([
            (
                "scaler",
                StandardScaler()
            ),
            (
                "model",
                LogisticRegression(
                    max_iter=2000,
                    class_weight="balanced",
                    random_state=RANDOM_STATE
                )
            )
        ]),

        "random_forest": RandomForestClassifier(
            n_estimators=300,
            max_depth=None,
            min_samples_leaf=2,
            class_weight="balanced",
            n_jobs=-1,
            random_state=RANDOM_STATE
        ),

        "hist_gradient_boosting": HistGradientBoostingClassifier(
            max_iter=300,
            learning_rate=0.08,
            max_leaf_nodes=31,
            l2_regularization=1.0,
            random_state=RANDOM_STATE
        ),
    }

    validation_results = {}

    print("\nTraining models...\n")

    for name, model in models.items():

        print(f"Training: {name}")

        start = time.perf_counter()

        model.fit(
            X_train,
            y_train
        )

        training_time = time.perf_counter() - start

        metrics = evaluate_model(
            model,
            X_val,
            y_val
        )

        metrics["training_seconds"] = training_time

        validation_results[name] = metrics

        print(
            f"  Accuracy : {metrics['accuracy']:.4f}"
        )
        print(
            f"  Precision: {metrics['precision']:.4f}"
        )
        print(
            f"  Recall   : {metrics['recall']:.4f}"
        )
        print(
            f"  F1       : {metrics['f1']:.4f}"
        )
        print(
            f"  ROC-AUC  : {metrics['roc_auc']:.4f}"
        )
        print(
            f"  PR-AUC   : {metrics['pr_auc']:.4f}"
        )
        print()

    # Select model using validation F1.
    best_name = max(
        validation_results,
        key=lambda name: validation_results[name]["f1"]
    )

    best_model = models[best_name]

    print("=" * 70)
    print(f"BEST MODEL: {best_name}")
    print("=" * 70)

    # Refit selected model using train + validation.
    X_train_full = pd.concat(
        [X_train, X_val],
        ignore_index=True
    )

    y_train_full = pd.concat(
        [y_train, y_val],
        ignore_index=True
    )

    print("\nRefitting best model on train + validation data...")

    best_model.fit(
        X_train_full,
        y_train_full
    )

    print("\nFinal test evaluation...")

    test_metrics = evaluate_model(
        best_model,
        X_test,
        y_test
    )

    print(
        f"Accuracy : {test_metrics['accuracy']:.4f}"
    )
    print(
        f"Precision: {test_metrics['precision']:.4f}"
    )
    print(
        f"Recall   : {test_metrics['recall']:.4f}"
    )
    print(
        f"F1       : {test_metrics['f1']:.4f}"
    )
    print(
        f"ROC-AUC  : {test_metrics['roc_auc']:.4f}"
    )
    print(
        f"PR-AUC   : {test_metrics['pr_auc']:.4f}"
    )

    print("\nConfusion Matrix:")

    print(
        f"TN={test_metrics['true_negative']} "
        f"FP={test_metrics['false_positive']}"
    )

    print(
        f"FN={test_metrics['false_negative']} "
        f"TP={test_metrics['true_positive']}"
    )

    # Save model
    joblib.dump(
        best_model,
        MODEL_FILE
    )

    # Save feature schema
    feature_schema = {
        "features": list(X_train.columns),
        "feature_count": len(X_train.columns),
        "label": "label",
        "model": best_name,
        "random_state": RANDOM_STATE
    }

    with open(
        FEATURE_FILE,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            feature_schema,
            file,
            indent=2
        )

    # Save metrics
    output_metrics = {
        "selected_model": best_name,
        "validation": validation_results,
        "test": test_metrics,
        "dataset": {
            "train_rows": len(X_train_full),
            "test_rows": len(X_test),
            "features": len(X_train.columns)
        }
    }

    with open(
        METRICS_FILE,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            output_metrics,
            file,
            indent=2
        )

    print("\nSaved:")
    print(f"Model  : {MODEL_FILE}")
    print(f"Schema : {FEATURE_FILE}")
    print(f"Metrics: {METRICS_FILE}")

    print("\nTraining completed successfully.")


if __name__ == "__main__":
    main()