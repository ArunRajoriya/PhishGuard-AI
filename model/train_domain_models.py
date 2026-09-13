import sys
import json
import time
from pathlib import Path

import joblib
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


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
MODEL_DIR = PROJECT_ROOT / "model"

TRAIN_FILE = PROCESSED_DIR / "robust_train.csv"
VALIDATION_FILE = PROCESSED_DIR / "robust_validation.csv"
TEST_FILE = PROCESSED_DIR / "robust_test.csv"


# ============================================================
# CONFIGURATION
# ============================================================

TARGET = "label"


EXCLUDED_COLUMNS = {
    "label",
    "url",
    "domain",
    "original_url",
    "augmentation_source",
}



# ============================================================
# LOAD DATA
# ============================================================

def load_dataset(path):
    df = pd.read_csv(path)

    print(
        f"Loaded {path.name}: "
        f"{len(df):,} rows"
    )

    return df


# ============================================================
# METRICS
# ============================================================

def evaluate_model(model, X, y):

    start = time.perf_counter()

    predictions = model.predict(X)

    prediction_time = time.perf_counter() - start

    probabilities = model.predict_proba(X)[:, 1]

    metrics = {
        "accuracy": accuracy_score(y, predictions),
        "precision": precision_score(
            y,
            predictions,
            zero_division=0,
        ),
        "recall": recall_score(
            y,
            predictions,
            zero_division=0,
        ),
        "f1": f1_score(
            y,
            predictions,
            zero_division=0,
        ),
        "roc_auc": roc_auc_score(
            y,
            probabilities,
        ),
        "prediction_time_seconds": prediction_time,
    }

    return metrics


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 75)
    print("PhishGuard AI - Domain Robust Model Training")
    print("=" * 75)

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    # --------------------------------------------------------
    # Load
    # --------------------------------------------------------

    train = load_dataset(TRAIN_FILE)
    validation = load_dataset(VALIDATION_FILE)
    test = load_dataset(TEST_FILE)

    # --------------------------------------------------------
    # Feature columns
    # --------------------------------------------------------

    feature_columns = [
        column
        for column in train.columns
        if column not in EXCLUDED_COLUMNS
    ]

    print("\nFeature count:", len(feature_columns))

    print("\nFeatures:")

    for index, feature in enumerate(
        feature_columns,
        start=1,
    ):
        print(
            f"{index:2d}. {feature}"
        )

    # --------------------------------------------------------
    # Prepare X / y
    # --------------------------------------------------------

    X_train = train[feature_columns]
    y_train = train[TARGET]

    X_validation = validation[feature_columns]
    y_validation = validation[TARGET]

    X_test = test[feature_columns]
    y_test = test[TARGET]

    print("\nShapes:")

    print(
        "Train:",
        X_train.shape,
    )

    print(
        "Validation:",
        X_validation.shape,
    )

    print(
        "Test:",
        X_test.shape,
    )

    # --------------------------------------------------------
    # Models
    # --------------------------------------------------------

    models = {

        "Logistic Regression":
            LogisticRegression(
                max_iter=2000,
                class_weight="balanced",
                random_state=42,
            ),

        "Random Forest":
            RandomForestClassifier(
                n_estimators=300,
                max_depth=18,
                min_samples_leaf=2,
                class_weight="balanced",
                n_jobs=-1,
                random_state=42,
            ),

        "XGBoost":
            XGBClassifier(
                n_estimators=300,
                max_depth=6,
                learning_rate=0.05,
                subsample=0.9,
                colsample_bytree=0.9,
                objective="binary:logistic",
                eval_metric="logloss",
                random_state=42,
                n_jobs=-1,
            ),
    }

    validation_results = {}

    # --------------------------------------------------------
    # Train and validate
    # --------------------------------------------------------

    print("\n" + "=" * 75)
    print("VALIDATION RESULTS")
    print("=" * 75)

    for name, model in models.items():

        print(
            f"\nTraining {name}..."
        )

        start = time.perf_counter()

        model.fit(
            X_train,
            y_train,
        )

        train_time = (
            time.perf_counter() - start
        )

        metrics = evaluate_model(
            model,
            X_validation,
            y_validation,
        )

        metrics["train_time_seconds"] = train_time

        validation_results[name] = metrics

        print(
            f"Accuracy : {metrics['accuracy']:.4f}"
        )

        print(
            f"Precision: {metrics['precision']:.4f}"
        )

        print(
            f"Recall   : {metrics['recall']:.4f}"
        )

        print(
            f"F1       : {metrics['f1']:.4f}"
        )

        print(
            f"ROC-AUC  : {metrics['roc_auc']:.4f}"
        )

        print(
            f"Train    : {train_time:.2f}s"
        )

    # --------------------------------------------------------
    # Select best model
    # --------------------------------------------------------

    best_name = max(
        validation_results,
        key=lambda name:
            validation_results[name]["f1"],
    )

    print("\n" + "=" * 75)

    print(
        f"BEST VALIDATION MODEL: {best_name}"
    )

    print(
        f"Validation F1: "
        f"{validation_results[best_name]['f1']:.4f}"
    )

    print("=" * 75)

    # --------------------------------------------------------
    # Refit on train + validation
    # --------------------------------------------------------

    X_train_final = pd.concat(
        [
            X_train,
            X_validation,
        ],
        ignore_index=True,
    )

    y_train_final = pd.concat(
        [
            y_train,
            y_validation,
        ],
        ignore_index=True,
    )

    best_model = models[best_name]

    print(
        "\nRefitting best model on "
        f"{len(X_train_final):,} rows..."
    )

    start = time.perf_counter()

    best_model.fit(
        X_train_final,
        y_train_final,
    )

    refit_time = (
        time.perf_counter() - start
    )

    print(
        f"Refit completed in "
        f"{refit_time:.2f}s"
    )

    # --------------------------------------------------------
    # Final untouched test
    # --------------------------------------------------------

    print("\n" + "=" * 75)
    print("UNSEEN-DOMAIN TEST RESULTS")
    print("=" * 75)

    test_metrics = evaluate_model(
        best_model,
        X_test,
        y_test,
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
        f"Predict  : "
        f"{test_metrics['prediction_time_seconds']:.4f}s"
    )

    print("\nClassification Report:")

    predictions = best_model.predict(
        X_test
    )

    print(
        classification_report(
            y_test,
            predictions,
            target_names=[
                "Legitimate",
                "Phishing",
            ],
            zero_division=0,
        )
    )

    # --------------------------------------------------------
    # Feature importance
    # --------------------------------------------------------

    print("=" * 75)
    print("FEATURE IMPORTANCE")
    print("=" * 75)

    if hasattr(
        best_model,
        "feature_importances_",
    ):

        importance = pd.Series(
            best_model.feature_importances_,
            index=feature_columns,
        )

        importance = (
            importance
            .sort_values(
                ascending=False
            )
            .head(15)
        )

        for feature, value in importance.items():

            print(
                f"{feature:30s} "
                f"{value:.6f}"
            )

    # --------------------------------------------------------
    # Save model
    # --------------------------------------------------------

    model_path = (
        MODEL_DIR /
        "domain_url_model.pkl"
    )

    schema_path = (
        MODEL_DIR /
        "domain_feature_schema.json"
    )

    metrics_path = (
        MODEL_DIR /
        "domain_metrics.json"
    )

    joblib.dump(
        best_model,
        model_path,
    )

    schema = {
        "model_name": best_name,
        "feature_count": len(feature_columns),
        "features": feature_columns,
        "positive_class": "Phishing",
        "negative_class": "Legitimate",
    }

    with open(
        schema_path,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            schema,
            file,
            indent=2,
        )

    complete_metrics = {
        "validation": validation_results,
        "best_model": best_name,
        "test": test_metrics,
        "test_classification_report":
            classification_report(
                y_test,
                predictions,
                target_names=[
                    "Legitimate",
                    "Phishing",
                ],
                output_dict=True,
                zero_division=0,
            ),
    }

    with open(
        metrics_path,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            complete_metrics,
            file,
            indent=2,
        )

    print("\n" + "=" * 75)
    print("MODEL ARTIFACTS SAVED")
    print("=" * 75)

    print(model_path)
    print(schema_path)
    print(metrics_path)


if __name__ == "__main__":
    main()