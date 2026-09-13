from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import joblib
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

# -------------------------------------------------------------------
# PROJECT PATH
# -------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data" / "processed"
MODEL_DIR = PROJECT_ROOT / "model"

MODEL_DIR.mkdir(parents=True, exist_ok=True)


# -------------------------------------------------------------------
# URL / HOSTNAME PREPARATION
# -------------------------------------------------------------------

def prepare_hostname(value: str) -> str:
    """
    Convert hostname into a character-level learning representation.

    Examples:
        www.google.com
        accounts.google.com
        paypal-login.example.com

    We keep dots and hyphens because they carry useful structural
    information for phishing detection.
    """

    if not isinstance(value, str):
        return ""

    value = value.strip().lower()

    # Remove protocol if present
    if "://" in value:
        value = value.split("://", 1)[1]

    # Remove path/query/fragment
    value = value.split("/", 1)[0]
    value = value.split("?", 1)[0]
    value = value.split("#", 1)[0]

    # Remove username/password if accidentally present
    if "@" in value:
        value = value.rsplit("@", 1)[-1]

    return value


# -------------------------------------------------------------------
# DATA LOADING
# -------------------------------------------------------------------

def load_split(filename: str) -> pd.DataFrame:
    path = DATA_DIR / filename

    if not path.exists():
        raise FileNotFoundError(f"Missing dataset: {path}")

    df = pd.read_csv(path)

    required = {"url", "label"}

    missing = required - set(df.columns)

    if missing:
        raise ValueError(
            f"{filename} missing required columns: {sorted(missing)}"
        )

    return df


print("=" * 75)
print("PHISHGUARD AI - HOSTNAME CHARACTER MODEL")
print("=" * 75)

train_df = load_split("robust_train.csv")
validation_df = load_split("robust_validation.csv")
test_df = load_split("robust_test.csv")

print(f"Train rows      : {len(train_df):,}")
print(f"Validation rows : {len(validation_df):,}")
print(f"Test rows       : {len(test_df):,}")


# -------------------------------------------------------------------
# PREPARE HOSTNAMES
# -------------------------------------------------------------------

X_train = train_df["url"].map(prepare_hostname)
X_validation = validation_df["url"].map(prepare_hostname)
X_test = test_df["url"].map(prepare_hostname)

y_train = train_df["label"].astype(int)
y_validation = validation_df["label"].astype(int)
y_test = test_df["label"].astype(int)

print()
print("Example hostname representations:")

for value in X_train.head(5):
    print(f"  {value}")


# -------------------------------------------------------------------
# CHARACTER TF-IDF
# -------------------------------------------------------------------

print()
print("=" * 75)
print("BUILDING CHARACTER N-GRAM FEATURES")
print("=" * 75)

vectorizer = TfidfVectorizer(
    analyzer="char",
    ngram_range=(2, 5),
    min_df=3,
    max_features=150_000,
    sublinear_tf=True,
)

start = time.time()

X_train_vec = vectorizer.fit_transform(X_train)

X_validation_vec = vectorizer.transform(X_validation)
X_test_vec = vectorizer.transform(X_test)

print(f"Vectorization time: {time.time() - start:.2f}s")
print(f"Vocabulary size   : {len(vectorizer.vocabulary_):,}")
print(f"Train matrix      : {X_train_vec.shape}")
print(f"Validation matrix : {X_validation_vec.shape}")
print(f"Test matrix       : {X_test_vec.shape}")


# -------------------------------------------------------------------
# LOGISTIC REGRESSION
# -------------------------------------------------------------------

print()
print("=" * 75)
print("TRAINING LOGISTIC REGRESSION")
print("=" * 75)

model = LogisticRegression(
    max_iter=1000,
    class_weight="balanced",
    C=3.0,
    solver="liblinear",
)

start = time.time()

model.fit(X_train_vec, y_train)

print(f"Training time: {time.time() - start:.2f}s")


# -------------------------------------------------------------------
# VALIDATION
# -------------------------------------------------------------------

validation_pred = model.predict(X_validation_vec)
validation_prob = model.predict_proba(X_validation_vec)[:, 1]

validation_accuracy = accuracy_score(
    y_validation,
    validation_pred,
)

validation_precision = precision_score(
    y_validation,
    validation_pred,
    zero_division=0,
)

validation_recall = recall_score(
    y_validation,
    validation_pred,
    zero_division=0,
)

validation_f1 = f1_score(
    y_validation,
    validation_pred,
    zero_division=0,
)

validation_auc = roc_auc_score(
    y_validation,
    validation_prob,
)

print()
print("=" * 75)
print("VALIDATION RESULTS")
print("=" * 75)

print(f"Accuracy : {validation_accuracy:.4f}")
print(f"Precision: {validation_precision:.4f}")
print(f"Recall   : {validation_recall:.4f}")
print(f"F1       : {validation_f1:.4f}")
print(f"ROC-AUC  : {validation_auc:.4f}")


# -------------------------------------------------------------------
# TEST
# -------------------------------------------------------------------

test_pred = model.predict(X_test_vec)
test_prob = model.predict_proba(X_test_vec)[:, 1]

test_accuracy = accuracy_score(
    y_test,
    test_pred,
)

test_precision = precision_score(
    y_test,
    test_pred,
    zero_division=0,
)

test_recall = recall_score(
    y_test,
    test_pred,
    zero_division=0,
)

test_f1 = f1_score(
    y_test,
    test_pred,
    zero_division=0,
)

test_auc = roc_auc_score(
    y_test,
    test_prob,
)

print()
print("=" * 75)
print("UNSEEN-DOMAIN TEST RESULTS")
print("=" * 75)

print(f"Accuracy : {test_accuracy:.4f}")
print(f"Precision: {test_precision:.4f}")
print(f"Recall   : {test_recall:.4f}")
print(f"F1       : {test_f1:.4f}")
print(f"ROC-AUC  : {test_auc:.4f}")

print()
print("Classification Report:")
print(
    classification_report(
        y_test,
        test_pred,
        target_names=["Legitimate", "Phishing"],
        zero_division=0,
    )
)


# -------------------------------------------------------------------
# SAVE MODEL
# -------------------------------------------------------------------

model_path = MODEL_DIR / "hostname_char_model.pkl"
vectorizer_path = MODEL_DIR / "hostname_vectorizer.pkl"
metrics_path = MODEL_DIR / "hostname_metrics.json"

joblib.dump(model, model_path)
joblib.dump(vectorizer, vectorizer_path)

metrics = {
    "model": "LogisticRegression",
    "feature_type": "hostname_character_tfidf",
    "ngram_range": [2, 5],
    "max_features": 150000,
    "validation": {
        "accuracy": float(validation_accuracy),
        "precision": float(validation_precision),
        "recall": float(validation_recall),
        "f1": float(validation_f1),
        "roc_auc": float(validation_auc),
    },
    "test": {
        "accuracy": float(test_accuracy),
        "precision": float(test_precision),
        "recall": float(test_recall),
        "f1": float(test_f1),
        "roc_auc": float(test_auc),
    },
}

with open(metrics_path, "w", encoding="utf-8") as f:
    json.dump(metrics, f, indent=2)


# -------------------------------------------------------------------
# COMPLETE
# -------------------------------------------------------------------

print()
print("=" * 75)
print("MODEL ARTIFACTS SAVED")
print("=" * 75)

print(model_path)
print(vectorizer_path)
print(metrics_path)

print()
print("Next step:")
print("  python model/test_hostname_model.py")
