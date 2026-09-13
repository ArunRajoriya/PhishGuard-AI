"""
PhishGuard AI - URL ML Predictor

Loads the production URL-based XGBoost model trained on
the 40-feature URL feature schema.

Model:
    model/domain_url_model.pkl

Schema:
    model/domain_feature_schema.json
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

MODEL_PATH = BASE_DIR / "model" / "domain_url_model.pkl"
SCHEMA_PATH = BASE_DIR / "model" / "domain_feature_schema.json"


# ---------------------------------------------------------------------------
# Model loading
# ---------------------------------------------------------------------------

_model = None
_feature_schema: list[str] = []


def _load_model() -> None:
    """Load the URL model and feature schema once."""

    global _model
    global _feature_schema

    if _model is not None:
        return

    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"URL model not found: {MODEL_PATH}"
        )

    if not SCHEMA_PATH.exists():
        raise FileNotFoundError(
            f"Feature schema not found: {SCHEMA_PATH}"
        )

    _model = joblib.load(MODEL_PATH)

    with open(SCHEMA_PATH, "r", encoding="utf-8") as file:
        schema_data = json.load(file)

    # Support either:
    # {"features": [...]}
    # or simply [...]
    if isinstance(schema_data, dict):
        _feature_schema = schema_data.get("features", [])
    elif isinstance(schema_data, list):
        _feature_schema = schema_data
    else:
        raise ValueError(
            "Invalid feature schema format."
        )

    if not _feature_schema:
        raise ValueError(
            "Feature schema is empty."
        )


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _prepare_features(features: dict[str, Any]) -> pd.DataFrame:
    """
    Convert extracted URL features into the exact feature order
    expected by the trained model.
    """

    _load_model()

    if not isinstance(features, dict):
        raise TypeError(
            "features must be a dictionary."
        )

    missing = [
        name
        for name in _feature_schema
        if name not in features
    ]

    if missing:
        raise ValueError(
            f"Missing required features: {missing}"
        )

    # Only use features that were present during training.
    values = {
        name: features[name]
        for name in _feature_schema
    }

    dataframe = pd.DataFrame(
        [values],
        columns=_feature_schema,
    )

    # Convert everything to numeric.
    dataframe = dataframe.apply(
        pd.to_numeric,
        errors="coerce",
    )

    if dataframe.isnull().any().any():
        bad_columns = dataframe.columns[
            dataframe.isnull().any()
        ].tolist()

        raise ValueError(
            f"Invalid numeric values in features: {bad_columns}"
        )

    return dataframe


# ---------------------------------------------------------------------------
# Prediction
# ---------------------------------------------------------------------------

def predict_url(features: dict[str, Any]) -> dict[str, Any]:
    """
    Predict whether a URL is phishing.

    Uses a single RandomForest predict_proba() call and derives
    the predicted class from the returned probabilities.

    Returns:
        {
            "available": True,
            "prediction": 0 or 1,
            "probability": float,
            "score": float
        }

    prediction:
        0 = legitimate
        1 = phishing

    probability:
        Probability of phishing.

    score:
        Probability converted to 0-100.
    """

    try:
        dataframe = _prepare_features(features)

        # Run the RandomForest only once.
        probabilities = _model.predict_proba(dataframe)[0]

        # Class labels may not necessarily be [0, 1].
        classes = list(_model.classes_)

        # Predicted class = class with highest probability.
        prediction_index = int(np.argmax(probabilities))
        prediction = int(classes[prediction_index])

        # Extract probability belonging specifically to class 1.
        if 1 in classes:
            phishing_index = classes.index(1)
            phishing_probability = float(
                probabilities[phishing_index]
            )
        else:
            phishing_probability = float(
                probabilities[-1]
            )

        return {
            "available": True,
            "prediction": prediction,
            "probability": phishing_probability,
            "score": phishing_probability * 100.0,
        }

    except Exception as exc:
        return {
            "available": False,
            "prediction": None,
            "probability": None,
            "score": None,
            "error": str(exc),
        }
    """
    Predict whether a URL is phishing.

    Returns:
        {
            "available": True,
            "prediction": 0 or 1,
            "probability": float,
            "score": float
        }

    prediction:
        0 = legitimate
        1 = phishing

    probability:
        Probability of phishing.

    score:
        Probability converted to 0-100.
    """

    try:
        dataframe = _prepare_features(features)

        prediction = int(
            _model.predict(dataframe)[0]
        )

        probabilities = _model.predict_proba(dataframe)[0]

        # Class labels may not necessarily be [0, 1].
        classes = list(_model.classes_)

        if 1 in classes:
            phishing_index = classes.index(1)
            phishing_probability = float(
                probabilities[phishing_index]
            )
        else:
            # Defensive fallback.
            phishing_probability = float(
                probabilities[-1]
            )

        return {
            "available": True,
            "prediction": prediction,
            "probability": phishing_probability,
            "score": phishing_probability * 100.0,
        }

    except Exception as exc:
        return {
            "available": False,
            "prediction": None,
            "probability": None,
            "score": None,
            "error": str(exc),
        }


# ---------------------------------------------------------------------------
# Model information
# ---------------------------------------------------------------------------

def get_model_info() -> dict[str, Any]:
    """Return information about the currently loaded URL model."""

    _load_model()

    return {
        "model_path": str(MODEL_PATH),
        "schema_path": str(SCHEMA_PATH),
        "model_type": type(_model).__name__,
        "feature_count": len(_feature_schema),
        "features": _feature_schema,
    }


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from feature_extractor import extract_features

    print("=" * 80)
    print("PhishGuard AI - URL Predictor Test")
    print("=" * 80)

    print("\nModel information:")
    print(get_model_info())

    test_urls = [
        "https://www.google.com",
        "https://www.microsoft.com",
        "https://www.paypal.com",
        "https://paypal-login.security-check.example.com/account/verify",
        "https://microsoft-login.example.com/verify",
        "https://paypal-security.example.xyz/login",
        "http://192.168.1.10/login",
        "https://user:password@example.com/login",
    ]

    for url in test_urls:
        print("\n" + "=" * 80)
        print(url)
        print("=" * 80)

        try:
            features = extract_features(url)
            result = predict_url(features)

            print(f"Prediction : {result.get('prediction')}")
            print(
                f"Probability: "
                f"{result.get('probability')}"
            )
            print(
                f"Score      : "
                f"{result.get('score')}"
            )

            if result.get("prediction") == 1:
                print("Result     : PHISHING")
            elif result.get("prediction") == 0:
                print("Result     : LEGITIMATE")
            else:
                print("Result     : UNAVAILABLE")

            if result.get("error"):
                print(
                    f"Error      : {result['error']}"
                )

        except Exception as exc:
            print(f"ERROR: {exc}")