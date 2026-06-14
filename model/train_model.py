import pandas as pd
import joblib
import os
import logging
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def train_model():
    """Train phishing detection model"""
    
    logger.info("Starting model training...")
    
    # Sample training data (in production, use a larger dataset)
    data = {
        "url_length": [10, 15, 20, 40, 55, 60, 25, 30, 65, 70, 12, 18, 45, 50, 58],
        "has_https": [1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0],
        "hyphen_count": [0, 0, 0, 2, 4, 5, 0, 1, 3, 6, 0, 0, 2, 3, 4],
        "dot_count": [1, 1, 2, 3, 4, 5, 1, 2, 3, 5, 1, 1, 3, 4, 4],
        "subdomain_count": [0, 0, 1, 2, 3, 4, 0, 1, 2, 4, 0, 0, 2, 3, 3],
        "label": [0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1]
    }

    df = pd.DataFrame(data)
    
    logger.info(f"Training data shape: {df.shape}")
    logger.info(f"Class distribution:\n{df['label'].value_counts()}")

    # Split features and labels
    X = df.drop("label", axis=1)
    y = df["label"]

    # Split data for validation
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Train Random Forest model
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        class_weight='balanced'
    )

    logger.info("Training model...")
    model.fit(X_train, y_train)

    # Evaluate model
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    logger.info(f"Model Accuracy: {accuracy:.2%}")
    logger.info(f"\nClassification Report:\n{classification_report(y_test, y_pred)}")
    
    # Feature importance
    feature_importance = pd.DataFrame({
        'feature': X.columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    logger.info(f"\nFeature Importance:\n{feature_importance}")

    # Save model
    model_dir = "model"
    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, "model.pkl")
    
    joblib.dump(model, model_path)
    logger.info(f"Model saved successfully to {model_path}")
    
    return model

if __name__ == "__main__":
    try:
        train_model()
        logger.info("Model training completed successfully!")
    except Exception as e:
        logger.error(f"Model training failed: {str(e)}")
        raise