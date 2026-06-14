import joblib
import os
import logging

logger = logging.getLogger(__name__)

MODEL_PATH = "model/model.pkl"

# Load model at module initialization
try:
    if os.path.exists(MODEL_PATH):
        model = joblib.load(MODEL_PATH)
        logger.info(f"Model loaded successfully from {MODEL_PATH}")
    else:
        logger.warning(f"Model file not found at {MODEL_PATH}")
        model = None
except Exception as e:
    logger.error(f"Failed to load model: {str(e)}")
    model = None

def predict_url(features):
    """
    Predict if URL is phishing using ML model
    
    Args:
        features: Dictionary containing URL features
        
    Returns:
        tuple: (prediction, confidence) where prediction is 0 (safe) or 1 (phishing)
    """
    try:
        if model is None:
            raise ValueError("Model not loaded")
        
        data = [[
            features["url_length"],
            features["has_https"],
            features["hyphen_count"],
            features["dot_count"],
            features["subdomain_count"]
        ]]

        prediction = model.predict(data)[0]
        confidence = max(model.predict_proba(data)[0])
        
        logger.debug(f"ML Prediction: {prediction}, Confidence: {confidence}")
        
        return prediction, confidence
        
    except Exception as e:
        logger.error(f"Error during prediction: {str(e)}")
        raise