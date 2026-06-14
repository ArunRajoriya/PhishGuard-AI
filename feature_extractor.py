from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)

def extract_features(url):
    """
    Extract features from URL for ML prediction
    
    Args:
        url: URL string to extract features from
        
    Returns:
        dict: Dictionary containing extracted features
    """
    try:
        parsed = urlparse(url)

        features = {
            "url_length": len(url),
            "has_https": 1 if parsed.scheme == "https" else 0,
            "hyphen_count": url.count("-"),
            "dot_count": url.count("."),
            "subdomain_count": parsed.netloc.count(".")
        }
        
        logger.debug(f"Extracted features for {url}: {features}")
        return features
        
    except Exception as e:
        logger.error(f"Error extracting features from URL {url}: {str(e)}")
        raise