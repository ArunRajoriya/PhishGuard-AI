import requests
import base64
import os
import logging
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

API_KEY = os.getenv("VT_API_KEY")

def scan_url(url):
    """
    Scan URL using VirusTotal API
    
    Args:
        url: URL to scan
        
    Returns:
        dict: Scan results with malicious, suspicious, harmless, undetected counts
    """
    try:
        if not API_KEY:
            logger.error("VirusTotal API key not found")
            return {
                "error": True,
                "message": "VirusTotal API key not configured"
            }
        
        # Encode URL to base64
        url_id = base64.urlsafe_b64encode(
            url.encode()
        ).decode().strip("=")

        headers = {
            "x-apikey": API_KEY
        }

        logger.info(f"Requesting VirusTotal scan for: {url}")
        
        # Make API request with timeout
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=10
        )

        # Check HTTP status
        if response.status_code == 404:
            # URL not found, submit for scanning
            logger.info(f"URL not found in VT database, submitting for scan: {url}")
            return submit_url_for_scan(url)
        
        if response.status_code == 401:
            logger.error("Invalid VirusTotal API key")
            return {
                "error": True,
                "message": "Invalid API key"
            }
        
        if response.status_code != 200:
            logger.error(f"VirusTotal API returned status code: {response.status_code}")
            return {
                "error": True,
                "message": f"API request failed with status code: {response.status_code}"
            }

        data = response.json()

        if "data" not in data:
            logger.error(f"Unexpected API response format: {data}")
            error_message = data.get("error", {}).get("message", "Unknown error")
            return {
                "error": True,
                "message": error_message
            }

        stats = data["data"]["attributes"]["last_analysis_stats"]

        logger.info(f"VirusTotal scan complete: {stats}")

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0)
        }
        
    except requests.exceptions.Timeout:
        logger.error("VirusTotal API request timed out")
        return {
            "error": True,
            "message": "API request timed out"
        }
    except requests.exceptions.RequestException as e:
        logger.error(f"VirusTotal API request failed: {str(e)}")
        return {
            "error": True,
            "message": "Failed to connect to VirusTotal API"
        }
    except Exception as e:
        logger.error(f"Unexpected error during URL scan: {str(e)}")
        return {
            "error": True,
            "message": "An unexpected error occurred"
        }

def submit_url_for_scan(url):
    """
    Submit URL to VirusTotal for scanning
    
    Args:
        url: URL to submit
        
    Returns:
        dict: Submission result
    """
    try:
        headers = {
            "x-apikey": API_KEY
        }
        
        data = {"url": url}
        
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data=data,
            timeout=10
        )
        
        if response.status_code == 200:
            logger.info(f"URL submitted successfully: {url}")
            return {
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "message": "URL submitted for scanning. Results may take a few moments."
            }
        else:
            logger.error(f"Failed to submit URL: {response.status_code}")
            return {
                "error": True,
                "message": "Failed to submit URL for scanning"
            }
            
    except Exception as e:
        logger.error(f"Error submitting URL: {str(e)}")
        return {
            "error": True,
            "message": "Failed to submit URL for scanning"
        }