from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import logging
from datetime import datetime
import re

from feature_extractor import extract_features
from predictor import predict_url
from virustotal import scan_url
from database import save_scan_result, get_scan_history, get_statistics

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="PhishGuard AI",
    description="Threat Intelligence Powered Phishing URL Detection System",
    version="1.0.0"
)

# CORS middleware for production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure with specific domains in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount(
    "/static",
    StaticFiles(directory="static"),
    name="static"
)

templates = Jinja2Templates(directory="templates")

def validate_url(url: str) -> bool:
    """Validate URL format"""
    url_pattern = re.compile(
        r'^(https?://)?'  # http:// or https://
        r'(([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})'  # domain
        r'(/.*)?$'  # path
    )
    return bool(url_pattern.match(url))

@app.get("/")
async def home(request: Request):
    """Render home page"""
    try:
        return templates.TemplateResponse(
            request=request,
            name="index.html"
        )
    except Exception as e:
        logger.error(f"Error rendering home page: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/stats")
async def stats():
    """Get scan statistics"""
    try:
        stats_data = get_statistics()
        return stats_data
    except Exception as e:
        logger.error(f"Error fetching stats: {str(e)}")
        return {
            "total": 0,
            "safe": 0,
            "suspicious": 0,
            "phishing": 0
        }

@app.get("/api/history")
async def history():
    """Get scan history"""
    try:
        history_data = get_scan_history()
        return {"history": history_data}
    except Exception as e:
        logger.error(f"Error fetching history: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch history")

@app.post("/scan")
async def scan(url: str = Form(...)):
    """Scan URL for phishing threats"""
    try:
        # Validate URL
        if not url or len(url.strip()) == 0:
            return JSONResponse(
                status_code=400,
                content={
                    "risk": "Error",
                    "message": "URL cannot be empty"
                }
            )
        
        url = url.strip()
        
        if not validate_url(url):
            return JSONResponse(
                status_code=400,
                content={
                    "risk": "Error",
                    "message": "Invalid URL format"
                }
            )
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        logger.info(f"Scanning URL: {url}")
        
        # Scan with VirusTotal
        vt_result = scan_url(url)
        
        if "error" in vt_result:
            error_msg = vt_result.get("message", "VirusTotal API error")
            logger.error(f"VirusTotal error: {error_msg}")
            return JSONResponse(
                status_code=500,
                content={
                    "risk": "Error",
                    "message": error_msg
                }
            )
        
        malicious = vt_result.get("malicious", 0)
        suspicious = vt_result.get("suspicious", 0)
        harmless = vt_result.get("harmless", 0)
        
        # Determine risk level
        risk = "Safe"
        if malicious > 0:
            risk = "Phishing"
        elif suspicious > 0:
            risk = "Suspicious"
        
        # Extract features and get ML prediction
        try:
            features = extract_features(url)
            ml_prediction, confidence = predict_url(features)
            ml_risk = "Phishing" if ml_prediction == 1 else "Safe"
        except Exception as e:
            logger.warning(f"ML prediction failed: {str(e)}")
            ml_risk = None
            confidence = None
        
        # Save to database
        try:
            save_scan_result(url, risk, confidence if confidence else 0.0)
        except Exception as e:
            logger.error(f"Failed to save scan result: {str(e)}")
        
        result = {
            "url": url,
            "risk": risk,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if ml_risk:
            result["ml_prediction"] = ml_risk
            result["confidence"] = float(confidence) if confidence else None
        
        logger.info(f"Scan complete: {url} - Risk: {risk}")
        return result
        
    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={
                "risk": "Error",
                "message": "An unexpected error occurred during scanning"
            }
        )