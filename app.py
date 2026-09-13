# PhishGuard AI 2.2.0 - production-oriented FastAPI application
# Keep this file as the single API entry point. Existing ML, risk, Redis, DB and queue
# modules remain the source of truth for their respective responsibilities.

import os
import re
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from uuid import uuid4

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field, EmailStr

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

# Docker-friendly defaults. Explicit environment variables still win.
IN_DOCKER = Path("/.dockerenv").exists()
if IN_DOCKER:
    if not os.getenv("DATABASE_URL_DOCKER") and os.getenv("DATABASE_URL", "").startswith(("postgresql://", "postgres://")):
        db_url = os.getenv("DATABASE_URL", "")
        if "@localhost:" in db_url or "@127.0.0.1:" in db_url or "@192.168." in db_url:
            os.environ["DATABASE_URL"] = re.sub(r"@[^/]+(?=/)", "@host.docker.internal", db_url)
    elif os.getenv("DATABASE_URL_DOCKER"):
        os.environ["DATABASE_URL"] = os.environ["DATABASE_URL_DOCKER"]
    if not os.getenv("REDIS_URL_DOCKER"):
        redis_url = os.getenv("REDIS_URL", "")
        if redis_url.startswith("redis://localhost") or redis_url.startswith("redis://127.0.0.1"):
            os.environ["REDIS_URL"] = "redis://phishguard-redis:6379/0"
    else:
        os.environ["REDIS_URL"] = os.environ["REDIS_URL_DOCKER"]
    if not os.getenv("CELERY_BROKER_URL_DOCKER"):
        broker = os.getenv("CELERY_BROKER_URL", "")
        if broker.startswith("redis://localhost") or broker.startswith("redis://127.0.0.1"):
            os.environ["CELERY_BROKER_URL"] = "redis://phishguard-redis:6379/1"
    else:
        os.environ["CELERY_BROKER_URL"] = os.environ["CELERY_BROKER_URL_DOCKER"]
    if not os.getenv("CELERY_RESULT_BACKEND_DOCKER"):
        backend = os.getenv("CELERY_RESULT_BACKEND", "")
        if backend.startswith("redis://localhost") or backend.startswith("redis://127.0.0.1"):
            os.environ["CELERY_RESULT_BACKEND"] = "redis://phishguard-redis:6379/2"
    else:
        os.environ["CELERY_RESULT_BACKEND"] = os.environ["CELERY_RESULT_BACKEND_DOCKER"]

from predictor import _load_model
from risk_engine import analyze_url
from rate_limiter import check_rate_limit
from cache.redis_cache import get_cached_scan, set_cached_scan, redis_health_check
from jobs.scan_queue import create_scan_job, get_scan_job
from utils.url_normalizer import normalize_url
from auth import create_access_token, decode_access_token, hash_password, verify_password

logger = logging.getLogger("phishguard")
if not logger.handlers:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

API_V1_PREFIX = "/api/v1"
MAX_URL_LENGTH = 2048
MAX_HISTORY_LIMIT = 100
ALLOWED_SCHEMES = {"http", "https"}

STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"

# Lazy DB imports prevent database.py's import-time connection from crashing the
# entire ASGI process before FastAPI startup can report readiness correctly.
def _db():
    import database
    return database

def db_get_user_by_email(email: str):
    return _db().get_user_by_email(email)

def db_get_user_by_id(user_id: int):
    return _db().get_user_by_id(user_id)

def db_create_user(**kwargs):
    return _db().create_user(**kwargs)

def db_save_scan(**kwargs):
    return _db().save_scan(**kwargs)

def db_get_recent_scans(limit: int = MAX_HISTORY_LIMIT):
    return _db().get_recent_scans(limit)

def db_get_stats():
    return _db().get_stats()

def db_initialize():
    return _db().initialize_database()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting PhishGuard AI %s", app.version)
    logger.info("Runtime: %s", "Docker" if IN_DOCKER else "Local")

    # Preload the heavy RandomForest once per worker, not on the first request.
    try:
        started = perf_counter()
        _load_model()
        logger.info("URL ML model loaded during startup in %.2fms", (perf_counter() - started) * 1000)
    except Exception:
        logger.exception("URL ML model failed to load during startup")
        raise

    # Database initialization remains owned by database.py. Importing it here
    # makes configuration failures visible in startup logs instead of import traces.
    try:
        db_initialize()
        logger.info("PostgreSQL database initialized")
    except Exception:
        logger.exception("PostgreSQL initialization failed; API will report not-ready")

    try:
        logger.info("Redis health: %s", "up" if redis_health_check() else "down")
    except Exception:
        logger.exception("Redis health check failed during startup")

    yield
    logger.info("Shutting down PhishGuard AI")


app = FastAPI(
    title="PhishGuard AI",
    description=(
        "Production-oriented phishing URL detection API combining URL ML, "
        "hostname ML, security rules, threat intelligence, Redis caching, "
        "PostgreSQL persistence, JWT authentication and asynchronous scanning."
    ),
    version="2.2.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()"
        )

        return response


app.add_middleware(SecurityHeadersMiddleware)


def _cors_origins() -> List[str]:
    raw = os.getenv(
        "ALLOWED_ORIGINS",
        "http://localhost:5173,http://localhost:5174,http://localhost:5175,"
        "http://127.0.0.1:5173,http://127.0.0.1:5174,http://127.0.0.1:5175,"
        "http://localhost:8000,http://127.0.0.1:8000",
    )
    return [x.strip() for x in raw.split(",") if x.strip()]


ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def request_context_middleware(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or str(uuid4())
    request.state.request_id = request_id
    started = perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        logger.exception("Unhandled request | request_id=%s | path=%s", request_id, request.url.path)
        raise
    duration_ms = (perf_counter() - started) * 1000
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = (
    "camera=(), microphone=(), geolocation=()"
)
    logger.info("HTTP %s %s | status=%s | %.2fms | request_id=%s", request.method, request.url.path, response.status_code, duration_ms, request_id)
    return response


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", str(uuid4()))


def error_response(request: Request, status_code: int, code: str, message: str, details: Any = None):
    content = {
        "success": False,
        "error": {"code": code, "message": message},
        "request_id": _request_id(request),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if details is not None:
        content["error"]["details"] = details
    return JSONResponse(status_code=status_code, content=content, headers={"X-Request-ID": _request_id(request)})


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    return error_response(request, 422, "VALIDATION_ERROR", "Request validation failed.", exc.errors())


@app.exception_handler(Exception)
async def unhandled_handler(request: Request, exc: Exception):
    logger.exception("Unhandled application exception | request_id=%s", _request_id(request))
    return error_response(request, 500, "INTERNAL_SERVER_ERROR", "An unexpected server error occurred.")


if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

templates = Jinja2Templates(directory=str(TEMPLATES_DIR)) if TEMPLATES_DIR.exists() else None


# ----------------------------- Schemas -----------------------------
class RegisterRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    email: str = Field(..., min_length=5, max_length=255)
    password: str = Field(..., min_length=8, max_length=128)

class LoginRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    email: str = Field(..., min_length=5, max_length=255)
    password: str = Field(..., min_length=1, max_length=128)

class UserResponse(BaseModel):
    id: int
    email: str
    role: str
    is_active: bool
    created_at: str

class AuthResponse(BaseModel):
    success: bool = True
    access_token: str
    token_type: str = "bearer"
    user: UserResponse
    request_id: str

class MeResponse(BaseModel):
    success: bool = True
    user: UserResponse
    request_id: str

class ScanRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    url: str = Field(..., min_length=1, max_length=MAX_URL_LENGTH, examples=["https://example.com"])

class RiskInfo(BaseModel):
    score: float
    level: str
    confidence: float

class ModelScore(BaseModel):
    available: bool = False
    prediction: Optional[int] = None
    probability: Optional[float] = None
    score: Optional[float] = None

class ModelScores(BaseModel):
    url_ml: Optional[ModelScore] = None
    hostname_ml: Optional[ModelScore] = None
    fusion_score: Optional[float] = None
    rule_score: Optional[float] = None

class ScanResponse(BaseModel):
    success: bool = True
    url: str
    risk: RiskInfo
    prediction: str
    trusted_domain: bool
    reasons: List[str] = Field(default_factory=list)
    models: ModelScores
    threat_intelligence: Dict[str, Any] = Field(default_factory=dict)
    scan_duration_ms: float
    timestamp: str
    cache: Dict[str, Any]
    request_id: str
    rate_limit: Optional[Dict[str, Any]] = None

class AsyncScanRequest(ScanRequest):
    pass

class AsyncScanResponse(BaseModel):
    success: bool = True
    message: str
    scan_id: str
    status: str
    url: str
    created_at: str
    request_id: str

class ScanStatusResponse(BaseModel):
    success: bool = True
    scan_id: str
    status: str
    url: Optional[str] = None
    created_at: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    request_id: str


# ----------------------------- Validation -----------------------------
URL_PATTERN = re.compile(
    r"^(?:https?://)?(?:"
    r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|"
    r"(?:\d{1,3}\.){3}\d{1,3}|localhost"
    r")(?:[:\d]{0,6})?(?:[/?#].*)?$"
)

def validate_url(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("URL must be a string.")
    value = value.strip()
    if not value:
        raise ValueError("URL cannot be empty.")
    if len(value) > MAX_URL_LENGTH:
        raise ValueError(f"URL exceeds maximum allowed length of {MAX_URL_LENGTH} characters.")
    if not URL_PATTERN.match(value):
        raise ValueError("Invalid URL format.")
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES or not parsed.hostname:
        raise ValueError("Only valid HTTP/HTTPS URLs are supported.")
    try:
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("Invalid port number.")
    except ValueError as exc:
        raise ValueError(str(exc)) from exc
    return normalize_url(value)


def get_client_ip(request: Request) -> str:
    if os.getenv("TRUST_PROXY_HEADERS", "false").lower() == "true":
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def rate_limit_response(request: Request, result: dict):
    rid = _request_id(request)
    return JSONResponse(
        status_code=429,
        content={
            "success": False,
            "error": {"code": "RATE_LIMIT_EXCEEDED", "message": "Too many scan requests. Please try again later."},
            "retry_after": result.get("reset_after", 60),
            "request_id": rid,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        headers={
            "Retry-After": str(result.get("reset_after", 60)),
            "X-RateLimit-Limit": str(result.get("limit", 30)),
            "X-RateLimit-Remaining": str(result.get("remaining", 0)),
            "X-Request-ID": rid,
        },
    )


def apply_rate_limit(request: Request):
    try:
        result = check_rate_limit(get_client_ip(request))
    except Exception as exc:
        # Never turn a Redis outage into a 500 for the scanner. The limiter module
        # itself is fail-open; this guard protects the API if that module changes.
        logger.warning("Rate limiter unavailable; continuing fail-open: %s", exc)
        return {"allowed": True, "limit": 0, "remaining": 0, "reset_after": 0}, None
    if not result.get("allowed", False):
        return None, rate_limit_response(request, result)
    return result, None


# ----------------------------- Authentication -----------------------------
security = HTTPBearer(auto_error=False)

def normalize_email(email: str) -> str:
    return email.strip().lower()

def serialize_user(user: dict) -> dict:
    created = user.get("created_at")
    created_at = created.isoformat() if hasattr(created, "isoformat") else str(created)
    return {
        "id": int(user["id"]),
        "email": str(user["email"]),
        "role": str(user.get("role", "user")),
        "is_active": bool(user.get("is_active", True)),
        "created_at": created_at,
    }

def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Authentication required.", headers={"WWW-Authenticate": "Bearer"})
    payload = decode_access_token(credentials.credentials)
    if not payload or not payload.get("sub"):
        raise HTTPException(status_code=401, detail="Invalid or expired access token.", headers={"WWW-Authenticate": "Bearer"})
    try:
        user_id = int(payload["sub"])
    except (TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid access token.", headers={"WWW-Authenticate": "Bearer"})
    user = db_get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found.", headers={"WWW-Authenticate": "Bearer"})
    if not user.get("is_active", False):
        raise HTTPException(status_code=403, detail="User account is inactive.")
    return user


# ----------------------------- Core scan -----------------------------
def _safe_models(result: dict) -> dict:
    models = result.get("models") or {}
    return {
        "url_ml": models.get("url_ml"),
        "hostname_ml": models.get("hostname_ml"),
        "fusion_score": models.get("model_score"),
        "rule_score": models.get("rule_score"),
    }
def perform_scan(
    normalized_url: str,
    request_id: str,
    rate_limit: Optional[dict] = None,
) -> dict:
    """
    Execute a URL scan.

    Architecture:
        Redis cache -> Risk Engine -> PostgreSQL -> Redis

    Important:
        Every scan is recorded in PostgreSQL history, including
        scans whose analysis result comes from Redis cache.
    """

    # ============================================================
    # 1. REDIS CACHE LOOKUP
    # ============================================================
    try:
        cached = get_cached_scan(normalized_url)

        if cached is not None:
            response = dict(cached)

            response["cache"] = {
                "hit": True,
                "source": "redis",
            }

            response["request_id"] = request_id

            if rate_limit:
                response["rate_limit"] = {
                    key: rate_limit.get(key)
                    for key in (
                        "limit",
                        "remaining",
                        "reset_after",
                    )
                }

            # ----------------------------------------------------
            # CACHE HIT IS STILL A SCAN EVENT
            # ----------------------------------------------------
            try:
                risk = response.get("risk") or {}

                prediction = str(
                    response.get(
                        "prediction",
                        risk.get("level", "UNKNOWN"),
                    )
                )

                risk_score = float(
                    risk.get(
                        "score",
                        response.get("risk_score", 0),
                    )
                    or 0
                )

                risk_level = str(
                    risk.get(
                        "level",
                        response.get(
                            "risk_level",
                            "UNKNOWN",
                        ),
                    )
                )

                confidence = float(
                    risk.get(
                        "confidence",
                        response.get(
                            "confidence",
                            0,
                        ),
                    )
                    or 0
                )

                trusted_domain = bool(
                    response.get(
                        "trusted_domain",
                        False,
                    )
                )

                models = response.get("models") or {}

                threat_intelligence = (
                    response.get(
                        "threat_intelligence"
                    )
                    or {}
                )

                db_save_scan(
                    url=normalized_url,
                    prediction=prediction,
                    confidence=confidence,
                    risk_score=risk_score,
                    risk_level=risk_level,
                    trusted_domain=trusted_domain,
                    models=models,
                    threat_intelligence=threat_intelligence,
                    scan_duration_ms=0,
                )

                logger.info(
                    "Cached scan saved to PostgreSQL history | "
                    "url=%s | request_id=%s",
                    normalized_url,
                    request_id,
                )

            except Exception as exc:
                # History failure must never break an otherwise
                # successful cached scan.
                logger.warning(
                    "Cached scan history write failed | "
                    "request_id=%s | %s",
                    request_id,
                    exc,
                )

            return response

    except Exception as exc:
        logger.warning(
            "Redis cache lookup failed | %s",
            exc,
        )

    # ============================================================
    # 2. RUN RISK ENGINE
    # ============================================================
    started = perf_counter()

    try:
        result = analyze_url(
            normalized_url,
            include_threat_intel=True,
        )

    except Exception as exc:
        logger.exception(
            "URL analysis failed | request_id=%s",
            request_id,
        )

        raise RuntimeError(
            f"URL analysis failed: {exc}"
        ) from exc

    duration_ms = (
        perf_counter() - started
    ) * 1000

    # ============================================================
    # 3. EXTRACT RESULT
    # ============================================================
    risk_score = float(
        result.get(
            "risk_score",
            0,
        )
        or 0
    )

    risk_level = str(
        result.get(
            "risk_level",
            "UNKNOWN",
        )
    )

    confidence = float(
        result.get(
            "confidence",
            0,
        )
        or 0
    )

    prediction = str(
        result.get(
            "prediction",
            risk_level,
        )
    )

    trusted_domain = bool(
        result.get(
            "trusted_domain",
            False,
        )
    )

    models = _safe_models(result)

    threat_intelligence = (
        result.get(
            "threat_intelligence"
        )
        or {}
    )

    # ============================================================
    # 4. BUILD RESPONSE
    # ============================================================
    response = {
        "success": True,

        "url": normalized_url,

        "risk": {
            "score": risk_score,
            "level": risk_level,
            "confidence": confidence,
        },

        "prediction": prediction,

        "trusted_domain": trusted_domain,

        "reasons": list(
            dict.fromkeys(
                result.get(
                    "reasons"
                )
                or []
            )
        ),

        "models": models,

        "threat_intelligence": (
            threat_intelligence
        ),

        "scan_duration_ms": round(
            duration_ms,
            2,
        ),

        "timestamp": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),

        "cache": {
            "hit": False,
            "source": "risk_engine",
        },

        "request_id": request_id,
    }

    # ============================================================
    # 5. RATE LIMIT INFORMATION
    # ============================================================
    if rate_limit:
        response["rate_limit"] = {
            key: rate_limit.get(key)
            for key in (
                "limit",
                "remaining",
                "reset_after",
            )
        }

    # ============================================================
    # 6. SAVE TO POSTGRESQL
    # ============================================================
    try:
        db_save_scan(
            url=normalized_url,
            prediction=prediction,
            confidence=confidence,
            risk_score=risk_score,
            risk_level=risk_level,
            trusted_domain=trusted_domain,
            models=models,
            threat_intelligence=(
                threat_intelligence
            ),
            scan_duration_ms=duration_ms,
        )

        logger.info(
            "Scan saved to PostgreSQL | "
            "url=%s | request_id=%s",
            normalized_url,
            request_id,
        )

    except Exception as exc:
        logger.warning(
            "PostgreSQL history write failed | "
            "request_id=%s | %s",
            request_id,
            exc,
        )

    # ============================================================
    # 7. SAVE ANALYSIS RESULT TO REDIS
    # ============================================================
    try:
        set_cached_scan(
            normalized_url,
            response,
        )

    except Exception as exc:
        logger.warning(
            "Redis cache write failed | "
            "request_id=%s | %s",
            request_id,
            exc,
        )

    # ============================================================
    # 8. FINAL LOG
    # ============================================================
    logger.info(
        "Scan complete | url=%s | risk=%s | "
        "score=%.2f | %.2fms | request_id=%s",
        normalized_url,
        risk_level,
        risk_score,
        duration_ms,
        request_id,
    )

    return response
# ----------------------------- System -----------------------------
@app.get("/health", tags=["System"])
async def health_check():
    redis_ok = False
    try:
        redis_ok = bool(redis_health_check())
    except Exception:
        pass
    postgres_ok = False
    try:
        db_get_stats()
        postgres_ok = True
    except Exception:
        pass
    model_ok = True
    try:
        _load_model()
    except Exception:
        model_ok = False
    return {
        "status": "healthy" if model_ok else "degraded",
        "service": "phishguard-ai", "version": app.version,
        "services": {"model": "up" if model_ok else "down", "redis": "up" if redis_ok else "down", "postgresql": "up" if postgres_ok else "down"},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

@app.get("/ready", tags=["System"])
async def readiness_check():
    try:
        _load_model()
        model_ok = True
    except Exception:
        model_ok = False
    try:
        redis_ok = bool(redis_health_check())
    except Exception:
        redis_ok = False
    try:
        db_get_stats(); postgres_ok = True
    except Exception:
        postgres_ok = False
    ready = model_ok and redis_ok and postgres_ok
    payload = {
        "success": ready, "status": "ready" if ready else "not_ready", "service": "phishguard-ai", "version": app.version,
        "services": {"model": "up" if model_ok else "down", "redis": "up" if redis_ok else "down", "postgresql": "up" if postgres_ok else "down"},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    return JSONResponse(status_code=200 if ready else 503, content=payload)

@app.get("/api", tags=["System"])
async def api_info():
    return {
        "name": "PhishGuard AI", "version": app.version, "api_version": "v1",
        "architecture": {"api": "FastAPI", "ml": ["URL ML", "Hostname ML"], "risk_engine": "ML + security rules + threat intelligence", "cache": "Redis", "database": "PostgreSQL", "queue": "Redis-backed"},
        "endpoints": {"scan": f"{API_V1_PREFIX}/scan", "async_scan": f"{API_V1_PREFIX}/scan/async", "status": f"{API_V1_PREFIX}/scan/{{scan_id}}", "history": f"{API_V1_PREFIX}/history", "stats": f"{API_V1_PREFIX}/stats", "auth": f"{API_V1_PREFIX}/auth"},
    }


# ----------------------------- Web pages -----------------------------
@app.get("/", response_class=HTMLResponse, tags=["Web"])
async def home(request: Request):
    if templates is None:
        return HTMLResponse("<h1>PhishGuard AI</h1><p>API is running.</p>")
    try:
        return templates.TemplateResponse(request, "index.html", {"request": request})
    except Exception:
        return HTMLResponse("<h1>PhishGuard AI</h1><p>API is running.</p>", status_code=200)

@app.get("/dashboard", response_class=HTMLResponse, tags=["Web"])
async def dashboard(request: Request):
    if templates is None:
        return HTMLResponse("<h1>PhishGuard AI Dashboard</h1>")
    return templates.TemplateResponse(request, "dashboard.html", {"request": request})

@app.get("/history", response_class=HTMLResponse, tags=["Web"])
async def history_page(request: Request):
    if templates is None:
        return HTMLResponse("<h1>PhishGuard AI History</h1>")
    return templates.TemplateResponse(request, "history.html", {"request": request})


# ----------------------------- Authentication -----------------------------
@app.post(f"{API_V1_PREFIX}/auth/register", response_model=AuthResponse, status_code=201, tags=["Authentication"])
async def register(request: Request, payload: RegisterRequest):
    email = normalize_email(str(payload.email))
    if db_get_user_by_email(email):
        return error_response(request, 409, "EMAIL_ALREADY_EXISTS", "An account with this email already exists.")
    try:
        user = dict(db_create_user(email=email, password_hash=hash_password(payload.password), role="user"))
        token = create_access_token({"sub": str(user["id"]), "email": user["email"], "role": user.get("role", "user")})
        return {"success": True, "access_token": token, "token_type": "bearer", "user": serialize_user(user), "request_id": _request_id(request)}
    except Exception as exc:
        logger.exception("Registration failed | request_id=%s", _request_id(request))
        # Unique constraint races should be reported cleanly.
        if "unique" in str(exc).lower() or "duplicate" in str(exc).lower():
            return error_response(request, 409, "EMAIL_ALREADY_EXISTS", "An account with this email already exists.")
        return error_response(request, 500, "REGISTRATION_FAILED", "Unable to create account.")

@app.post(f"{API_V1_PREFIX}/auth/login", response_model=AuthResponse, tags=["Authentication"])
async def login(request: Request, payload: LoginRequest):
    email = normalize_email(str(payload.email))
    user = db_get_user_by_email(email)
    if not user or not user.get("is_active", False):
        return error_response(request, 401, "INVALID_CREDENTIALS", "Invalid email or password.")
    try:
        valid = verify_password(payload.password, user["password_hash"])
    except Exception:
        logger.exception("Password verification error | request_id=%s", _request_id(request))
        return error_response(request, 500, "AUTHENTICATION_ERROR", "Authentication failed.")
    if not valid:
        return error_response(request, 401, "INVALID_CREDENTIALS", "Invalid email or password.")
    token = create_access_token({"sub": str(user["id"]), "email": user["email"], "role": user.get("role", "user")})
    return {"success": True, "access_token": token, "token_type": "bearer", "user": serialize_user(user), "request_id": _request_id(request)}

@app.get(f"{API_V1_PREFIX}/auth/me", response_model=MeResponse, tags=["Authentication"])
async def get_me(request: Request, current_user: dict = Depends(get_current_user)):
    return {"success": True, "user": serialize_user(current_user), "request_id": _request_id(request)}


# ----------------------------- Synchronous scanning -----------------------------
async def _scan_json(request: Request, payload: ScanRequest, current_user: dict):
    rate_limit, rate_error = apply_rate_limit(request)
    if rate_error:
        return rate_error
    try:
        normalized = validate_url(payload.url)
    except ValueError as exc:
        return error_response(request, 400, "INVALID_URL", str(exc))
    try:
        response = perform_scan(normalized, _request_id(request), rate_limit)
        return JSONResponse(content=response, headers={
            "X-RateLimit-Limit": str(rate_limit.get("limit", 0)),
            "X-RateLimit-Remaining": str(rate_limit.get("remaining", 0)),
            "X-RateLimit-Reset": str(rate_limit.get("reset_after", 0)),
            "X-Request-ID": _request_id(request),
        })
    except RuntimeError as exc:
        return error_response(request, 500, "SCAN_FAILED", str(exc))

@app.post(f"{API_V1_PREFIX}/scan", response_model=ScanResponse, tags=["Scan"], summary="Analyze a URL")
async def api_v1_scan(request: Request, payload: ScanRequest, current_user: dict = Depends(get_current_user)):
    return await _scan_json(request, payload, current_user)

@app.post("/scan", tags=["Legacy"], summary="Legacy form URL scan")
async def legacy_scan(request: Request, url: str = Form(...)):
    rate_limit, rate_error = apply_rate_limit(request)
    if rate_error:
        return rate_error
    try:
        normalized = validate_url(url)
        result = perform_scan(normalized, _request_id(request), rate_limit)
        return JSONResponse(content=result, headers={"X-Request-ID": _request_id(request)})
    except ValueError as exc:
        return error_response(request, 400, "INVALID_URL", str(exc))
    except RuntimeError as exc:
        return error_response(request, 500, "SCAN_FAILED", str(exc))


# ----------------------------- Async scanning -----------------------------
def _queue_scan(request: Request, url: str):
    rate_limit, rate_error = apply_rate_limit(request)
    if rate_error:
        return rate_error
    try:
        normalized = validate_url(url)
        job = create_scan_job(normalized)
        response = {"success": True, "message": "Scan job queued successfully.", "scan_id": str(job["scan_id"]), "status": job["status"], "url": job["url"], "created_at": str(job["created_at"]), "request_id": _request_id(request)}
        return JSONResponse(status_code=202, content=response, headers={"X-Request-ID": _request_id(request)})
    except ValueError as exc:
        return error_response(request, 400, "INVALID_URL", str(exc))
    except Exception:
        logger.exception("Queue failure | request_id=%s", _request_id(request))
        return error_response(request, 500, "QUEUE_ERROR", "Failed to queue scan job.")

@app.post(f"{API_V1_PREFIX}/scan/async", response_model=AsyncScanResponse, status_code=202, tags=["Scan"], summary="Queue a URL scan")
async def api_v1_async_scan(request: Request, payload: AsyncScanRequest, current_user: dict = Depends(get_current_user)):
    return _queue_scan(request, payload.url)

@app.post("/scan/async", tags=["Legacy"], summary="Legacy async URL scan")
async def legacy_async_scan(request: Request, url: str = Form(...)):
    return _queue_scan(request, url)


# ----------------------------- Async job status -----------------------------
@app.get(f"{API_V1_PREFIX}/scan/{{scan_id}}", response_model=ScanStatusResponse, tags=["Scan"])
async def api_v1_scan_status(request: Request, scan_id: str, current_user: dict = Depends(get_current_user)):
    if not scan_id or len(scan_id) > 128 or not re.fullmatch(r"[A-Za-z0-9_-]+", scan_id):
        return error_response(request, 400, "INVALID_SCAN_ID", "Invalid scan ID.")
    job = get_scan_job(scan_id)
    if job is None:
        return error_response(request, 404, "SCAN_NOT_FOUND", "Scan job not found.", {"scan_id": scan_id})
    return {"success": True, "scan_id": scan_id, "status": job.get("status", "unknown"), "url": job.get("url"), "created_at": job.get("created_at"), "result": job.get("result"), "error": job.get("error"), "request_id": _request_id(request)}

@app.get("/scan/{scan_id}", tags=["Legacy"], summary="Legacy async scan status")
async def legacy_scan_status(request: Request, scan_id: str):
    job = get_scan_job(scan_id)
    if job is None:
        return error_response(request, 404, "SCAN_NOT_FOUND", "Scan job not found.")
    return {"success": True, **job, "request_id": _request_id(request)}


# ----------------------------- History & analytics -----------------------------
@app.get(f"{API_V1_PREFIX}/history", tags=["Analytics"], summary="Recent scan history")
async def api_v1_history(request: Request, limit: int = MAX_HISTORY_LIMIT, current_user: dict = Depends(get_current_user)):
    limit = max(1, min(limit, MAX_HISTORY_LIMIT))
    try:
        rows = db_get_recent_scans(limit)
        return {"success": True, "count": len(rows), "limit": limit, "results": rows, "request_id": _request_id(request)}
    except Exception:
        logger.exception("History retrieval failed | request_id=%s", _request_id(request))
        return error_response(request, 500, "HISTORY_ERROR", "Unable to retrieve scan history.")

@app.get(f"{API_V1_PREFIX}/stats", tags=["Analytics"], summary="Scan statistics")
async def api_v1_stats(request: Request, current_user: dict = Depends(get_current_user)):
    try:
        return {"success": True, "data": db_get_stats(), "request_id": _request_id(request)}
    except Exception:
        logger.exception("Statistics retrieval failed | request_id=%s", _request_id(request))
        return error_response(request, 500, "STATS_ERROR", "Unable to retrieve statistics.")

@app.get("/api/history", tags=["Legacy Analytics"])
async def legacy_history(request: Request):
    try:
        rows = db_get_recent_scans(MAX_HISTORY_LIMIT)
        return {"success": True, "count": len(rows), "results": rows}
    except Exception:
        return error_response(request, 500, "HISTORY_ERROR", "Unable to retrieve scan history.")

@app.get("/stats", tags=["Legacy Analytics"])
async def legacy_stats(request: Request):
    try:
        return db_get_stats()
    except Exception:
        return error_response(request, 500, "STATS_ERROR", "Unable to retrieve statistics.")


# ----------------------------- Entry point -----------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")), reload=True)
