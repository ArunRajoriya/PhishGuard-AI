import pytest
from fastapi.testclient import TestClient

import app as app_module
from app import create_access_token
from datetime import datetime, timezone

client = TestClient(app_module.app)

TEST_USER = {
    "id": 999999,
    "email": "pytest-auth@example.com",
    "role": "user",
    "is_active": True,
    "created_at": datetime(2026, 9, 10, tzinfo=timezone.utc),
}

TEST_TOKEN = create_access_token({"sub": str(TEST_USER["id"])})
AUTH_HEADERS = {"Authorization": f"Bearer {TEST_TOKEN}"}


@pytest.fixture(autouse=True)
def isolate_external_services(monkeypatch):
    """Prevent tests from depending on Redis, PostgreSQL, or VirusTotal."""

    monkeypatch.setattr(
        app_module,
        "check_rate_limit",
        lambda ip: {
    "allowed": True,
    "limit": 30,
    "remaining": 29,
    "reset_after": 60,
},
    )

    monkeypatch.setattr(
        app_module,
        "get_cached_scan",
        lambda url: None,
    )

    monkeypatch.setattr(
        app_module,
        "set_cached_scan",
        lambda url, result: True,
    )

    monkeypatch.setattr(
        app_module,
        "save_scan",
        lambda **kwargs: True,
    )

    monkeypatch.setattr(
        app_module,
        "get_user_by_id",
        lambda user_id: TEST_USER if int(user_id) == TEST_USER["id"] else None,
    )

    def fake_analyze_url(url, include_threat_intel=True):
        return {
            "risk_score": 12.5,
            "risk_level": "SAFE",
            "confidence": 96.0,
            "prediction": "LEGITIMATE",
            "trusted_domain": True,
            "reasons": ["Trusted domain"],
            "models": {
                "url_ml": 2.0,
                "hostname_ml": 1.0,
                "model_score": 1.5,
                "rule_score": 0.0,
            },
            "threat_intelligence": {
                "provider": "test",
                "status": "disabled",
                "threat_score": 0,
                "malicious": 0,
                "suspicious": 0,
                "total_engines": 0,
                "cached": False,
            },
        }

    monkeypatch.setattr(
        app_module,
        "analyze_url",
        fake_analyze_url,
    )


# ---------------------------------------------------------
# BASIC APPLICATION TESTS
# ---------------------------------------------------------

def test_root():
    response = client.get("/")

    assert response.status_code == 200


def test_api_info():
    response = client.get("/api")

    assert response.status_code == 200

    data = response.json()

    assert "name" in data
    assert "version" in data


# ---------------------------------------------------------
# DOCUMENTATION
# ---------------------------------------------------------

def test_openapi():
    response = client.get("/openapi.json")

    assert response.status_code == 200

    data = response.json()

    assert "openapi" in data
    assert "paths" in data


def test_swagger_docs():
    response = client.get("/docs")

    assert response.status_code == 200


def test_redoc():
    response = client.get("/redoc")

    assert response.status_code == 200


# ---------------------------------------------------------
# REQUEST ID
# ---------------------------------------------------------

def test_request_id_is_generated():
    response = client.get("/api")

    assert response.status_code == 200
    assert "X-Request-ID" in response.headers

    request_id = response.headers["X-Request-ID"]

    assert len(request_id) > 0


def test_request_id_is_preserved():
    request_id = "test-request-123"

    response = client.get(
        "/api",
        headers={"X-Request-ID": request_id},
    )

    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == request_id


# ---------------------------------------------------------
# HEALTH / READINESS
# ---------------------------------------------------------

def test_health(monkeypatch):
    monkeypatch.setattr(
        app_module,
        "redis_health_check",
        lambda: True,
    )

    monkeypatch.setattr(
        app_module,
        "get_stats",
        lambda: {"total_scans": 10},
    )

    response = client.get("/health")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "healthy"


def test_ready(monkeypatch):
    monkeypatch.setattr(
        app_module,
        "redis_health_check",
        lambda: True,
    )

    monkeypatch.setattr(
        app_module,
        "get_stats",
        lambda: {"total_scans": 10},
    )

    response = client.get("/ready")

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True


def test_not_ready_when_redis_is_down(monkeypatch):
    monkeypatch.setattr(
        app_module,
        "redis_health_check",
        lambda: False,
    )

    monkeypatch.setattr(
        app_module,
        "get_stats",
        lambda: {"total_scans": 10},
    )

    response = client.get("/ready")

    assert response.status_code == 503


# ---------------------------------------------------------
# AUTHENTICATION
# ---------------------------------------------------------

def test_auth_me_requires_token():
    response = client.get("/api/v1/auth/me")
    assert response.status_code in (401, 403)


def test_protected_scan_requires_token():
    response = client.post(
        "/api/v1/scan",
        json={"url": "https://google.com"},
    )
    assert response.status_code in (401, 403)


def test_auth_me_with_valid_token():
    response = client.get(
        "/api/v1/auth/me",
        headers=AUTH_HEADERS,
    )

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True
    assert data["user"]["id"] == TEST_USER["id"]
    assert data["user"]["email"] == TEST_USER["email"]


def test_protected_scan_with_valid_token():
    response = client.post(
        "/api/v1/scan",
        headers=AUTH_HEADERS,
        json={"url": "https://google.com"},
    )

    assert response.status_code == 200


def test_invalid_token_is_rejected():
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer invalid-token"},
    )

    assert response.status_code in (401, 403)


# ---------------------------------------------------------
# API V1 SCAN
# ---------------------------------------------------------

def test_api_v1_scan():
    response = client.post(
        "/api/v1/scan",
        headers=AUTH_HEADERS,
        json={
            "url": "https://google.com"
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True
    assert "url" in data
    assert "prediction" in data
    assert "risk" in data
    assert "models" in data


def test_api_v1_scan_returns_correct_url():
    url = "https://google.com"

    response = client.post(
        "/api/v1/scan",
        headers=AUTH_HEADERS,
        json={"url": url},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["url"] == url


def test_api_v1_scan_contains_risk_information():
    response = client.post(
        "/api/v1/scan",
        headers=AUTH_HEADERS,
        json={
            "url": "https://google.com"
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert "score" in data["risk"]
    assert "level" in data["risk"]
    assert "confidence" in data["risk"]


def test_api_v1_scan_contains_model_scores():
    response = client.post(
        "/api/v1/scan",
        headers=AUTH_HEADERS,
        json={
            "url": "https://google.com"
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert "url_ml" in data["models"]
    assert "hostname_ml" in data["models"]
    assert "fusion_score" in data["models"]
    assert "rule_score" in data["models"]


# ---------------------------------------------------------
# VALIDATION
# ---------------------------------------------------------

def test_scan_requires_url():
    response = client.post(
        "/api/v1/scan",
        headers=AUTH_HEADERS,
        json={},
    )

    assert response.status_code == 422


def test_scan_rejects_invalid_url():
    response = client.post(
        "/api/v1/scan",
        headers=AUTH_HEADERS,
        json={
            "url": "not-a-valid-url"
        },
    )

    assert response.status_code == 400


def test_scan_rejects_empty_url():
    response = client.post(
        "/api/v1/scan",
        headers=AUTH_HEADERS,
        json={
            "url": ""
        },
    )

    assert response.status_code == 422


# ---------------------------------------------------------
# CACHE
# ---------------------------------------------------------

def test_scan_cache_hit(monkeypatch):
    cached_result = {
        "risk_score": 10.0,
        "risk_level": "SAFE",
        "confidence": 99.0,
        "prediction": "LEGITIMATE",
        "trusted_domain": True,
        "reasons": ["Cached result"],
        "models": {
            "url_ml": 1.0,
            "hostname_ml": 1.0,
            "model_score": 1.0,
            "rule_score": 0.0,
        },
        "threat_intelligence": {
            "provider": "test",
            "status": "cached",
            "threat_score": 0,
            "malicious": 0,
            "suspicious": 0,
            "total_engines": 0,
            "cached": True,
        },
    }

    monkeypatch.setattr(
        app_module,
        "get_cached_scan",
        lambda url: cached_result,
    )

    def fail_analyze(*args, **kwargs):
        pytest.fail("analyze_url should not run on cache hit")

    monkeypatch.setattr(
        app_module,
        "analyze_url",
        fail_analyze,
    )

    response = client.post(
        "/api/v1/scan",
        headers=AUTH_HEADERS,
        json={
            "url": "https://google.com"
        },
    )

    assert response.status_code == 200


# ---------------------------------------------------------
# ASYNC SCANNING
# ---------------------------------------------------------

def test_async_scan(monkeypatch):
    monkeypatch.setattr(
    app_module,
    "create_scan_job",
    lambda url: {
        "scan_id": "test-job-123",
        "status": "queued",
        "url": url,
        "created_at": "2026-09-09T00:00:00+00:00",
    },
)

    response = client.post(
        "/api/v1/scan/async",
        headers=AUTH_HEADERS,
        json={
            "url": "https://google.com"
        },
    )

    assert response.status_code == 202

    data = response.json()

    assert data["scan_id"] == "test-job-123"
    assert data["status"] == "queued"


def test_async_scan_requires_url():
    response = client.post(
        "/api/v1/scan/async",
        headers=AUTH_HEADERS,
        json={},
    )

    assert response.status_code == 422


# ---------------------------------------------------------
# ASYNC STATUS
# ---------------------------------------------------------

def test_scan_status(monkeypatch):
    monkeypatch.setattr(
        app_module,
        "get_scan_job",
        lambda scan_id: {
            "scan_id": scan_id,
            "status": "completed",
            "result": {
                "prediction": "LEGITIMATE",
            },
        },
    )

    response = client.get(
        "/api/v1/scan/test-job-123",
        headers=AUTH_HEADERS
    )

    assert response.status_code == 200

    data = response.json()

    assert data["scan_id"] == "test-job-123"
    assert data["status"] == "completed"


def test_scan_status_not_found(monkeypatch):
    monkeypatch.setattr(
        app_module,
        "get_scan_job",
        lambda scan_id: None,
    )

    response = client.get(
        "/api/v1/scan/non-existent",
        headers=AUTH_HEADERS
    )

    assert response.status_code == 404


# ---------------------------------------------------------
# RATE LIMITING
# ---------------------------------------------------------

def test_rate_limit_response(monkeypatch):
    monkeypatch.setattr(
        app_module,
        "check_rate_limit",
        lambda ip: {
    "allowed": False,
    "limit": 30,
    "remaining": 0,
    "reset_after": 60,
},
    )

    response = client.post(
        "/api/v1/scan",
        headers=AUTH_HEADERS,
        json={
            "url": "https://google.com"
        },
    )

    assert response.status_code == 429

    assert "Retry-After" in response.headers


# ---------------------------------------------------------
# LEGACY ENDPOINT
# ---------------------------------------------------------

def test_legacy_scan_endpoint():
    response = client.post(
        "/scan",
        data={
            "url": "https://google.com"
        },
    )

    assert response.status_code == 200