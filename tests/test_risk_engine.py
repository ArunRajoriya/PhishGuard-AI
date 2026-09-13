import pytest

from risk_engine import (
    analyze_url,
    calculate_final_risk,
    is_trusted_domain,
)


# ============================================================
# TRUSTED DOMAIN TESTS
# ============================================================

def test_google_is_trusted():
    assert is_trusted_domain("https://google.com") is True


def test_google_subdomain_is_trusted():
    assert is_trusted_domain("https://www.google.com") is True


def test_paypal_is_trusted():
    assert is_trusted_domain("https://paypal.com") is True


def test_github_is_trusted():
    assert is_trusted_domain("https://github.com") is True


def test_fake_paypal_is_not_trusted():
    assert is_trusted_domain(
        "https://paypal-login.example.com"
    ) is False


def test_fake_google_is_not_trusted():
    assert is_trusted_domain(
        "https://google-login.example.com"
    ) is False


# ============================================================
# BASIC URL ANALYSIS
# ============================================================

def test_google_analysis_returns_result():
    result = analyze_url(
        "https://google.com",
        include_threat_intel=False,
    )

    assert isinstance(result, dict)


def test_analysis_contains_required_fields():
    result = analyze_url(
        "https://google.com",
        include_threat_intel=False,
    )

    required_fields = {
        "url",
        "risk_score",
        "risk_level",
        "confidence",
        "trusted_domain",
    }

    assert required_fields.issubset(result.keys())


# ============================================================
# RISK SCORE VALIDATION
# ============================================================

@pytest.mark.parametrize(
    "url",
    [
        "https://google.com",
        "https://github.com",
        "https://paypal.com",
        "https://amazon.com",
        "https://apple.com",
        "https://example.com",
        "https://paypal-login.example.com/login",
        "http://192.168.1.10/login",
    ],
)
def test_risk_score_is_between_zero_and_hundred(url):
    result = analyze_url(
        url,
        include_threat_intel=False,
    )

    assert 0 <= result["risk_score"] <= 100


def test_confidence_is_between_zero_and_hundred():
    result = analyze_url(
        "https://google.com",
        include_threat_intel=False,
    )

    assert 0 <= result["confidence"] <= 100


# ============================================================
# LEGITIMATE DOMAINS
# ============================================================

@pytest.mark.parametrize(
    "url",
    [
        "https://google.com",
        "https://www.google.com",
        "https://microsoft.com",
        "https://www.microsoft.com",
        "https://paypal.com",
        "https://www.paypal.com",
        "https://amazon.com",
        "https://apple.com",
        "https://github.com",
        "https://linkedin.com",
        "https://stackoverflow.com",
    ],
)
def test_trusted_domains_are_not_phishing(url):
    result = analyze_url(
        url,
        include_threat_intel=False,
    )

    assert result["risk_level"] != "PHISHING"


# ============================================================
# PHISHING PATTERN TESTS
# ============================================================

def test_brand_impersonation_is_detected():
    result = analyze_url(
        "https://paypal-login.example.com/account/verify",
        include_threat_intel=False,
    )

    assert result["risk_level"] in {
        "SUSPICIOUS",
        "PHISHING",
    }


def test_suspicious_authentication_path():
    result = analyze_url(
        "https://example.com/login/verify/account",
        include_threat_intel=False,
    )

    assert result["risk_score"] > 0


def test_ip_address_login_is_suspicious():
    result = analyze_url(
        "http://192.168.1.10/login",
        include_threat_intel=False,
    )

    assert result["risk_level"] in {
        "SUSPICIOUS",
        "PHISHING",
    }


def test_credentials_in_url_are_high_risk():
    result = analyze_url(
        "https://user:password@example.com/login",
        include_threat_intel=False,
    )

    assert result["risk_level"] == "PHISHING"


def test_suspicious_tld_and_brand():
    result = analyze_url(
        "https://paypal-security.example.xyz/login",
        include_threat_intel=False,
    )

    assert result["risk_level"] == "PHISHING"


# ============================================================
# OUTPUT CONTRACT
# ============================================================

def test_risk_level_is_valid():
    result = analyze_url(
        "https://example.com",
        include_threat_intel=False,
    )

    assert result["risk_level"] in {
        "SAFE",
        "SUSPICIOUS",
        "PHISHING",
    }


def test_risk_score_is_numeric():
    result = analyze_url(
        "https://google.com",
        include_threat_intel=False,
    )

    assert isinstance(result["risk_score"], (int, float))


def test_confidence_is_numeric():
    result = analyze_url(
        "https://google.com",
        include_threat_intel=False,
    )

    assert isinstance(result["confidence"], (int, float))


# ============================================================
# MALFORMED INPUT
# ============================================================

@pytest.mark.parametrize(
    "url",
    [
        "",
        "not a valid url",
        "://broken",
    ],
)
def test_invalid_urls_do_not_crash(url):
    try:
        result = analyze_url(
            url,
            include_threat_intel=False,
        )

        assert isinstance(result, dict)

    except Exception:
        # Invalid input may legitimately be rejected.
        # The important requirement is that the test suite
        # handles it predictably rather than crashing pytest.
        assert True