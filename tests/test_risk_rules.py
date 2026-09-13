from utils.risk_rules import analyze_url


def test_safe_google_url():
    result = analyze_url("https://www.google.com")

    assert result["risk_score"] < 30
    assert result["risk_level"] in {"MINIMAL", "LOW"}


def test_credentials_are_high_risk():
    result = analyze_url(
        "https://admin:password@example.com/login"
    )

    assert result["signals"]["has_credentials"] is True
    assert result["risk_score"] >= 60


def test_ip_login_is_suspicious():
    result = analyze_url(
        "http://192.168.1.10/login"
    )

    assert result["signals"]["is_ip_address"] is True
    assert result["risk_score"] >= 30


def test_suspicious_tld():
    result = analyze_url(
        "https://example.xyz/account/verify"
    )

    assert result["signals"]["suspicious_tld"] is True
    assert result["risk_score"] >= 10


def test_brand_impersonation():
    result = analyze_url(
        "https://paypal-security.example.xyz/login"
    )

    assert result["signals"]["brand_impersonation"] is True
    assert result["risk_score"] >= 60


def test_suspicious_auth_path():
    result = analyze_url(
        "https://example.com/login/verify/account"
    )

    assert result["signals"]["suspicious_path_structure"] is True


def test_multiple_suspicious_words():
    result = analyze_url(
        "https://paypal-login-security.example.com/verify"
    )

    assert result["signals"]["suspicious_word_count"] >= 3
    assert result["risk_score"] >= 10


def test_legitimate_paypal_domain_not_impersonation():
    result = analyze_url(
        "https://www.paypal.com/login"
    )

    assert result["signals"]["brand_impersonation"] is False


def test_legitimate_microsoft_domain_not_impersonation():
    result = analyze_url(
        "https://www.microsoft.com/account/login"
    )

    assert result["signals"]["brand_impersonation"] is False


def test_result_contains_required_fields():
    result = analyze_url("https://example.com")

    assert "normalized_url" in result
    assert "hostname" in result
    assert "risk_score" in result
    assert "risk_level" in result
    assert "signals" in result
    assert "reasons" in result