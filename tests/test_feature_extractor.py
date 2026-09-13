from feature_extractor import extract_features, FEATURE_NAMES


def test_feature_count():
    features = extract_features("https://example.com")
    assert len(features) == 40
    assert len(FEATURE_NAMES) == 40


def test_feature_names_are_unique():
    assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES))


def test_https_detection():
    https_features = extract_features("https://example.com")
    http_features = extract_features("http://example.com")

    assert https_features["has_https"] == 1
    assert http_features["has_https"] == 0


def test_ip_address_detection():
    features = extract_features("http://192.168.1.10/login")

    assert features["is_ip_address"] == 1


def test_credentials_detection():
    features = extract_features(
        "https://admin:password@example.com/login"
    )

    assert features["has_credentials"] == 1
    assert features["at_count"] == 1


def test_subdomain_count():
    features = extract_features(
        "https://login.security.example.com/account"
    )

    assert features["subdomain_count"] == 2


def test_suspicious_words():
    features = extract_features(
        "https://paypal-login-security.example.com/verify-account"
    )

    assert features["has_suspicious_word"] == 1
    assert features["suspicious_word_count"] > 0


def test_url_encoding_detection():
    features = extract_features(
        "https://example.com/%2Flogin"
    )

    assert features["has_url_encoding"] == 1
    assert features["encoded_char_count"] > 0


def test_query_parameters():
    features = extract_features(
        "https://example.com/login?user=test&redirect=home"
    )

    assert features["query_parameter_count"] == 2


def test_path_depth():
    features = extract_features(
        "https://example.com/a/b/c/login"
    )

    assert features["path_depth"] == 4