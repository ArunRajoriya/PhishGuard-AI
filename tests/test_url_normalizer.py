from utils.url_normalizer import (
    normalize_url,
    get_hostname,
    get_registered_domain,
)


def test_normalize_adds_https():
    url = "example.com"

    result = normalize_url(url)

    assert result == "https://example.com"


def test_normalize_lowercases_hostname():
    url = "HTTPS://EXAMPLE.COM"

    result = normalize_url(url)

    assert result == "https://example.com"


def test_normalize_preserves_path_query_fragment():
    url = "https://EXAMPLE.COM/Login?User=Test#Section"

    result = normalize_url(url)

    assert result == "https://example.com/Login?User=Test#Section"


def test_get_hostname():
    url = "https://www.google.com/search?q=test"

    assert get_hostname(url) == "www.google.com"


def test_get_registered_domain():
    url = "https://www.google.com/search?q=test"

    assert get_registered_domain(url) == "google.com"


def test_get_registered_domain_with_subdomain():
    url = "https://paypal-login.security-check.example.org/account/verify"

    assert get_registered_domain(url) == "example.org"


def test_get_registered_domain_co_uk():
    url = "https://login.example.co.uk/account"

    assert get_registered_domain(url) == "example.co.uk"


def test_ip_address():
    url = "http://192.168.1.10/login"

    assert get_hostname(url) == "192.168.1.10"
    assert get_registered_domain(url) == "192.168.1.10"


def test_trailing_dot_is_removed():
    url = "https://example.com./login"

    assert get_hostname(url) == "example.com"
    assert get_registered_domain(url) == "example.com"


def test_empty_url_raises_error():
    try:
        normalize_url("")
        assert False, "Expected ValueError"
    except ValueError:
        pass