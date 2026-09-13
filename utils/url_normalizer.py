"""
PhishGuard AI - URL Normalizer

Normalizes URLs before feature extraction so that
equivalent URLs produce consistent structural features.
"""

from urllib.parse import urlsplit, urlunsplit


def normalize_url(url: str) -> str:
    """
    Normalize a URL without changing its security-relevant meaning.

    Examples:
        google.com
        https://GOOGLE.COM
        https://google.com/
        https://www.google.com

    The normalizer intentionally does NOT:
        - remove paths
        - remove query parameters
        - remove fragments
        - decode percent encoding
        - remove credentials

    Those can be security-relevant signals.
    """

    if not isinstance(url, str):
        raise TypeError("URL must be a string")

    url = url.strip()

    if not url:
        raise ValueError("URL cannot be empty")

    # Add a scheme for parsing if missing.
    parse_target = url

    if "://" not in parse_target:
        parse_target = "https://" + parse_target

    parsed = urlsplit(parse_target)

    # Normalize scheme.
    scheme = parsed.scheme.lower()

    # Normalize hostname while preserving credentials.
    hostname = parsed.hostname or ""
    hostname = hostname.lower().rstrip(".")

    # Preserve explicit port.
    port = parsed.port

    # Reconstruct authority.
    username = parsed.username
    password = parsed.password

    userinfo = ""

    if username is not None:
        userinfo = username

        if password is not None:
            userinfo += ":" + password

        userinfo += "@"

    host = hostname

    # IPv6 needs brackets when reconstructed.
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"

    if port is not None:
        host = f"{host}:{port}"

    netloc = userinfo + host

    # Normalize path only where it is safe.
    path = parsed.path

    if not path:
        path = ""

    # Keep query and fragment exactly as supplied.
    query = parsed.query
    fragment = parsed.fragment

    return urlunsplit(
        (
            scheme,
            netloc,
            path,
            query,
            fragment,
        )
    )


def get_hostname(url: str) -> str:
    """
    Return normalized hostname.
    """

    normalized = normalize_url(url)

    parsed = urlsplit(normalized)

    return (parsed.hostname or "").lower()


def get_registered_domain(url):
    hostname = get_hostname(url)

    if not hostname:
        return ""

    # IP addresses do not have a registered domain.
    import ipaddress

    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass

    if ":" in hostname:
        return hostname

    parts = hostname.split(".")

    if len(parts) <= 2:
        return hostname

    common_second_level = {
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "com.au",
        "net.au",
        "org.au",
        "co.in",
        "firm.in",
        "net.in",
        "org.in",
        "gen.in",
        "ind.in",
    }

    suffix = ".".join(parts[-2:])

    if suffix in common_second_level and len(parts) >= 3:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])
    """
    Return a conservative registered-domain approximation.

    This intentionally avoids external dependencies such as
    tldextract for now.

    Examples:
        www.google.com -> google.com
        login.example.org -> example.org
    """

    hostname = get_hostname(url)

    if not hostname:
        return ""

    # IPv4 / IPv6
    if ":" in hostname:
        return hostname

    parts = hostname.split(".")

    if len(parts) <= 2:
        return hostname

    # Basic handling for common two-level public suffixes.
    common_second_level = {
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "com.au",
        "net.au",
        "org.au",
        "co.in",
        "firm.in",
        "net.in",
        "org.in",
        "gen.in",
        "ind.in",
    }

    suffix = ".".join(parts[-2:])

    if suffix in common_second_level and len(parts) >= 3:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])


if __name__ == "__main__":

    test_urls = [
        "google.com",
        "https://GOOGLE.COM",
        "https://google.com/",
        "https://www.google.com",
        "HTTPS://WWW.GOOGLE.COM/",
        "https://Example.COM/login",
        "example.com/login?next=%2Faccount",
    ]

    print("=" * 70)
    print("PhishGuard AI - URL Normalizer Test")
    print("=" * 70)

    for url in test_urls:
        print(f"\nOriginal : {url}")
        print(f"Normalized: {normalize_url(url)}")
        print(f"Hostname : {get_hostname(url)}")
        print(f"Domain   : {get_registered_domain(url)}")