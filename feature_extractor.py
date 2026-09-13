import math
import re
from collections import Counter
from urllib.parse import urlsplit

from utils.url_normalizer import normalize_url, get_hostname, get_registered_domain


SUSPICIOUS_WORDS = {
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "secure",
    "security",
    "authenticate",
    "authentication",
    "password",
    "credential",
    "update",
    "confirm",
    "confirmation",
    "billing",
    "payment",
    "invoice",
    "wallet",
    "recover",
    "recovery",
    "unlock",
    "suspend",
    "suspended",
    "alert",
    "webscr",
    "validate",
}

SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "click",
    "top",
    "xyz",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "work",
    "support",
    "country",
    "stream",
    "download",
    "review",
    "party",
    "science",
}

FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "fragment_length",
    "letter_count",
    "digit_count",
    "special_char_count",
    "digit_ratio",
    "letter_ratio",
    "special_char_ratio",
    "dot_count",
    "hyphen_count",
    "slash_count",
    "underscore_count",
    "at_count",
    "equals_count",
    "question_mark_count",
    "ampersand_count",
    "percent_count",
    "hash_count",
    "subdomain_count",
    "is_ip_address",
    "has_punycode",
    "has_credentials",
    "has_https",
    "encoded_char_count",
    "hex_sequence_count",
    "has_url_encoding",
    "path_depth",
    "query_parameter_count",
    "suspicious_word_count",
    "has_suspicious_word",
    "has_suspicious_tld",
    "url_entropy",
    "hostname_entropy",
    "path_entropy",
    "subdomain_ratio",
    "path_to_url_ratio",
    "query_to_url_ratio",
]


def entropy(value: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def is_ip_address(hostname: str) -> int:
    """Detect IPv4-like hostnames."""
    if not hostname:
        return 0

    ipv4_pattern = r"^\d{1,3}(?:\.\d{1,3}){3}$"

    if re.match(ipv4_pattern, hostname):
        parts = hostname.split(".")

        try:
            return int(all(0 <= int(part) <= 255 for part in parts))
        except ValueError:
            return 0

    return 0


def count_encoded_characters(url: str) -> int:
    """Count percent-encoded characters such as %20 or %2F."""
    return len(re.findall(r"%[0-9a-fA-F]{2}", url))


def count_hex_sequences(url: str) -> int:
    """Count suspicious long hexadecimal sequences."""
    return len(
        re.findall(
            r"(?:0x[0-9a-fA-F]+|(?<![a-zA-Z0-9])[0-9a-fA-F]{8,}(?![a-zA-Z0-9]))",
            url,
        )
    )


def get_suspicious_word_count(url: str) -> int:
    """Count suspicious security/phishing-related words."""
    lowered = url.lower()

    return sum(
        1
        for word in SUSPICIOUS_WORDS
        if re.search(rf"(?<![a-z0-9]){re.escape(word)}(?![a-z0-9])", lowered)
    )


def has_suspicious_tld(hostname: str) -> int:
    """Check whether the registered domain uses a suspicious TLD."""
    registered_domain = get_registered_domain(hostname)

    if not registered_domain or "." not in registered_domain:
        return 0

    tld = registered_domain.rsplit(".", 1)[-1].lower()

    return int(tld in SUSPICIOUS_TLDS)


def extract_features(url: str) -> dict:
    """
    Extract exactly 40 URL-only phishing detection features.

    The URL is normalized before feature extraction so that superficial
    differences such as scheme case or hostname case do not create
    inconsistent model inputs.
    """

    normalized_url = normalize_url(url)

    parsed = urlsplit(normalized_url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    hostname_lower = hostname.lower()

    # ---------------------------------------------------------
    # Basic lengths
    # ---------------------------------------------------------

    url_length = len(normalized_url)
    hostname_length = len(hostname)
    path_length = len(path)
    query_length = len(query)
    fragment_length = len(fragment)

    # ---------------------------------------------------------
    # Character statistics
    # ---------------------------------------------------------

    letter_count = sum(char.isalpha() for char in normalized_url)
    digit_count = sum(char.isdigit() for char in normalized_url)

    special_char_count = sum(
        not char.isalnum() for char in normalized_url
    )

    digit_ratio = digit_count / url_length if url_length else 0.0
    letter_ratio = letter_count / url_length if url_length else 0.0
    special_char_ratio = (
        special_char_count / url_length
        if url_length
        else 0.0
    )

    # ---------------------------------------------------------
    # URL structure
    # ---------------------------------------------------------

    dot_count = normalized_url.count(".")
    hyphen_count = normalized_url.count("-")
    slash_count = normalized_url.count("/")
    underscore_count = normalized_url.count("_")
    at_count = normalized_url.count("@")
    equals_count = normalized_url.count("=")
    question_mark_count = normalized_url.count("?")
    ampersand_count = normalized_url.count("&")
    percent_count = normalized_url.count("%")
    hash_count = normalized_url.count("#")

        # ---------------------------------------------------------
    # Host features
    # ---------------------------------------------------------

    domain_parts = hostname_lower.split(".") if hostname_lower else []

    # Registered domain is not counted as a subdomain.
    registered_domain = get_registered_domain(hostname_lower)

    subdomain_count = 0

    if registered_domain and hostname_lower.endswith(registered_domain):
        prefix = hostname_lower[: -len(registered_domain)].rstrip(".")

        if prefix:
            subdomain_parts = prefix.split(".")

            # "www" is a standard web prefix, not a suspicious subdomain.
            if subdomain_parts and subdomain_parts[0] == "www":
                subdomain_parts = subdomain_parts[1:]

            subdomain_count = len(subdomain_parts)

    elif len(domain_parts) > 2:
        subdomain_parts = domain_parts[:-2]

        if subdomain_parts and subdomain_parts[0] == "www":
            subdomain_parts = subdomain_parts[1:]

        subdomain_count = len(subdomain_parts)

    # ---------------------------------------------------------
    # Security / obfuscation features
    # ---------------------------------------------------------

    ip_flag = is_ip_address(hostname_lower)

    has_punycode = int(
        "xn--" in hostname_lower
    )

    has_credentials = int(
        parsed.username is not None
        or parsed.password is not None
        or "@" in parsed.netloc
    )

    has_https = int(
        parsed.scheme.lower() == "https"
    )

    encoded_char_count = count_encoded_characters(
        normalized_url
    )

    hex_sequence_count = count_hex_sequences(
        normalized_url
    )

    has_url_encoding = int(
        encoded_char_count > 0
    )

    # ---------------------------------------------------------
    # Path / query complexity
    # ---------------------------------------------------------

    path_segments = [
        segment
        for segment in path.split("/")
        if segment
    ]

    path_depth = len(path_segments)

    query_parameter_count = 0

    if query:
        query_parameter_count = len(
            [
                item
                for item in query.split("&")
                if item
            ]
        )

    # ---------------------------------------------------------
    # Suspicious lexical signals
    # ---------------------------------------------------------

    suspicious_word_count = get_suspicious_word_count(
        normalized_url
    )

    has_suspicious_word = int(
        suspicious_word_count > 0
    )

    suspicious_tld_flag = has_suspicious_tld(
        hostname_lower
    )

    # ---------------------------------------------------------
    # Entropy
    # ---------------------------------------------------------

    url_entropy = entropy(normalized_url)
    hostname_entropy = entropy(hostname_lower)
    path_entropy = entropy(path)

    # ---------------------------------------------------------
    # Ratios
    # ---------------------------------------------------------

    subdomain_ratio = (
        subdomain_count / len(domain_parts)
        if domain_parts
        else 0.0
    )

    path_to_url_ratio = (
        path_length / url_length
        if url_length
        else 0.0
    )

    query_to_url_ratio = (
        query_length / url_length
        if url_length
        else 0.0
    )

    features = {
        "url_length": url_length,
        "hostname_length": hostname_length,
        "path_length": path_length,
        "query_length": query_length,
        "fragment_length": fragment_length,
        "letter_count": letter_count,
        "digit_count": digit_count,
        "special_char_count": special_char_count,
        "digit_ratio": digit_ratio,
        "letter_ratio": letter_ratio,
        "special_char_ratio": special_char_ratio,
        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "slash_count": slash_count,
        "underscore_count": underscore_count,
        "at_count": at_count,
        "equals_count": equals_count,
        "question_mark_count": question_mark_count,
        "ampersand_count": ampersand_count,
        "percent_count": percent_count,
        "hash_count": hash_count,
        "subdomain_count": subdomain_count,
        "is_ip_address": ip_flag,
        "has_punycode": has_punycode,
        "has_credentials": has_credentials,
        "has_https": has_https,
        "encoded_char_count": encoded_char_count,
        "hex_sequence_count": hex_sequence_count,
        "has_url_encoding": has_url_encoding,
        "path_depth": path_depth,
        "query_parameter_count": query_parameter_count,
        "suspicious_word_count": suspicious_word_count,
        "has_suspicious_word": has_suspicious_word,
        "has_suspicious_tld": suspicious_tld_flag,
        "url_entropy": url_entropy,
        "hostname_entropy": hostname_entropy,
        "path_entropy": path_entropy,
        "subdomain_ratio": subdomain_ratio,
        "path_to_url_ratio": path_to_url_ratio,
        "query_to_url_ratio": query_to_url_ratio,
    }

    # Safety check: the model schema must always remain exactly 40 features.
    if list(features.keys()) != FEATURE_NAMES:
        raise RuntimeError(
            f"Feature schema mismatch. "
            f"Expected {len(FEATURE_NAMES)} features, "
            f"got {len(features)}."
        )

    return features


if __name__ == "__main__":

    test_urls = [
        "example.com",
        "https://EXAMPLE.COM/",
        "https://www.google.com/search?q=test",
        "https://paypal-login.security-check.example.org/account/verify",
        "http://192.168.1.10/login",
        "https://user:password@example.com/login",
        "https://example.com/a%20b?token=123",
    ]

    for url in test_urls:
        print("=" * 80)
        print("Original:", url)

        normalized = normalize_url(url)
        print("Normalized:", normalized)

        print("Hostname:", get_hostname(url))
        print("Registered domain:", get_registered_domain(url))

        features = extract_features(url)

        print("Feature count:", len(features))

        for name, value in features.items():
            print(f"{name}: {value}")