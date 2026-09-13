import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlsplit

from utils.url_normalizer import normalize_url, get_hostname


# ============================================================
# SECURITY SIGNAL DEFINITIONS
# ============================================================

SUSPICIOUS_WORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "update",
    "confirm",
    "confirmation",
    "password",
    "credential",
    "wallet",
    "payment",
    "invoice",
    "unlock",
    "suspended",
    "recover",
    "authentication",
    "authorize",
    "banking",
}

SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "click",
    "zip",
    "mov",
    "work",
    "gq",
    "tk",
    "ml",
    "cf",
    "ga",
}

BRAND_NAMES = {
    "paypal",
    "microsoft",
    "office365",
    "google",
    "apple",
    "amazon",
    "facebook",
    "instagram",
    "linkedin",
    "netflix",
    "github",
    "coinbase",
    "binance",
    "adobe",
    "docusign",
}


# ============================================================
# LEGITIMATE BRAND DOMAINS
# ============================================================

LEGITIMATE_BRAND_DOMAINS = {
    "paypal": {
        "paypal.com",
    },
    "microsoft": {
        "microsoft.com",
        "live.com",
    },
    "office365": {
        "microsoft.com",
        "office.com",
    },
    "google": {
        "google.com",
    },
    "apple": {
        "apple.com",
    },
    "amazon": {
        "amazon.com",
    },
    "facebook": {
        "facebook.com",
        "fb.com",
    },
    "instagram": {
        "instagram.com",
    },
    "linkedin": {
        "linkedin.com",
    },
    "netflix": {
        "netflix.com",
    },
    "github": {
        "github.com",
    },
    "coinbase": {
        "coinbase.com",
    },
    "binance": {
        "binance.com",
    },
    "adobe": {
        "adobe.com",
    },
    "docusign": {
        "docusign.com",
    },
}


# ============================================================
# URL PARSING HELPERS
# ============================================================

def _safe_split(url: str):
    """
    Normalize and safely parse a URL.

    Returns:
        tuple[str, SplitResult]
    """

    normalized = normalize_url(url)
    parsed = urlsplit(normalized)

    return normalized, parsed


def _is_ip(hostname: str) -> bool:
    """
    Return True when hostname is an IPv4 or IPv6 address.
    """

    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True

    except ValueError:
        return False


def _entropy(value: str) -> float:
    """
    Calculate Shannon entropy.

    Higher values indicate more randomness/diversity.
    """

    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


# ============================================================
# SUSPICIOUS LANGUAGE
# ============================================================

def _suspicious_word_count(url: str) -> int:
    """
    Count security-sensitive words appearing in the URL.

    Word boundaries prevent partial matches such as:
        login -> login
        logging -> not counted as login
    """

    lowered = url.lower()

    return sum(
        len(
            re.findall(
                rf"\b{re.escape(word)}\b",
                lowered,
            )
        )
        for word in SUSPICIOUS_WORDS
    )


# ============================================================
# CREDENTIAL DETECTION
# ============================================================

def _has_credentials(parsed_url) -> bool:
    """
    Detect username/password credentials embedded in URL.
    """

    return (
        parsed_url.username is not None
        or parsed_url.password is not None
    )


# ============================================================
# TLD DETECTION
# ============================================================

def _suspicious_tld(hostname: str) -> bool:
    """
    Detect known high-risk/suspicious TLDs.

    This is only a risk signal.
    A suspicious TLD is NOT automatically malicious.
    """

    if not hostname or "." not in hostname:
        return False

    tld = hostname.rsplit(".", 1)[-1].lower()

    return tld in SUSPICIOUS_TLDS


# ============================================================
# REGISTERED DOMAIN
# ============================================================

def _registered_domain(hostname: str) -> str:
    """
    Extract a practical registered-domain approximation.

    Examples:
        www.google.com -> google.com
        login.example.co.uk -> example.co.uk
    """

    if not hostname:
        return ""

    hostname = hostname.lower().strip(".")

    if _is_ip(hostname):
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


# ============================================================
# BRAND IMPERSONATION
# ============================================================

def _brand_impersonation(hostname: str) -> list[str]:
    """
    Detect possible brand impersonation.

    Important:

    Legitimate:
        google.com
        www.google.com
        accounts.google.com

    Suspicious:
        google-login.example.com
        paypal-security.example.com
        microsoft-verify.example.net

    The function therefore checks whether the registered domain
    actually belongs to the brand.
    """

    if not hostname:
        return []

    hostname = hostname.lower().strip(".")

    registered_domain = _registered_domain(hostname)

    matches = []

    for brand in BRAND_NAMES:

        if brand not in hostname:
            continue

        legitimate_domains = LEGITIMATE_BRAND_DOMAINS.get(
            brand,
            set(),
        )

        is_legitimate = (
            registered_domain in legitimate_domains
        )

        if not is_legitimate:
            matches.append(brand)

    return matches


# ============================================================
# SUBDOMAIN COUNT
# ============================================================

def _subdomain_count(hostname: str) -> int:
    """
    Count subdomain labels.

    Examples:
        google.com -> 0
        www.google.com -> 1
        login.security.example.com -> 2
    """

    if not hostname or _is_ip(hostname):
        return 0

    parts = hostname.split(".")

    if len(parts) <= 2:
        return 0

    return len(parts) - 2


# ============================================================
# RISK SCORE
# ============================================================

def calculate_risk_score(
    signals: dict,
) -> tuple[int, list[str]]:
    """
    Calculate deterministic rule-based risk score.

    IMPORTANT:
        This is NOT the final ML prediction.

    The rule engine provides supporting security evidence
    which can later be combined with:

        - XGBoost probability
        - hostname model probability
        - VirusTotal
        - domain intelligence
        - other threat intelligence
    """

    score = 0
    reasons = []

    def add(points: int, reason: str):
        nonlocal score

        score += points
        reasons.append(reason)

    # ========================================================
    # STRONG INDIVIDUAL SIGNALS
    # ========================================================

    if signals["has_credentials"]:
        add(
            25,
            "Credentials embedded in URL",
        )

    if signals["has_at_symbol"]:
        add(
            20,
            "@ symbol can obscure the destination",
        )

    if signals["is_ip_address"]:
        add(
            15,
            "IP address used instead of a domain",
        )

    if signals["excessive_percent_encoding"]:
        add(
            15,
            "Excessive URL encoding",
        )

    # ========================================================
    # HOSTNAME SIGNALS
    # ========================================================

    if signals["excessive_subdomains"]:
        add(
            15,
            "Excessive number of subdomains",
        )

    if signals["suspicious_tld"]:
        add(
            10,
            "Suspicious top-level domain",
        )

    if signals["brand_impersonation"]:
        add(
            20,
            "Possible brand impersonation",
        )

    # ========================================================
    # SUSPICIOUS LANGUAGE
    # ========================================================

    suspicious_word_count = signals[
        "suspicious_word_count"
    ]

    if suspicious_word_count >= 3:

        add(
            10,
            "Multiple security-sensitive words found in URL",
        )

    elif suspicious_word_count > 0:

        add(
            4,
            "Security-sensitive words found in URL",
        )

    # ========================================================
    # PATH STRUCTURE
    # ========================================================

    if signals["suspicious_path_structure"]:

        add(
            5,
            "Suspicious authentication/account path",
        )

    if signals["deep_path"]:

        add(
            5,
            "Unusually deep URL path",
        )

    # ========================================================
    # QUERY STRUCTURE
    # ========================================================

    if signals["many_query_parameters"]:

        add(
            5,
            "Large number of query parameters",
        )

    # ========================================================
    # RANDOMNESS / OBFUSCATION
    # ========================================================

    if signals["high_hostname_entropy"]:

        add(
            10,
            "High hostname randomness",
        )

    if signals["high_path_entropy"]:

        add(
            5,
            "High path randomness",
        )

    # ========================================================
    # URL LENGTH
    # ========================================================

    if signals["very_long_url"]:

        add(
            5,
            "Unusually long URL",
        )

    if signals["very_long_hostname"]:

        add(
            5,
            "Unusually long hostname",
        )

    # ========================================================
    # HTTP
    # ========================================================

    if signals["insecure_http"]:

        add(
            3,
            "Connection does not use HTTPS",
        )

    # ========================================================
    # COMBINATION RULES
    # ========================================================

    # Brand impersonation + suspicious language
    if (
        signals["brand_impersonation"]
        and suspicious_word_count >= 2
    ):

        add(
            20,
            "Brand impersonation combined with suspicious language",
        )

    # IP + authentication path
    if (
        signals["is_ip_address"]
        and signals["suspicious_path_structure"]
    ):

        add(
            15,
            "IP address combined with authentication path",
        )

    # Credentials + authentication path
    if (
        signals["has_credentials"]
        and signals["suspicious_path_structure"]
    ):

        add(
            15,
            "Credentials combined with authentication path",
        )

    # Suspicious TLD + authentication path
    if (
        signals["suspicious_tld"]
        and signals["suspicious_path_structure"]
    ):

        add(
            10,
            "Suspicious TLD combined with authentication path",
        )

    # Suspicious TLD + brand impersonation
    if (
        signals["suspicious_tld"]
        and signals["brand_impersonation"]
    ):

        add(
            15,
            "Suspicious TLD combined with possible brand impersonation",
        )

    # ========================================================
    # CAP SCORE
    # ========================================================

    score = min(score, 100)

    return score, reasons


# ============================================================
# MAIN ANALYZER
# ============================================================

def analyze_url(url: str) -> dict:
    """
    Generate deterministic security signals from a URL.

    These signals are NOT the final phishing prediction.
    They are inputs to the future risk engine.
    """

    # --------------------------------------------------------
    # Normalize / parse
    # --------------------------------------------------------

    normalized, parsed = _safe_split(url)

    hostname = get_hostname(normalized)

    path = parsed.path or ""
    query = parsed.query or ""

    # --------------------------------------------------------
    # Basic URL properties
    # --------------------------------------------------------

    signals = {}

    signals["is_https"] = (
        parsed.scheme.lower() == "https"
    )

    signals["is_ip_address"] = _is_ip(
        hostname
    )

    signals["has_credentials"] = _has_credentials(
        parsed
    )

    signals["url_length"] = len(
        normalized
    )

    signals["hostname_length"] = len(
        hostname
    )

    signals["path_length"] = len(
        path
    )

    signals["query_length"] = len(
        query
    )

    # --------------------------------------------------------
    # Hostname structure
    # --------------------------------------------------------

    signals["subdomain_count"] = _subdomain_count(
        hostname
    )

    signals["excessive_subdomains"] = (
        signals["subdomain_count"] >= 4
    )

    signals["suspicious_tld"] = _suspicious_tld(
        hostname
    )

    # --------------------------------------------------------
    # Suspicious words
    # --------------------------------------------------------

    signals["suspicious_word_count"] = (
        _suspicious_word_count(normalized)
    )

    signals["has_suspicious_words"] = (
        signals["suspicious_word_count"] > 0
    )

    # --------------------------------------------------------
    # Brand impersonation
    # --------------------------------------------------------

    brands = _brand_impersonation(
        hostname
    )

    signals["brand_impersonation"] = (
        len(brands) > 0
    )

    signals["brand_matches"] = brands

    # --------------------------------------------------------
    # URL obfuscation
    # --------------------------------------------------------

    signals["has_at_symbol"] = (
        "@" in normalized
    )

    signals["has_percent_encoding"] = (
        "%" in normalized
    )

    signals["has_hex_encoding"] = bool(
        re.search(
            r"%[0-9a-fA-F]{2}",
            normalized,
        )
    )

    signals["excessive_percent_encoding"] = (
        normalized.count("%") >= 3
    )

    # --------------------------------------------------------
    # Path structure
    # --------------------------------------------------------

    path_segments = [
        segment
        for segment in path.split("/")
        if segment
    ]

    signals["path_depth"] = len(
        path_segments
    )

    signals["deep_path"] = (
        signals["path_depth"] >= 6
    )

    signals["suspicious_path_structure"] = bool(
        re.search(
            r"(login|signin|verify|secure|account|"
            r"password|confirm|update|payment|wallet|"
            r"authentication|authorize)",
            path,
            re.IGNORECASE,
        )
    )

    # --------------------------------------------------------
    # Query structure
    # --------------------------------------------------------

    query_parameter_count = (
        len(query.split("&"))
        if query
        else 0
    )

    signals["query_parameter_count"] = (
        query_parameter_count
    )

    signals["many_query_parameters"] = (
        query_parameter_count >= 8
    )

    # --------------------------------------------------------
    # Entropy / randomness
    # --------------------------------------------------------

    hostname_entropy = _entropy(
        hostname
    )

    path_entropy = _entropy(
        path
    )

    signals["hostname_entropy"] = (
        hostname_entropy
    )

    signals["path_entropy"] = (
        path_entropy
    )

    signals["high_hostname_entropy"] = (
        hostname_entropy >= 4.0
    )

    signals["high_path_entropy"] = (
        path_entropy >= 4.0
    )

    # --------------------------------------------------------
    # Length-based signals
    # --------------------------------------------------------

    signals["very_long_url"] = (
        len(normalized) >= 200
    )

    signals["very_long_hostname"] = (
        len(hostname) >= 80
    )

    # --------------------------------------------------------
    # HTTP risk signal
    # --------------------------------------------------------

    signals["insecure_http"] = (
        parsed.scheme.lower() == "http"
    )

    # --------------------------------------------------------
    # Calculate rule score
    # --------------------------------------------------------

    risk_score, reasons = calculate_risk_score(
        signals
    )

    # --------------------------------------------------------
    # Rule-level classification
    # --------------------------------------------------------

    if risk_score >= 60:

        risk_level = "HIGH"

    elif risk_score >= 30:

        risk_level = "MEDIUM"

    elif risk_score >= 10:

        risk_level = "LOW"

    else:

        risk_level = "MINIMAL"

    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

    return {
        "normalized_url": normalized,
        "hostname": hostname,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "reasons": reasons,
        "signals": signals,
    }


# ============================================================
# LOCAL TESTING
# ============================================================

if __name__ == "__main__":

    test_urls = [

        # Legitimate
        "https://www.google.com",

        # Brand impersonation
        "https://paypal-login.security-check.example.com/account/verify",

        # IP + login
        "http://192.168.1.10/login",

        # Credentials
        "https://user:password@example.com/login",

        # Suspicious TLD
        "https://example.xyz/account/verify",

        # Legitimate Microsoft
        "https://www.microsoft.com",

        # Fake Microsoft
        "https://microsoft-login.example.com/verify",

        # Legitimate PayPal
        "https://www.paypal.com",

        # Fake PayPal
        "https://paypal-security.example.xyz/login",
    ]

    for test_url in test_urls:

        result = analyze_url(
            test_url
        )

        print("\n" + "=" * 80)
        print(test_url)
        print("=" * 80)

        print(
            "Normalized URL:",
            result["normalized_url"],
        )

        print(
            "Hostname:",
            result["hostname"],
        )

        print(
            "Risk score:",
            result["risk_score"],
        )

        print(
            "Risk level:",
            result["risk_level"],
        )

        print(
            "Brand matches:",
            result["signals"]["brand_matches"],
        )

        print("Reasons:")

        if result["reasons"]:

            for reason in result["reasons"]:
                print(" -", reason)

        else:

            print(" - No significant rule-based risks detected")

        print("\nSignals:")

        for key, value in result["signals"].items():
            print(f" {key}: {value}")