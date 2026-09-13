
from pathlib import Path
from typing import Any, Dict

import joblib

from feature_extractor import extract_features
from predictor import predict_url
from utils.risk_rules import analyze_url as analyze_rule_url
from utils.url_normalizer import get_hostname, get_registered_domain
from threat_intel.service import threat_intel_service


# =========================================================
# PROJECT CONFIGURATION
# =========================================================

PROJECT_ROOT = Path(__file__).resolve().parent

HOSTNAME_MODEL_PATH = (
    PROJECT_ROOT / "model" / "hostname_char_model.pkl"
)

HOSTNAME_VECTORIZER_PATH = (
    PROJECT_ROOT / "model" / "hostname_vectorizer.pkl"
)


# =========================================================
# TRUSTED DOMAINS
# =========================================================

TRUSTED_DOMAINS = {
    "google.com",
    "microsoft.com",
    "paypal.com",
    "amazon.com",
    "apple.com",
    "github.com",
    "linkedin.com",
    "stackoverflow.com",
}


def is_trusted_domain(url: str) -> bool:
    """
    Return True only when the hostname is exactly a trusted domain
    or a legitimate subdomain of a trusted domain.

    Example:
        google.com           -> True
        www.google.com       -> True
        accounts.google.com  -> True
        google.com.evil.com  -> False
    """

    try:
        hostname = get_hostname(url)

        if not hostname:
            return False

        for domain in TRUSTED_DOMAINS:
            if hostname == domain:
                return True

            if hostname.endswith("." + domain):
                return True

        return False

    except Exception:
        return False

# =========================================================
# LOAD HOSTNAME MODEL
# =========================================================

hostname_model = None
hostname_vectorizer = None

try:
    hostname_model = joblib.load(HOSTNAME_MODEL_PATH)
    hostname_vectorizer = joblib.load(
        HOSTNAME_VECTORIZER_PATH
    )

    print("[INFO] Hostname model loaded successfully.")

except Exception as exc:
    print(
        f"[WARNING] Hostname model unavailable: {exc}"
    )


# =========================================================
# HOSTNAME PREDICTION
# =========================================================

def predict_hostname(url: str) -> Dict[str, Any]:
    """
    Predict phishing probability using the hostname
    character n-gram model.
    """

    if (
        hostname_model is None
        or hostname_vectorizer is None
    ):
        return {
            "available": False,
            "prediction": None,
            "probability": None,
        }

    try:
        hostname = get_hostname(url)

        if not hostname:
            return {
                "available": False,
                "prediction": None,
                "probability": None,
            }

        vector = hostname_vectorizer.transform(
            [hostname]
        )

        prediction = int(
            hostname_model.predict(vector)[0]
        )

        probability = float(
            hostname_model.predict_proba(vector)[0][1]
        )

        return {
            "available": True,
            "prediction": prediction,
            "probability": probability,
        }

    except Exception as exc:
        return {
            "available": False,
            "prediction": None,
            "probability": None,
            "error": str(exc),
        }


# =========================================================
# MODEL PROBABILITY → RISK SCORE
# =========================================================

def probability_to_score(
    probability: float | None,
) -> float:
    """
    Convert phishing probability [0, 1]
    into risk score [0, 100].
    """

    if probability is None:
        return 0.0

    return max(
        0.0,
        min(
            100.0,
            probability * 100.0,
        ),
    )


# =========================================================
# FINAL RISK CALCULATION
# =========================================================

def calculate_final_risk(
    url: str,
    url_ml: Dict[str, Any],
    hostname_ml: Dict[str, Any],
    rule_result: Dict[str, Any],
    threat_intel: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """
    Combine:

        1. URL ML model
        2. Hostname ML model
        3. Security rules
        4. Threat intelligence
        5. Trusted-domain protection

    into one final risk score.

    Risk levels:

        0-29   SAFE
        30-64  SUSPICIOUS
        65-100 PHISHING
    """

    # =====================================================
    # EXTRACT MODEL PROBABILITIES
    # =====================================================

    url_probability = url_ml.get("probability")

    hostname_probability = hostname_ml.get(
        "probability"
    )

    # =====================================================
    # SECURITY RULE SCORE
    # =====================================================

    rule_score = float(
        rule_result.get(
            "risk_score",
            0,
        )
    )

    signals = rule_result.get(
        "signals",
        {},
    )

    # =====================================================
    # THREAT INTELLIGENCE
    # =====================================================

    threat_intel = threat_intel or {}

    threat_intel_status = threat_intel.get(
        "status",
        "unavailable",
    )

    threat_intel_score = float(
        threat_intel.get(
            "threat_score",
            0.0,
        )
        or 0.0
    )

    # =====================================================
    # TRUSTED DOMAIN
    # =====================================================

    trusted_domain = is_trusted_domain(url)

    # =====================================================
    # MODEL SCORES
    # =====================================================

    url_score = probability_to_score(
        url_probability
    )

    hostname_score = probability_to_score(
        hostname_probability
    )

    # =====================================================
    # MODEL ENSEMBLE
    # =====================================================

    if (
        url_probability is not None
        and hostname_probability is not None
    ):
        model_score = (
            url_score * 0.35
            + hostname_score * 0.65
        )

    elif hostname_probability is not None:
        model_score = hostname_score

    elif url_probability is not None:
        model_score = url_score

    else:
        model_score = 0.0

    # =====================================================
    # BASE RISK FUSION
    # =====================================================
    #
    # ML provides predictive evidence.
    # Security rules provide interpretable evidence.
    #
    # ML alone must not produce a phishing-level score.
    # Independent security signals are required for high
    # confidence classifications.
    # =====================================================

    if rule_score <= 0:

        # Completely clean rule profile.
        #
        # ML can indicate suspicion, but without supporting
        # security evidence it cannot create a phishing score.

        final_score = min(
            model_score * 0.35,
            39.0,
        )

    else:

        # Security rules are present, so ML becomes more
        # influential in the final risk calculation.

        if threat_intel_status == "success":
            final_score = (
                model_score * 0.45
                + rule_score * 0.40
                + threat_intel_score * 0.15
            )
        else:
            final_score = (
                model_score * 0.55
                + rule_score * 0.45
            )

    # Security rules always retain authority.
    final_score = max(
        final_score,
        rule_score,
    )

    # =====================================================
    # SECURITY SIGNALS
    # =====================================================

    has_credentials = bool(
        signals.get(
            "has_credentials"
        )
    )

    is_ip = bool(
        signals.get(
            "is_ip_address"
        )
    )

    brand_impersonation = bool(
        signals.get(
            "brand_impersonation"
        )
    )

    suspicious_auth_path = bool(
        signals.get(
            "suspicious_auth_path"
        )
    )

    suspicious_tld = bool(
        signals.get(
            "has_suspicious_tld"
        )
    )

    suspicious_language = bool(
        signals.get(
            "has_suspicious_word"
        )
    )

    has_url_encoding = bool(
        signals.get(
            "has_url_encoding"
        )
    )

    # =====================================================
    # VERY STRONG SECURITY COMBINATIONS
    # =====================================================

    # Credentials + authentication page
    if (
        has_credentials
        and suspicious_auth_path
    ):
        final_score = max(
            final_score,
            85,
        )

    # Credentials embedded in URL
    if has_credentials:
        final_score = max(
            final_score,
            80,
        )

    # Brand impersonation + phishing intent
    if brand_impersonation and suspicious_language:
        final_score = max(final_score, 75)

    if brand_impersonation and suspicious_auth_path:
        final_score = max(final_score, 75)

    if (
        brand_impersonation
        and suspicious_language
        and suspicious_auth_path
    ):
        final_score = max(final_score, 85)
    # Suspicious TLD + brand impersonation
    if (
        suspicious_tld
        and brand_impersonation
    ):
        final_score = max(
            final_score,
            80,
        )

    # Suspicious TLD + authentication
    if (
        suspicious_tld
        and suspicious_auth_path
    ):
        final_score = max(
            final_score,
            65,
        )

    # IP address + authentication
    if (
        is_ip
        and suspicious_auth_path
    ):
        final_score = max(
            final_score,
            55,
        )

    # =====================================================
    # URL OBFUSCATION
    # =====================================================

    if (
        has_url_encoding
        and suspicious_auth_path
    ):
        final_score = max(
            final_score,
            60,
        )

    # =====================================================
    # ML AGREEMENT
    # =====================================================
    #
    # Agreement between ML models is useful evidence,
    # but ML agreement alone must NOT force PHISHING.
    #
    # Independent security evidence is required for
    # phishing-level classification.
    # =====================================================

    strong_ml_agreement = (
        url_probability is not None
        and hostname_probability is not None
        and url_probability >= 0.85
        and hostname_probability >= 0.75
    )

    if strong_ml_agreement:

        if rule_score > 0:

            # Rules provide independent evidence.
            final_score = max(
                final_score,
                min(
                    69.0,
                    model_score * 0.65
                    + rule_score * 0.35,
                ),
            )

        elif threat_intel_status == "success":

            vt_malicious = int(
                threat_intel.get(
                    "malicious",
                    0,
                )
                or 0
            )

            vt_suspicious = int(
                threat_intel.get(
                    "suspicious",
                    0,
                )
                or 0
            )

            if vt_malicious > 0:

                final_score = max(
                    final_score,
                    70.0,
                )

            elif vt_suspicious > 0:

                final_score = max(
                    final_score,
                    60.0,
                )

            else:

                # No independent evidence.
                final_score = min(
                    final_score,
                    39.0,
                )

        else:

            # Threat intelligence unavailable.
            # ML alone must not create phishing.
            final_score = min(
                final_score,
                39.0,
            )

    # =====================================================
    # THREAT INTELLIGENCE STRONG SIGNAL
    # =====================================================

    malicious = int(
        threat_intel.get(
            "malicious",
            0,
        )
        or 0
    )

    suspicious = int(
        threat_intel.get(
            "suspicious",
            0,
        )
        or 0
    )

    total_engines = int(
        threat_intel.get(
            "total_engines",
            0,
        )
        or 0
    )

    # Multiple independent engines reporting
    # malicious activity is strong evidence.

    if threat_intel_status == "success":

        if (
            total_engines >= 10
            and malicious >= 3
        ):
            final_score = max(
                final_score,
                85,
            )

        elif (
            total_engines >= 10
            and malicious >= 1
        ):
            final_score = max(
                final_score,
                70,
            )

        elif (
            total_engines >= 10
            and suspicious >= 3
        ):
            final_score = max(
                final_score,
                60,
            )

    # =====================================================
    # TRUSTED-DOMAIN PROTECTION
    # =====================================================
    #
    # A trusted domain should not automatically override
    # strong external threat intelligence.
    # =====================================================

    strong_external_threat = (
        threat_intel_status == "success"
        and total_engines >= 10
        and malicious >= 3
    )

    moderate_external_threat = (
        threat_intel_status == "success"
        and total_engines >= 10
        and (
            malicious >= 1
            or suspicious >= 3
        )
    )

    if (
        trusted_domain
        and rule_score < 30
        and not strong_external_threat
    ):

        # Trusted domains are protected from
        # ordinary ML false positives.

        final_score = min(
            final_score,
            25.0,
        )

        # A moderate VT signal should still allow
        # the trusted domain to remain below phishing
        # unless the local rules also indicate danger.

        if moderate_external_threat:
            final_score = min(
                final_score,
                39.0,
            )

    else:

        # =================================================
        # GENERIC LEGITIMATE-DOMAIN PROTECTION
        # =================================================

        if (
            rule_score == 0
            and hostname_probability is not None
            and hostname_probability < 0.40
        ):
            final_score = min(
                final_score,
                39.0,
            )

    # =====================================================
    # FINAL SCORE CAP
    # =====================================================

    final_score = max(
        0.0,
        min(
            100.0,
            final_score,
        ),
    )

   # Final risk classification
    if final_score >= 65:
     risk_level = "PHISHING"
    elif final_score >= 30:
     risk_level = "SUSPICIOUS"
    else:
     risk_level = "SAFE"

    # =====================================================
    # CONFIDENCE
    # =====================================================

    confidence_components = []

    # Model certainty
    if url_probability is not None:
        confidence_components.append(
            abs(url_probability - 0.5) * 2
        )

    if hostname_probability is not None:
        confidence_components.append(
            abs(hostname_probability - 0.5) * 2
        )

    # Rule evidence
    if rule_score > 0:
        confidence_components.append(
            rule_score / 100.0
        )

    # Threat intelligence evidence
    if (
        threat_intel_status == "success"
        and total_engines > 0
    ):
        confidence_components.append(
            min(
                max(
                    threat_intel_score / 100.0,
                    0.0,
                ),
                1.0,
            )
        )

    if confidence_components:

        confidence = (
            sum(confidence_components)
            / len(confidence_components)
        ) * 100.0

    else:

        confidence = abs(
            final_score - 50
        ) * 2

    # Trusted domain protection provides
    # high confidence when no strong security
    # signals are present.

    if (
        trusted_domain
        and rule_score < 30
        and not strong_external_threat
    ):
        confidence = max(
            confidence,
            90.0,
        )

    confidence = max(
        0.0,
        min(
            100.0,
            confidence,
        ),
    )

    # =====================================================
    # REASONS
    # =====================================================

    reasons = list(
        rule_result.get(
            "reasons",
            [],
        )
    )

    # =====================================================
    # THREAT INTELLIGENCE REASONS
    # =====================================================

    if threat_intel_status == "success":

        if (
            malicious > 0
            or suspicious > 0
        ):
            reasons.extend(
                threat_intel.get(
                    "reasons",
                    [],
                )
            )

        elif total_engines > 0:
            reasons.append(
                "Threat intelligence providers did not identify significant malicious activity."
            )

    elif threat_intel_status == "error":

        reasons.append(
            "Threat intelligence service was temporarily unavailable; local detection was used."
        )

    elif threat_intel_status == "unavailable":

        reasons.append(
            "Threat intelligence was unavailable; local ML and security rules were used."
        )

    elif threat_intel_status == "disabled":

        reasons.append(
            "Threat intelligence lookup was disabled; local ML and security rules were used."
        )

    # =====================================================
    # URL ML REASON
    # =====================================================

    if (
        risk_level in {
            "SUSPICIOUS",
            "PHISHING",
        }
        and url_probability is not None
        and url_probability >= 0.80
    ):
        reasons.append(
            "URL-based ML model detected a strong phishing pattern."
        )

    # =====================================================
    # HOSTNAME ML REASON
    # =====================================================

    if (
        risk_level in {
            "SUSPICIOUS",
            "PHISHING",
        }
        and hostname_probability is not None
        and hostname_probability >= 0.80
    ):
        reasons.append(
            "Hostname model detected a suspicious hostname pattern."
        )

    # =====================================================
    # ML-ONLY WARNING
    # =====================================================

    if (
        risk_level == "SAFE"
        and strong_ml_agreement
        and rule_score == 0
        and not moderate_external_threat
    ):
        reasons.append(
            "ML models detected a suspicious pattern, but no independent security evidence supported a high-risk classification."
        )

    # =====================================================
    # TRUSTED DOMAIN REASON
    # =====================================================

    if (
        trusted_domain
        and rule_score < 30
        and not strong_external_threat
    ):
        reasons.append(
            "Recognized trusted registered domain; ML false-positive protection applied."
        )

    # =====================================================
    # THREAT INTELLIGENCE SUMMARY REASON
    # =====================================================

    if (
        threat_intel_status == "success"
        and threat_intel_score >= 50
    ):
        reasons.append(
            "Threat intelligence indicates substantial malicious activity."
        )

    # =====================================================
    # REMOVE DUPLICATE REASONS
    # =====================================================

    reasons = list(
        dict.fromkeys(
            reasons
        )
    )

    # =====================================================
    # RETURN FINAL RESULT
    # =====================================================

    return {
        "risk_score": round(
            final_score,
            2,
        ),
        "risk_level": risk_level,
        "confidence": round(
            confidence,
            2,
        ),
        "reasons": reasons,
        "threat_intelligence": threat_intel,

        # Expose individual model scores.
        "url_ml_score": round(
            url_score,
            4,
        ),
        "hostname_ml_score": round(
            hostname_score,
            4,
        ),
        "rule_score": round(
            rule_score,
            2,
        ),
        "model_score": round(
            model_score,
            2,
        ),
    }


# =========================================================
# MAIN URL ANALYSIS PIPELINE
# =========================================================

def analyze_url(
    url: str,
    include_threat_intel: bool = True,
) -> Dict[str, Any]:
    """
    Complete PhishGuard URL analysis pipeline.

    Pipeline:

        URL
         │
         ├── URL feature extraction
         │
         ├── URL ML model
         │
         ├── Hostname ML model
         │
         ├── Security rule engine
         │
         ├── Threat intelligence
         │
         └── Final risk engine
    """

    # =====================================================
    # URL FEATURE MODEL
    # =====================================================

    try:
        features = extract_features(
            url
        )

        url_ml = predict_url(
            features
        )

    except Exception as exc:

        url_ml = {
            "available": False,
            "prediction": None,
            "probability": None,
            "error": str(exc),
        }

    # =====================================================
    # HOSTNAME MODEL
    # =====================================================

    hostname_ml = predict_hostname(
        url
    )

    # =====================================================
    # SECURITY RULE ENGINE
    # =====================================================

    try:
        rule_result = analyze_rule_url(
            url
        )

    except Exception as exc:

        rule_result = {
            "risk_score": 0,
            "risk_level": "SAFE",
            "signals": {},
            "reasons": [],
            "error": str(exc),
        }

    # =====================================================
    # THREAT INTELLIGENCE
    # =====================================================

    if include_threat_intel:

        try:

            threat_intel_result = (
                threat_intel_service
                .lookup(url)
                .to_dict()
            )

        except Exception as exc:

            threat_intel_result = {
                "provider": "VirusTotal",
                "status": "error",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "total_engines": 0,
                "threat_score": 0.0,
                "cached": False,
                "error": str(exc),
                "reasons": [],
            }

    else:

        threat_intel_result = {
            "provider": "VirusTotal",
            "status": "disabled",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "total_engines": 0,
            "threat_score": 0.0,
            "cached": False,
            "error": None,
            "reasons": [],
        }

    # =====================================================
    # FINAL RISK ENGINE
    # =====================================================

    final_risk = calculate_final_risk(
        url=url,
        url_ml=url_ml,
        hostname_ml=hostname_ml,
        rule_result=rule_result,
        threat_intel=threat_intel_result,
    )

    # =====================================================
    # FINAL RESPONSE
    # =====================================================

    return {
        "url": url,

        "risk_score": final_risk[
            "risk_score"
        ],

        "risk_level": final_risk[
            "risk_level"
        ],

        "confidence": final_risk[
            "confidence"
        ],

        "reasons": final_risk[
            "reasons"
        ],

        # Detailed ML information
        "models": {
            "url_ml": url_ml,
            "hostname_ml": hostname_ml,

            "url_ml_score": final_risk[
                "url_ml_score"
            ],

            "hostname_ml_score": final_risk[
                "hostname_ml_score"
            ],

            "model_score": final_risk[
                "model_score"
            ],

            "rule_score": final_risk[
                "rule_score"
            ],
        },

        # Security rules
        "rules": {
            "risk_score": rule_result.get(
                "risk_score",
                0,
            ),

            "risk_level": rule_result.get(
                "risk_level"
            ),

            "signals": rule_result.get(
                "signals",
                {},
            ),
        },

        # Threat intelligence
        "threat_intelligence": threat_intel_result,

        # Trusted domain status
        "trusted_domain": is_trusted_domain(
            url
        ),
    }


# =========================================================
# MANUAL TESTING
# =========================================================

if __name__ == "__main__":

    test_urls = [

        # -------------------------------------------------
        # Legitimate domains
        # -------------------------------------------------

        "https://example.com",
        "https://google.com",
        "https://www.google.com",
        "https://www.microsoft.com",
        "https://paypal.com",
        "https://www.paypal.com",
        "https://amazon.com",
        "https://apple.com",
        "https://github.com",
        "https://linkedin.com",
        "https://stackoverflow.com",

        # -------------------------------------------------
        # Brand impersonation
        # -------------------------------------------------

        "https://paypal-login.security-check.example.com/account/verify",
        "https://microsoft-login.example.com/verify",
        "https://secure-paypal-login.example.com/signin",
        "https://paypal-security.example.xyz/login",

        # -------------------------------------------------
        # IP-based phishing
        # -------------------------------------------------

        "http://192.168.1.10/login",

        # -------------------------------------------------
        # Credentials
        # -------------------------------------------------

        "https://user:password@example.com/login",
    ]

    print(
        "\n"
        + "=" * 80
    )

    print(
        "PHISHGUARD AI — RISK ENGINE TEST"
    )

    print(
        "=" * 80
    )

    for url in test_urls:

        print(
            "\n"
            + "-" * 80
        )

        print(
            f"URL: {url}"
        )

        try:

            result = analyze_url(
                url,
                include_threat_intel=True,
            )

            print(
                f"Risk Score : {result['risk_score']}"
            )

            print(
                f"Risk Level : {result['risk_level']}"
            )

            print(
                f"Confidence : {result['confidence']}%"
            )

            print(
                f"Trusted Domain : {result['trusted_domain']}"
            )

            print(
                "\nReasons:"
            )

            for reason in result[
                "reasons"
            ]:
                print(
                    f"  - {reason}"
                )

            print(
                "\nModel Scores:"
            )

            models = result.get(
                "models",
                {},
            )

            print(
                "  URL ML Score       : "
                f"{models.get('url_ml_score', 'N/A')}"
            )

            print(
                "  Hostname ML Score  : "
                f"{models.get('hostname_ml_score', 'N/A')}"
            )

            print(
                "  Combined ML Score  : "
                f"{models.get('model_score', 'N/A')}"
            )

            print(
                "  Security Rule Score: "
                f"{models.get('rule_score', 'N/A')}"
            )

            print(
                "\nThreat Intelligence:"
            )

            threat_intel = result.get(
                "threat_intelligence",
                {},
            )

            print(
                "  Provider      : "
                f"{threat_intel.get('provider', 'N/A')}"
            )

            print(
                "  Status        : "
                f"{threat_intel.get('status', 'N/A')}"
            )

            print(
                "  Threat Score  : "
                f"{threat_intel.get('threat_score', 0)}"
            )

            print(
                "  Malicious     : "
                f"{threat_intel.get('malicious', 0)}"
            )

            print(
                "  Suspicious    : "
                f"{threat_intel.get('suspicious', 0)}"
            )

            print(
                "  Total Engines : "
                f"{threat_intel.get('total_engines', 0)}"
            )

            print(
                "  Cached        : "
                f"{threat_intel.get('cached', False)}"
            )

        except Exception as exc:

            print(
                f"[ERROR] Failed to analyze URL: {exc}"
            )
