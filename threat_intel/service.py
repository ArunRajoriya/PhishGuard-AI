
from __future__ import annotations

import base64
import os
import time
from typing import Any, Dict, Optional

import requests
from dotenv import load_dotenv

from threat_intel.cache import TTLCache
from threat_intel.models import ThreatIntelResult

load_dotenv()

VT_BASE_URL = "https://www.virustotal.com/api/v3"
VT_TIMEOUT = 10

# Keep polling bounded so a user request never hangs indefinitely.
VT_POLL_INTERVAL_SECONDS = 2
VT_MAX_POLLS = 8

CACHE_TTL_SECONDS = 900
CACHE_MAX_SIZE = 5000

_cache = TTLCache(
    ttl_seconds=CACHE_TTL_SECONDS,
    max_size=CACHE_MAX_SIZE,
)


class VirusTotalThreatIntel:
    def __init__(self) -> None:
        self.api_key = os.getenv("VT_API_KEY", "").strip()

    @property
    def configured(self) -> bool:
        return bool(self.api_key)
    def lookup(self, url: str) -> ThreatIntelResult:
        result = self.analyze(url)
        return ThreatIntelResult(
        provider=result.get("provider", "VirusTotal"),
        status=result.get("status", "unknown"),
        malicious=int(result.get("malicious", 0) or 0),
        suspicious=int(result.get("suspicious", 0) or 0),
        harmless=int(result.get("harmless", 0) or 0),
        undetected=int(result.get("undetected", 0) or 0),
        threat_score=float(result.get("threat_score", 0.0) or 0.0),
        cached=bool(result.get("cached", False)),
        error=result.get("error"),
        reasons=result.get("reasons", []),
    )

    def _headers(self) -> Dict[str, str]:
        return {
            "x-apikey": self.api_key,
            "accept": "application/json",
        }
    

    @staticmethod
    def _url_id(url: str) -> str:
        """
        VirusTotal accepts an unpadded URL-safe Base64 representation
        as a URL identifier.
        """
        encoded = base64.urlsafe_b64encode(
            url.encode("utf-8")
        ).decode("utf-8")

        return encoded.rstrip("=")

    @staticmethod
    def _calculate_threat_score(
        malicious: int,
        suspicious: int,
        total: int,
    ) -> float:
        if total <= 0:
            return 0.0

        weighted_detection = malicious + (0.5 * suspicious)
        score = (weighted_detection / total) * 100.0

        return round(min(score, 100.0), 2)

    @staticmethod
    def _build_reasons(
        malicious: int,
        suspicious: int,
        threat_score: float,
        status: str,
    ) -> list[str]:
        reasons: list[str] = []

        if status != "completed":
            reasons.append(
                f"VirusTotal analysis did not complete before the polling deadline "
                f"(status: {status})."
            )

        if malicious > 0:
            reasons.append(
                f"{malicious} security engine(s) classified the URL as malicious."
            )
        elif suspicious > 0:
            reasons.append(
                f"{suspicious} security engine(s) classified the URL as suspicious."
            )
        else:
            reasons.append(
                "No malicious or suspicious detections were reported."
            )

        if threat_score >= 50:
            reasons.append("VirusTotal detection level is high.")
        elif threat_score >= 20:
            reasons.append("VirusTotal detection level is elevated.")

        return reasons

    def _parse_analysis(
        self,
        response_json: Dict[str, Any],
    ) -> Dict[str, Any]:
        data = response_json.get("data", {})
        attributes = data.get("attributes", {})

        status = attributes.get("status", "unknown")
        stats = attributes.get("stats", {})

        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        harmless = int(stats.get("harmless", 0) or 0)
        undetected = int(stats.get("undetected", 0) or 0)
        timeout = int(stats.get("timeout", 0) or 0)

        total = (
            malicious
            + suspicious
            + harmless
            + undetected
            + timeout
        )

        threat_score = self._calculate_threat_score(
            malicious=malicious,
            suspicious=suspicious,
            total=total,
        )

        return {
            "status": status,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "timeout": timeout,
            "total_engines": total,
            "threat_score": threat_score,
        }

    def _get_analysis(
        self,
        analysis_id: str,
    ) -> Optional[Dict[str, Any]]:
        response = requests.get(
            f"{VT_BASE_URL}/analyses/{analysis_id}",
            headers=self._headers(),
            timeout=VT_TIMEOUT,
        )

        if response.status_code != 200:
            return None

        return response.json()

    def _poll_analysis(
        self,
        analysis_id: str,
    ) -> Optional[Dict[str, Any]]:
        latest: Optional[Dict[str, Any]] = None

        for attempt in range(VT_MAX_POLLS):
            latest = self._get_analysis(analysis_id)

            if latest is None:
                return None

            parsed = self._parse_analysis(latest)

            if parsed["status"] == "completed":
                return latest

            if attempt < VT_MAX_POLLS - 1:
                time.sleep(VT_POLL_INTERVAL_SECONDS)

        return latest

    def analyze(self, url: str) -> Dict[str, Any]:
        if not self.configured:
            return ThreatIntelResult(
                provider="VirusTotal",
                status="unavailable",
                error="VT_API_KEY is not configured.",
                reasons=["VirusTotal integration is not configured."],
            ).to_dict()

        cached = _cache.get(url)

        if cached is not None:
            cached_result = dict(cached)
            cached_result["cached"] = True
            return cached_result

        try:
            url_id = self._url_id(url)

            # First try to retrieve an existing VT URL object.
            report_response = requests.get(
                f"{VT_BASE_URL}/urls/{url_id}",
                headers=self._headers(),
                timeout=VT_TIMEOUT,
            )

            if report_response.status_code == 200:
                report = report_response.json()
                parsed = self._parse_url_report(report)

                result = ThreatIntelResult(
                    provider="VirusTotal",
                    status="success",
                    malicious=parsed["malicious"],
                    suspicious=parsed["suspicious"],
                    harmless=parsed["harmless"],
                    undetected=parsed["undetected"],
                    threat_score=parsed["threat_score"],
                    cached=False,
                    reasons=self._build_reasons(
                        parsed["malicious"],
                        parsed["suspicious"],
                        parsed["threat_score"],
                        "completed",
                    ),
                ).to_dict()

                _cache.set(url, result)
                return result
            

            # URL does not have a report: submit it for analysis.
            if report_response.status_code == 404:
                submit_response = requests.post(
                    f"{VT_BASE_URL}/urls",
                    headers=self._headers(),
                    files={"url": (None, url)},
                    timeout=VT_TIMEOUT,
                )

                if submit_response.status_code not in (200, 201):
                    return self._error_response(
                        f"VirusTotal submission failed "
                        f"(HTTP {submit_response.status_code})."
                    )

                submission = submit_response.json()

                analysis_id = (
                    submission.get("data", {})
                    .get("id")
                )

                if not analysis_id:
                    return self._error_response(
                        "VirusTotal submission succeeded but no analysis ID was returned."
                    )

                analysis_response = self._poll_analysis(
                    analysis_id
                )

                if analysis_response is None:
                    return self._error_response(
                        "Unable to retrieve VirusTotal analysis status."
                    )

                parsed = self._parse_analysis(
                    analysis_response
                )

                final_status = parsed["status"]

                result = ThreatIntelResult(
                    provider="VirusTotal",
                    status=(
                        "success"
                        if final_status == "completed"
                        else final_status
                    ),
                    malicious=parsed["malicious"],
                    suspicious=parsed["suspicious"],
                    harmless=parsed["harmless"],
                    undetected=parsed["undetected"],
                    threat_score=parsed["threat_score"],
                    cached=False,
                    reasons=self._build_reasons(
                        parsed["malicious"],
                        parsed["suspicious"],
                        parsed["threat_score"],
                        final_status,
                    ),
                ).to_dict()

                # Cache completed analyses only.
                if final_status == "completed":
                    _cache.set(url, result)

                return result

            if report_response.status_code == 401:
                return self._error_response(
                    "VirusTotal API authentication failed."
                )

            if report_response.status_code == 429:
                return self._error_response(
                    "VirusTotal API rate limit exceeded."
                )

            return self._error_response(
                f"VirusTotal request failed "
                f"(HTTP {report_response.status_code})."
            )

        except requests.Timeout:
            return self._error_response(
                "VirusTotal request timed out."
            )

        except requests.RequestException as exc:
            return self._error_response(
                f"VirusTotal request failed: {exc}"
            )

        except Exception as exc:
            return self._error_response(
                f"Unexpected VirusTotal error: {exc}"
            )

    def _parse_url_report(
        self,
        report: Dict[str, Any],
    ) -> Dict[str, Any]:
        attributes = (
            report.get("data", {})
            .get("attributes", {})
        )

        stats = attributes.get(
            "last_analysis_stats",
            {},
        )

        malicious = int(
            stats.get("malicious", 0) or 0
        )
        suspicious = int(
            stats.get("suspicious", 0) or 0
        )
        harmless = int(
            stats.get("harmless", 0) or 0
        )
        undetected = int(
            stats.get("undetected", 0) or 0
        )

        total = (
            malicious
            + suspicious
            + harmless
            + undetected
        )

        return {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "threat_score": self._calculate_threat_score(
                malicious,
                suspicious,
                total,
            ),
        }

    @staticmethod
    def _error_response(message: str) -> Dict[str, Any]:
        return ThreatIntelResult(
            provider="VirusTotal",
            status="error",
            error=message,
            reasons=[message],
        ).to_dict()

def lookup(self, url: str) -> Dict[str, Any]:
    """
    Backward-compatible wrapper.

    The risk engine currently calls `lookup()`, while the new
    implementation uses `analyze()`.
    """
    return self.analyze(url)



# Singleton used by the risk engine.
threat_intel_service = VirusTotalThreatIntel()

