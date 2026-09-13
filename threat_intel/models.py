
from dataclasses import dataclass, field
from typing import List


@dataclass
class ThreatIntelResult:
    """
    Normalized threat-intelligence result.

    This keeps the rest of the application independent
    from any specific threat-intelligence provider.
    """

    provider: str = "unknown"
    status: str = "unavailable"

    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0

    threat_score: float = 0.0

    cached: bool = False

    error: str | None = None

    reasons: List[str] = field(default_factory=list)

    @property
    def total_engines(self) -> int:
        return (
            self.malicious
            + self.suspicious
            + self.harmless
            + self.undetected
        )

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "status": self.status,
            "malicious": self.malicious,
            "suspicious": self.suspicious,
            "harmless": self.harmless,
            "undetected": self.undetected,
            "total_engines": self.total_engines,
            "threat_score": round(self.threat_score, 2),
            "cached": self.cached,
            "error": self.error,
            "reasons": self.reasons,
        }

