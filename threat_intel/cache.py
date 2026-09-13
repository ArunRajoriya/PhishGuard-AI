
import hashlib
import time
from typing import Any


class TTLCache:
    """
    Simple thread-safe-ish in-memory TTL cache.

    This is suitable for the first implementation.
    It will later be replaced by Redis for production
    multi-instance deployments.
    """

    def __init__(self, ttl_seconds: int = 900, max_size: int = 5000):
        self.ttl_seconds = ttl_seconds
        self.max_size = max_size
        self._cache: dict[str, tuple[float, Any]] = {}

    @staticmethod
    def make_key(url: str) -> str:
        """
        Create a stable SHA-256 cache key.

        We don't store the raw URL as the dictionary key.
        """
        normalized = url.strip().lower()

        return hashlib.sha256(
            normalized.encode("utf-8")
        ).hexdigest()

    def get(self, url: str) -> Any | None:
        key = self.make_key(url)

        item = self._cache.get(key)

        if item is None:
            return None

        expires_at, value = item

        if time.time() >= expires_at:
            del self._cache[key]
            return None

        return value

    def set(self, url: str, value: Any) -> None:
        key = self.make_key(url)

        # Simple eviction strategy.
        if len(self._cache) >= self.max_size:
            oldest_key = min(
                self._cache,
                key=lambda k: self._cache[k][0],
            )
            del self._cache[oldest_key]

        self._cache[key] = (
            time.time() + self.ttl_seconds,
            value,
        )

    def delete(self, url: str) -> None:
        key = self.make_key(url)
        self._cache.pop(key, None)

    def clear(self) -> None:
        self._cache.clear()

    def size(self) -> int:
        return len(self._cache)

