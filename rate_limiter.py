import logging
import os

import redis

from cache.redis_cache import get_redis_client


logger = logging.getLogger("phishguard.rate_limiter")


# ============================================================
# CONFIGURATION
# ============================================================

RATE_LIMIT_REQUESTS = int(
    os.getenv("RATE_LIMIT_REQUESTS", "30")
)

RATE_LIMIT_WINDOW = int(
    os.getenv("RATE_LIMIT_WINDOW", "60")
)


# ============================================================
# RATE LIMIT RESULT
# ============================================================

def check_rate_limit(client_ip: str) -> dict:
    """
    Check whether an IP address is allowed to make
    another request.

    Uses Redis INCR + EXPIRE.

    Returns:

        {
            "allowed": True,
            "limit": 30,
            "remaining": 29,
            "reset_after": 60
        }
    """

    if not client_ip:
        client_ip = "unknown"

    try:

        client = get_redis_client()

        key = f"phishguard:ratelimit:{client_ip}"

        # Increment request counter.
        current_count = client.incr(key)

        # First request starts the expiration window.
        if current_count == 1:

            client.expire(
                key,
                RATE_LIMIT_WINDOW
            )

        # Calculate remaining requests.
        remaining = max(
            RATE_LIMIT_REQUESTS - current_count,
            0,
        )

        # Get remaining TTL.
        ttl = client.ttl(key)

        if ttl < 0:
            ttl = RATE_LIMIT_WINDOW

        allowed = (
            current_count
            <= RATE_LIMIT_REQUESTS
        )

        logger.info(
            "Rate limit | IP=%s | count=%s | "
            "remaining=%s | allowed=%s",
            client_ip,
            current_count,
            remaining,
            allowed,
        )

        return {
            "allowed": allowed,
            "limit": RATE_LIMIT_REQUESTS,
            "remaining": remaining,
            "reset_after": ttl,
        }

    except redis.RedisError as exc:

        # Redis failure should not take down
        # the phishing scanner.
        logger.warning(
            "Rate limiter Redis failure: %s",
            exc,
        )

        return {
            "allowed": True,
            "limit": RATE_LIMIT_REQUESTS,
            "remaining": RATE_LIMIT_REQUESTS,
            "reset_after": 0,
            "error": "rate_limiter_unavailable",
        }