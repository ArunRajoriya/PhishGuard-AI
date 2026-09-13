import json
import logging
import os
from typing import Any, Optional

import redis
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
CACHE_TTL = int(os.getenv("REDIS_CACHE_TTL", "900"))

_client: Optional[redis.Redis] = None


def get_redis_client() -> redis.Redis:
    global _client

    if _client is None:
        _client = redis.from_url(
            REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )

    return _client


def build_cache_key(url: str) -> str:
    return f"phishguard:scan:{url}"


def get_cached_scan(url: str) -> Optional[dict[str, Any]]:
    try:
        client = get_redis_client()
        key = build_cache_key(url)

        cached = client.get(key)

        if cached is None:
            logger.info("Redis cache MISS: %s", url)
            return None

        logger.info("Redis cache HIT: %s", url)
        return json.loads(cached)

    except (redis.RedisError, json.JSONDecodeError) as exc:
        logger.warning("Redis cache read failed: %s", exc)
        return None


def set_cached_scan(
    url: str,
    result: dict[str, Any],
    ttl: int = CACHE_TTL,
) -> bool:
    try:
        client = get_redis_client()
        key = build_cache_key(url)

        client.setex(
            key,
            ttl,
            json.dumps(result, default=str),
        )

        logger.info("Redis cache SET: %s", url)
        return True

    except (redis.RedisError, TypeError, ValueError) as exc:
        logger.warning("Redis cache write failed: %s", exc)
        return False


def delete_cached_scan(url: str) -> bool:
    try:
        client = get_redis_client()
        return bool(client.delete(build_cache_key(url)))

    except redis.RedisError as exc:
        logger.warning("Redis cache delete failed: %s", exc)
        return False


def clear_cache() -> bool:
    try:
        client = get_redis_client()

        deleted = 0

        for key in client.scan_iter(match="phishguard:scan:*"):
            deleted += client.delete(key)

        logger.info("Redis cache cleared: %d entries", deleted)
        return True

    except redis.RedisError as exc:
        logger.warning("Redis cache clear failed: %s", exc)
        return False


def redis_health_check() -> bool:
    try:
        client = get_redis_client()
        return bool(client.ping())

    except redis.RedisError:
        return False