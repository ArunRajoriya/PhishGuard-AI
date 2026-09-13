import json
import logging
import os
import uuid
from datetime import datetime, timezone

import redis

from cache.redis_cache import get_redis_client

logger = logging.getLogger("phishguard.scan_queue")

QUEUE_NAME = os.getenv(
    "SCAN_QUEUE_NAME",
    "phishguard:scan_queue",
)

JOB_PREFIX = "phishguard:job:"
JOB_TTL = int(
    os.getenv("SCAN_JOB_TTL", "3600")
)


def create_scan_job(url: str) -> dict:
    """
    Create a new scan job and push it into Redis.
    """

    scan_id = str(uuid.uuid4())

    job = {
        "scan_id": scan_id,
        "url": url,
        "status": "queued",
        "created_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "updated_at": datetime.now(
            timezone.utc
        ).isoformat(),
    }

    client = get_redis_client()

    job_key = f"{JOB_PREFIX}{scan_id}"

    client.setex(
        job_key,
        JOB_TTL,
        json.dumps(job),
    )

    client.rpush(
        QUEUE_NAME,
        scan_id,
    )

    logger.info(
        "Scan job created | scan_id=%s | url=%s",
        scan_id,
        url,
    )

    return job


def get_scan_job(scan_id: str) -> dict | None:
    """
    Retrieve a scan job from Redis.
    """

    client = get_redis_client()

    job_key = f"{JOB_PREFIX}{scan_id}"

    data = client.get(job_key)

    if data is None:
        return None

    try:
        return json.loads(data)
    except json.JSONDecodeError:
        logger.warning(
            "Invalid job data | scan_id=%s",
            scan_id,
        )
        return None


def update_scan_job(
    scan_id: str,
    **updates,
) -> dict | None:
    """
    Update an existing scan job.
    """

    client = get_redis_client()

    job_key = f"{JOB_PREFIX}{scan_id}"

    data = client.get(job_key)

    if data is None:
        return None

    try:
        job = json.loads(data)
    except json.JSONDecodeError:
        logger.warning(
            "Invalid job data | scan_id=%s",
            scan_id,
        )
        return None

    job.update(updates)

    job["updated_at"] = datetime.now(
        timezone.utc
    ).isoformat()

    client.setex(
        job_key,
        JOB_TTL,
        json.dumps(job),
    )

    logger.info(
        "Scan job updated | scan_id=%s | status=%s",
        scan_id,
        job.get("status"),
    )

    return job


def pop_scan_job(timeout: int = 1) -> str | None:
    """
    Wait for the next scan job.

    Uses Redis blocking pop so the worker does not
    continuously poll Redis.
    """

    client = get_redis_client()

    result = client.blpop(
        QUEUE_NAME,
        timeout=timeout,
    )

    if result is None:
        return None

    _, scan_id = result

    logger.info(
        "Scan job received | scan_id=%s",
        scan_id,
    )

    return scan_id