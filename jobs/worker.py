import logging
import os
import time

from jobs.scan_queue import (
    pop_scan_job,
    get_scan_job,
    update_scan_job,
)

from app import perform_scan


logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

logger = logging.getLogger("phishguard.worker")


def process_scan_job(scan_id: str) -> None:
    """Process a single asynchronous scan job."""

    job = get_scan_job(scan_id)

    if job is None:
        logger.warning(
            "Job not found | scan_id=%s",
            scan_id,
        )
        return

    url = job["url"]

    logger.info(
        "Processing scan job | scan_id=%s | url=%s",
        scan_id,
        url,
    )

    # ------------------------------------------------------------
    # Mark job as processing
    # ------------------------------------------------------------
    update_scan_job(
        scan_id,
        status="processing",
    )

    started_at = time.perf_counter()

    try:
        # --------------------------------------------------------
        # IMPORTANT:
        # Use the central scan pipeline from app.py.
        #
        # This handles:
        #   Redis cache lookup
        #   ML analysis
        #   Risk engine
        #   Threat intelligence
        #   PostgreSQL history
        #   Redis cache write
        # --------------------------------------------------------
        result = perform_scan(
            normalized_url=url,
            request_id=f"async-{scan_id}",
        )

        duration_ms = (
            time.perf_counter() - started_at
        ) * 1000

        # --------------------------------------------------------
        # Store completed result in Redis job state
        # --------------------------------------------------------
        update_scan_job(
            scan_id,
            status="completed",
            result=result,
            duration_ms=round(
                duration_ms,
                2,
            ),
        )

        logger.info(
            "Scan job completed | "
            "scan_id=%s | duration=%.2fms",
            scan_id,
            duration_ms,
        )

    except Exception as exc:
        duration_ms = (
            time.perf_counter() - started_at
        ) * 1000

        logger.exception(
            "Scan job failed | scan_id=%s",
            scan_id,
        )

        update_scan_job(
            scan_id,
            status="failed",
            error=str(exc),
            duration_ms=round(
                duration_ms,
                2,
            ),
        )


def run_worker() -> None:
    """Continuously consume scan jobs from Redis."""

    logger.info(
        "PhishGuard worker started."
    )

    while True:
        try:
            scan_id = pop_scan_job(
                timeout=1,
            )

            if scan_id is None:
                continue

            logger.info(
                "Scan job received | scan_id=%s",
                scan_id,
            )

            process_scan_job(scan_id)

        except KeyboardInterrupt:
            logger.info(
                "Worker stopped."
            )
            break

        except Exception:
            logger.exception(
                "Unexpected worker error."
            )

            time.sleep(1)


if __name__ == "__main__":
    run_worker()