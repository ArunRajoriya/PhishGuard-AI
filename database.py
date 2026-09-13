import logging
import os
from contextlib import contextmanager
from typing import Any, Dict, Optional

import psycopg
from psycopg.rows import dict_row
from dotenv import load_dotenv


# ============================================================
# CONFIGURATION
# ============================================================

load_dotenv()

logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL is not configured. "
        "Add it to your .env file."
    )


# ============================================================
# DATABASE CONNECTION
# ============================================================

@contextmanager
def get_db_connection():
    """
    Create and safely manage a PostgreSQL connection.

    The transaction is committed when the context exits
    successfully and rolled back when an exception occurs.
    """

    conn = None

    try:
        conn = psycopg.connect(
            DATABASE_URL,
            row_factory=dict_row,
        )

        yield conn

        conn.commit()

    except Exception:
        if conn:
            conn.rollback()

        logger.exception(
            "Database transaction failed"
        )

        raise

    finally:
        if conn:
            conn.close()


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def initialize_database():
    """
    Create the complete PhishGuard PostgreSQL schema.
    """

    try:

        with get_db_connection() as conn:

            with conn.cursor() as cursor:

                # ====================================================
                # SCAN HISTORY TABLE
                # ====================================================

                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS scan_history (
                        id BIGSERIAL PRIMARY KEY,

                        url TEXT NOT NULL,

                        prediction VARCHAR(32) NOT NULL,

                        risk_score DOUBLE PRECISION,

                        risk_level VARCHAR(32),

                        confidence DOUBLE PRECISION,

                        trusted_domain BOOLEAN DEFAULT FALSE,

                        url_ml_score DOUBLE PRECISION,

                        hostname_ml_score DOUBLE PRECISION,

                        model_score DOUBLE PRECISION,

                        rule_score DOUBLE PRECISION,

                        threat_score DOUBLE PRECISION,

                        vt_malicious INTEGER DEFAULT 0,

                        vt_suspicious INTEGER DEFAULT 0,

                        vt_harmless INTEGER DEFAULT 0,

                        vt_undetected INTEGER DEFAULT 0,

                        vt_total_engines INTEGER DEFAULT 0,

                        threat_intel_status VARCHAR(32),

                        threat_intel_provider VARCHAR(64),

                        scan_duration_ms DOUBLE PRECISION,

                        scanned_at TIMESTAMPTZ NOT NULL
                            DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )

                # ====================================================
                # SCAN HISTORY INDEXES
                # ====================================================

                cursor.execute(
                    """
                    CREATE INDEX IF NOT EXISTS
                    idx_scan_history_scanned_at
                    ON scan_history (scanned_at DESC)
                    """
                )

                cursor.execute(
                    """
                    CREATE INDEX IF NOT EXISTS
                    idx_scan_history_prediction
                    ON scan_history (prediction)
                    """
                )

                cursor.execute(
                    """
                    CREATE INDEX IF NOT EXISTS
                    idx_scan_history_risk_level
                    ON scan_history (risk_level)
                    """
                )

                cursor.execute(
                    """
                    CREATE INDEX IF NOT EXISTS
                    idx_scan_history_trusted_domain
                    ON scan_history (trusted_domain)
                    """
                )

                # ====================================================
                # USERS TABLE
                # ====================================================

                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        id BIGSERIAL PRIMARY KEY,

                        email VARCHAR(255) NOT NULL UNIQUE,

                        password_hash TEXT NOT NULL,

                        role VARCHAR(32) NOT NULL DEFAULT 'user',

                        is_active BOOLEAN NOT NULL DEFAULT TRUE,

                        created_at TIMESTAMPTZ NOT NULL
                            DEFAULT CURRENT_TIMESTAMP,

                        updated_at TIMESTAMPTZ NOT NULL
                            DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )

                # ====================================================
                # USER INDEX
                # ====================================================

                cursor.execute(
                    """
                    CREATE INDEX IF NOT EXISTS
                    idx_users_email
                    ON users (email)
                    """
                )

        logger.info(
            "PostgreSQL database initialized successfully"
        )

    except Exception:
        logger.exception(
            "Failed to initialize PostgreSQL database"
        )
        raise


# ============================================================
# SAFE TYPE CONVERSION
# ============================================================

def _safe_float(value: Any) -> Optional[float]:
    """
    Safely convert a value to float.
    """

    if value is None:
        return None

    try:
        return float(value)

    except (TypeError, ValueError):
        return None


def _safe_int(value: Any) -> int:
    """
    Safely convert a value to integer.
    """

    if value is None:
        return 0

    try:
        return int(value)

    except (TypeError, ValueError):
        return 0


# ============================================================
# SAVE SCAN
# ============================================================

def save_scan(
    url: str,
    prediction: str,
    confidence: float,
    risk_score: Optional[float] = None,
    risk_level: Optional[str] = None,
    trusted_domain: bool = False,
    models: Optional[Dict[str, Any]] = None,
    threat_intelligence: Optional[Dict[str, Any]] = None,
    scan_duration_ms: Optional[float] = None,
):
    """
    Save a complete PhishGuard scan.

    The first three arguments remain compatible with the
    previous database implementation.
    """

    models = models or {}

    threat_intelligence = (
        threat_intelligence or {}
    )

    # ========================================================
    # MODEL DATA
    # ========================================================

    url_ml = models.get("url_ml") or {}

    hostname_ml = (
        models.get("hostname_ml") or {}
    )

    url_ml_score = _safe_float(
        url_ml.get("score")
    )

    hostname_ml_score = _safe_float(
        hostname_ml.get("probability")
    )

    # Hostname model currently returns probability
    # rather than a normalized score.

    if hostname_ml_score is not None:
        hostname_ml_score *= 100.0

    model_score = _safe_float(
        models.get("fusion_score")
    )

    if model_score is None:
        model_score = _safe_float(
            models.get("model_score")
        )

    rule_score = _safe_float(
        models.get("rule_score")
    )

    # ========================================================
    # THREAT INTELLIGENCE DATA
    # ========================================================

    threat_score = _safe_float(
        threat_intelligence.get(
            "threat_score"
        )
    )

    vt_malicious = _safe_int(
        threat_intelligence.get(
            "malicious"
        )
    )

    vt_suspicious = _safe_int(
        threat_intelligence.get(
            "suspicious"
        )
    )

    vt_harmless = _safe_int(
        threat_intelligence.get(
            "harmless"
        )
    )

    vt_undetected = _safe_int(
        threat_intelligence.get(
            "undetected"
        )
    )

    vt_total_engines = _safe_int(
        threat_intelligence.get(
            "total_engines"
        )
    )

    threat_intel_status = (
        threat_intelligence.get(
            "status"
        )
    )

    threat_intel_provider = (
        threat_intelligence.get(
            "provider"
        )
    )

    # ========================================================
    # INSERT SCAN
    # ========================================================

    with get_db_connection() as conn:

        with conn.cursor() as cursor:

            cursor.execute(
                """
                INSERT INTO scan_history
                (
                    url,
                    prediction,
                    risk_score,
                    risk_level,
                    confidence,
                    trusted_domain,

                    url_ml_score,
                    hostname_ml_score,
                    model_score,
                    rule_score,

                    threat_score,

                    vt_malicious,
                    vt_suspicious,
                    vt_harmless,
                    vt_undetected,
                    vt_total_engines,

                    threat_intel_status,
                    threat_intel_provider,

                    scan_duration_ms
                )
                VALUES
                (
                    %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    %s,
                    %s, %s, %s, %s, %s,
                    %s, %s,
                    %s
                )
                RETURNING id
                """,
                (
                    url,
                    prediction,
                    _safe_float(risk_score),
                    risk_level,
                    _safe_float(confidence),
                    bool(trusted_domain),

                    url_ml_score,
                    hostname_ml_score,
                    model_score,
                    rule_score,

                    threat_score,

                    vt_malicious,
                    vt_suspicious,
                    vt_harmless,
                    vt_undetected,
                    vt_total_engines,

                    threat_intel_status,
                    threat_intel_provider,

                    _safe_float(
                        scan_duration_ms
                    ),
                ),
            )

            row = cursor.fetchone()

            scan_id = row["id"]

            logger.info(
                "Saved scan #%s: %s -> %s",
                scan_id,
                url,
                prediction,
            )

            return scan_id


# ============================================================
# RECENT SCANS
# ============================================================

def get_recent_scans(
    limit: int = 100,
):
    """
    Return the most recent scans.
    """

    try:

        limit = max(
            1,
            min(int(limit), 1000),
        )

        with get_db_connection() as conn:

            with conn.cursor() as cursor:

                cursor.execute(
                    """
                    SELECT
                        id,
                        url,
                        prediction,
                        risk_score,
                        risk_level,
                        confidence,
                        trusted_domain,
                        url_ml_score,
                        hostname_ml_score,
                        model_score,
                        rule_score,
                        threat_score,
                        vt_malicious,
                        vt_suspicious,
                        vt_harmless,
                        vt_undetected,
                        vt_total_engines,
                        threat_intel_status,
                        threat_intel_provider,
                        scan_duration_ms,
                        scanned_at
                    FROM scan_history
                    ORDER BY
                        scanned_at DESC,
                        id DESC
                    LIMIT %s
                    """,
                    (limit,),
                )

                return cursor.fetchall()

    except Exception:

        logger.exception(
            "Failed to fetch recent scans"
        )

        return []


# ============================================================
# STATISTICS
# ============================================================

def get_stats():
    """
    Return dashboard statistics.
    """

    try:

        with get_db_connection() as conn:

            with conn.cursor() as cursor:

                # Total scans

                cursor.execute(
                    """
                    SELECT COUNT(*) AS total
                    FROM scan_history
                    """
                )

                total = cursor.fetchone()[
                    "total"
                ]

                # Prediction counts

                cursor.execute(
                    """
                    SELECT
                        prediction,
                        COUNT(*) AS count
                    FROM scan_history
                    GROUP BY prediction
                    """
                )

                counts = {
                    "Safe": 0,
                    "Suspicious": 0,
                    "Phishing": 0,
                }

                for row in cursor.fetchall():

                    prediction = row[
                        "prediction"
                    ]

                    if prediction in counts:
                        counts[prediction] = (
                            row["count"]
                        )

                return {
                    "total": total,
                    "safe": counts["Safe"],
                    "suspicious": counts[
                        "Suspicious"
                    ],
                    "phishing": counts[
                        "Phishing"
                    ],
                }

    except Exception:

        logger.exception(
            "Failed to fetch statistics"
        )

        return {
            "total": 0,
            "safe": 0,
            "suspicious": 0,
            "phishing": 0,
        }


# ============================================================
# USER MANAGEMENT
# ============================================================

def create_user(
    email: str,
    password_hash: str,
    role: str = "user",
):
    """
    Create a new application user.

    Returns the newly created user without
    exposing the password hash.
    """

    with get_db_connection() as conn:

        with conn.cursor() as cursor:

            cursor.execute(
                """
                INSERT INTO users
                (
                    email,
                    password_hash,
                    role
                )
                VALUES
                (
                    %s,
                    %s,
                    %s
                )
                RETURNING
                    id,
                    email,
                    role,
                    is_active,
                    created_at
                """,
                (
                    email,
                    password_hash,
                    role,
                ),
            )

            return cursor.fetchone()


def get_user_by_email(
    email: str,
):
    """
    Retrieve a user by email address.

    The password hash is returned because it is
    required for authentication verification.
    """

    with get_db_connection() as conn:

        with conn.cursor() as cursor:

            cursor.execute(
                """
                SELECT
                    id,
                    email,
                    password_hash,
                    role,
                    is_active,
                    created_at,
                    updated_at
                FROM users
                WHERE email = %s
                """,
                (email,),
            )

            return cursor.fetchone()


def get_user_by_id(
    user_id: int,
):
    """
    Retrieve a user by primary key.
    """

    with get_db_connection() as conn:

        with conn.cursor() as cursor:

            cursor.execute(
                """
                SELECT
                    id,
                    email,
                    role,
                    is_active,
                    created_at,
                    updated_at
                FROM users
                WHERE id = %s
                """,
                (user_id,),
            )

            return cursor.fetchone()


def update_user_last_modified(
    user_id: int,
):
    """
    Update the user's updated_at timestamp.
    """

    with get_db_connection() as conn:

        with conn.cursor() as cursor:

            cursor.execute(
                """
                UPDATE users
                SET updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
                """,
                (user_id,),
            )


def deactivate_user(
    user_id: int,
):
    """
    Deactivate a user account.
    """

    with get_db_connection() as conn:

        with conn.cursor() as cursor:

            cursor.execute(
                """
                UPDATE users
                SET
                    is_active = FALSE,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
                RETURNING
                    id,
                    email,
                    role,
                    is_active,
                    updated_at
                """,
                (user_id,),
            )

            return cursor.fetchone()


# ============================================================
# BACKWARD-COMPATIBLE FUNCTION NAMES
# ============================================================

def save_scan_result(
    url: str,
    prediction: str,
    confidence: float,
):
    return save_scan(
        url=url,
        prediction=prediction,
        confidence=confidence,
    )


def get_scan_history(
    limit: int = 100,
):
    return get_recent_scans(limit)


def get_statistics():
    return get_stats()


# ============================================================
# DATABASE INITIALIZATION
# ============================================================
# Database initialization is handled explicitly by app.py
# during FastAPI startup.