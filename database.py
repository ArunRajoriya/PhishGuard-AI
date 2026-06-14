import sqlite3
import logging
import os
from contextlib import contextmanager
from datetime import datetime

logger = logging.getLogger(__name__)

DATABASE_PATH = "database/phishguard.db"

@contextmanager
def get_db_connection():
    """Context manager for database connections"""
    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error(f"Database error: {str(e)}")
        raise
    finally:
        conn.close()

def initialize_database():
    """Initialize database tables"""
    try:
        # Check if database directory exists
        db_dir = os.path.dirname(DATABASE_PATH)
        if not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
            logger.info(f"Created database directory: {db_dir}")
        
        # Check if database file is corrupted
        if os.path.exists(DATABASE_PATH):
            try:
                # Try to connect to verify it's a valid database
                test_conn = sqlite3.connect(DATABASE_PATH)
                test_conn.execute("SELECT 1")
                test_conn.close()
            except sqlite3.DatabaseError:
                # Database is corrupted, remove it
                logger.warning(f"Corrupted database detected, removing: {DATABASE_PATH}")
                os.remove(DATABASE_PATH)
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_history(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    prediction TEXT NOT NULL,
                    confidence REAL,
                    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            logger.info("Database initialized successfully")
            
    except Exception as e:
        logger.error(f"Failed to initialize database: {str(e)}")
        # If initialization fails, try to remove corrupted database
        if os.path.exists(DATABASE_PATH):
            try:
                os.remove(DATABASE_PATH)
                logger.info("Removed corrupted database, will retry on next import")
            except Exception as remove_error:
                logger.error(f"Could not remove corrupted database: {str(remove_error)}")
        raise

def save_scan_result(url: str, prediction: str, confidence: float):
    """
    Save scan result to database
    
    Args:
        url: Scanned URL
        prediction: Risk prediction (Safe/Suspicious/Phishing)
        confidence: Confidence score
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO scan_history (url, prediction, confidence)
                VALUES (?, ?, ?)
                """,
                (url, prediction, confidence)
            )
            logger.info(f"Saved scan result: {url} - {prediction}")
            
    except Exception as e:
        logger.error(f"Failed to save scan result: {str(e)}")
        raise

def get_scan_history(limit: int = 100):
    """
    Get recent scan history
    
    Args:
        limit: Maximum number of records to return
        
    Returns:
        list: List of scan records
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, url, prediction, confidence, scanned_at
                FROM scan_history
                ORDER BY scanned_at DESC
                LIMIT ?
                """,
                (limit,)
            )
            
            rows = cursor.fetchall()
            history = []
            
            for row in rows:
                history.append({
                    "id": row["id"],
                    "url": row["url"],
                    "prediction": row["prediction"],
                    "confidence": row["confidence"],
                    "scanned_at": row["scanned_at"]
                })
            
            return history
            
    except Exception as e:
        logger.error(f"Failed to fetch scan history: {str(e)}")
        return []

def get_statistics():
    """
    Get scan statistics
    
    Returns:
        dict: Statistics including total, safe, suspicious, and phishing counts
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get total count
            cursor.execute("SELECT COUNT(*) as total FROM scan_history")
            total = cursor.fetchone()["total"]
            
            # Get counts by prediction
            cursor.execute(
                """
                SELECT prediction, COUNT(*) as count
                FROM scan_history
                GROUP BY prediction
                """
            )
            
            counts = {"Safe": 0, "Suspicious": 0, "Phishing": 0}
            for row in cursor.fetchall():
                counts[row["prediction"]] = row["count"]
            
            return {
                "total": total,
                "safe": counts["Safe"],
                "suspicious": counts["Suspicious"],
                "phishing": counts["Phishing"]
            }
            
    except Exception as e:
        logger.error(f"Failed to fetch statistics: {str(e)}")
        return {
            "total": 0,
            "safe": 0,
            "suspicious": 0,
            "phishing": 0
        }

# Initialize database on module import
initialize_database()