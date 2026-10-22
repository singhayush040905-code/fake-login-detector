"""
SQLite Database Layer for Scan History and Reporting.
Stores analysis results, metadata, and provides retrieval for history logs and stats.
"""

import os
import json
import sqlite3
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scans.db")

def get_connection():
    """Returns a connection to the SQLite database with dictionary cursor row factory."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database schema if it doesn't already exist."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            normalized_url TEXT,
            target_brand TEXT,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            indicators_count INTEGER DEFAULT 0,
            report_json TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def save_scan(report: dict) -> int:
    """Saves a scan report to SQLite and returns the inserted scan ID."""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO scan_history (
            url, normalized_url, target_brand, risk_score, 
            risk_level, indicators_count, report_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        report.get("url"),
        report.get("normalized_url"),
        report.get("target_brand"),
        report.get("risk_score", 0),
        report.get("risk_level", "low"),
        report.get("indicators_count", 0),
        json.dumps(report),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def get_recent_scans(limit: int = 50) -> list:
    """Retrieves recent scans ordered by timestamp descending."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, url, normalized_url, target_brand, risk_score, 
               risk_level, indicators_count, created_at 
        FROM scan_history 
        ORDER BY id DESC 
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_scan_by_id(scan_id: int) -> dict:
    """Retrieves full JSON report for a specific scan ID."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT report_json FROM scan_history WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return json.loads(row["report_json"])
    return None

def clear_history():
    """Deletes all saved scan history records."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scan_history")
    conn.commit()
    conn.close()

def get_scan_stats() -> dict:
    """Returns aggregated statistics for the dashboard."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) AS total FROM scan_history")
    total = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS count FROM scan_history WHERE risk_level = 'high'")
    high = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) AS count FROM scan_history WHERE risk_level = 'medium'")
    medium = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) AS count FROM scan_history WHERE risk_level = 'low'")
    low = cursor.fetchone()["count"]

    conn.close()
    return {
        "total_scans": total,
        "high_risk": high,
        "medium_risk": medium,
        "low_risk": low
    }
