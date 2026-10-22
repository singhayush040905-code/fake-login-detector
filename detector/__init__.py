"""
Fake Login Page Awareness Detector Package
"""

from .analyzer import analyze_url_and_page
from .ip_scanner import scan_ip_full
from .database import init_db, save_scan, get_recent_scans, get_scan_by_id, clear_history, get_scan_stats

__all__ = [
    "analyze_url_and_page",
    "scan_ip_full",
    "init_db",
    "save_scan",
    "get_recent_scans",
    "get_scan_by_id",
    "clear_history",
    "get_scan_stats"
]
