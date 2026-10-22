"""
Flask Web Application Entrypoint for Fake Login Page Awareness Detector.
Provides RESTful API endpoints for URL analysis, scan history management,
and local simulation endpoints for demonstration purposes.
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for
from detector import (
    analyze_url_and_page,
    init_db,
    save_scan,
    get_recent_scans,
    get_scan_by_id,
    clear_history,
    get_scan_stats
)

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# Initialize the SQLite schema on startup
with app.app_context():
    init_db()

@app.route("/")
def index():
    """Main dashboard page."""
    stats = get_scan_stats()
    return render_template("index.html", stats=stats)

@app.route("/api/scan", methods=["POST"])
def api_scan():
    """
    POST API to scan a URL.
    Payload: { "url": "http://...", "inspect_page": true|false }
    """
    data = request.get_json(silent=True) or request.form
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"status": "error", "message": "A website URL is required for scanning."}), 400

    inspect_page = data.get("inspect_page", True)
    if isinstance(inspect_page, str):
        inspect_page = inspect_page.lower() in ("true", "1", "yes")

    try:
        report = analyze_url_and_page(url, perform_page_inspection=inspect_page)
        if "error" in report:
            return jsonify({"status": "error", "message": report["error"]}), 400

        scan_id = save_scan(report)
        return jsonify({
            "status": "success",
            "scan_id": scan_id,
            "data": report
        })
    except Exception as e:
        return jsonify({"status": "error", "message": f"Scanning error: {str(e)}"}), 500

@app.route("/history")
def history_page():
    """Scan history view."""
    scans = get_recent_scans(limit=100)
    stats = get_scan_stats()
    return render_template("history.html", scans=scans, stats=stats)

@app.route("/api/history", methods=["GET"])
def api_get_history():
    """Retrieves recent scans list in JSON format."""
    limit = request.args.get("limit", 50, type=int)
    scans = get_recent_scans(limit=limit)
    return jsonify({"status": "success", "scans": scans})

@app.route("/api/history/<int:scan_id>", methods=["GET"])
def api_get_scan(scan_id):
    """Retrieves full report for a specific scan ID."""
    report = get_scan_by_id(scan_id)
    if not report:
        return jsonify({"status": "error", "message": "Scan report not found."}), 404
    return jsonify({"status": "success", "data": report})

@app.route("/api/history/clear", methods=["POST"])
def api_clear_history():
    """Clears all saved scans."""
    clear_history()
    return jsonify({"status": "success", "message": "Scan history cleared successfully."})

@app.route("/api/stats", methods=["GET"])
def api_stats():
    """Returns database statistics."""
    return jsonify({"status": "success", "stats": get_scan_stats()})

@app.route("/about")
def about():
    """Project documentation, architecture, and Viva preparation guide."""
    return render_template("about.html")

# Simulated Demonstration Endpoints
@app.route("/demo/legitimate-login", methods=["GET", "POST"])
def demo_legitimate():
    """Mock authorized login page for safe lab demonstration."""
    return render_template("demo/legitimate_demo.html")

@app.route("/demo/phishing-login", methods=["GET", "POST"])
def demo_phishing():
    """Mock deceptive login page for detection demonstration."""
    return render_template("demo/phishing_demo.html")

if __name__ == "__main__":
    # Host on 127.0.0.1:5000
    app.run(host="127.0.0.1", port=5000, debug=True)
