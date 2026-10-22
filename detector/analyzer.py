"""
Master Risk Analyzer & Scoring Engine.
Combines URL heuristics and live DOM inspection into an explainable risk score (0-100),
verdict classification, and personalized cybersecurity advice.
"""

from .url_rules import parse_and_tokenize_url, analyze_url_heuristics
from .page_inspector import inspect_webpage

def generate_safety_advice(risk_level: str, indicators: list, target_brand: str = None) -> list:
    """Generates actionable, non-technical safety recommendations for users."""
    advice = []

    has_https_issue = any("HTTPS" in ind["id"] or "SSL" in ind["id"] for ind in indicators)
    has_brand_issue = any("BRAND" in ind["id"] or "TYPOSQUATTING" in ind["id"] or "SUBDOMAIN_HIJACK" in ind["id"] for ind in indicators)
    has_form_issue = any("FORM" in ind["id"] or "EXFILTRATION" in ind["id"] for ind in indicators)
    has_redirect_issue = any("REDIRECT" in ind["id"] for ind in indicators)

    if risk_level == "high":
        advice.append("⚠️ DO NOT enter your username, password, or OTP on this website.")
        if target_brand:
            advice.append(f"🔒 If you need to access {target_brand}, navigate manually by typing the official address in a new tab.")
        if has_form_issue:
            advice.append("🚨 The login form on this page has been flagged for abnormal data exfiltration. Close this browser tab immediately.")
        if has_https_issue:
            advice.append("🚫 This page lacks secure encryption. Any data typed here can be intercepted by anyone on your network or Wi-Fi.")
    elif risk_level == "medium":
        advice.append("⚠️ Exercise caution: Multiple suspicious traits were found on this domain.")
        if has_brand_issue:
            advice.append("🔍 Verify the spelling in the address bar closely. Look out for substituted letters (e.g. '0' instead of 'o').")
        if has_redirect_issue:
            advice.append("🔄 The website redirected across multiple destinations. Confirm where the final page landed.")
        advice.append("🛡️ Check if the website has a valid security lock icon and verified SSL certificate in your browser.")
    else:
        advice.append("✅ No major deceptive patterns were detected by our rule-based scanner.")
        advice.append("💡 Remember that even legitimate websites can occasionally be compromised. Always verify before entering sensitive passwords.")

    advice.append("🔑 Tip: Enable Two-Factor Authentication (2FA) wherever possible so stolen passwords alone cannot compromise your accounts.")
    return advice

def analyze_url_and_page(raw_url: str, perform_page_inspection: bool = True) -> dict:
    """
    Primary analysis coordinator. Evaluates URL and optionally inspects page DOM.
    Returns complete report dictionary.
    """
    if not raw_url or not raw_url.strip():
        return {"error": "Please provide a valid URL to analyze."}

    # 1. Tokenize URL
    tokens = parse_and_tokenize_url(raw_url)

    # 2. Run URL Heuristic Rules
    url_indicators = analyze_url_heuristics(tokens)

    # 3. Optional Live Page Inspection
    page_inspection_data = None
    page_indicators = []
    
    if perform_page_inspection:
        # Determine URL to fetch
        fetch_url = tokens["raw_url"]
        if not tokens["has_explicit_scheme"]:
            fetch_url = f"http://{tokens['raw_url']}"

        page_inspection_data = inspect_webpage(fetch_url)
        page_indicators = page_inspection_data.get("indicators", [])

    # 4. Combine all indicators
    all_indicators = url_indicators + page_indicators

    # Deduplicate indicators by id if needed
    seen_ids = set()
    deduped_indicators = []
    for ind in all_indicators:
        if ind["id"] not in seen_ids:
            seen_ids.add(ind["id"])
            deduped_indicators.append(ind)

    # 5. Calculate Aggregated Risk Score
    raw_score = sum(ind["points"] for ind in deduped_indicators)
    capped_score = min(100, max(0, raw_score))

    # 6. Determine Risk Level
    # Standard Viva thresholds:
    # 0 - 29: Low Risk
    # 30 - 59: Medium Risk
    # 60 - 100: High Risk
    if capped_score >= 60:
        risk_level = "high"
        verdict = "High Risk - Potential Phishing / Fake Login Page"
        status_color = "#ef4444"  # Red
        badge_class = "badge-danger"
    elif capped_score >= 30:
        risk_level = "medium"
        verdict = "Medium Risk - Suspicious Indicators Detected"
        status_color = "#f59e0b"  # Amber
        badge_class = "badge-warning"
    else:
        risk_level = "low"
        verdict = "Low Risk - No Obvious Deceptive Indicators Found"
        status_color = "#10b981"  # Emerald Green
        badge_class = "badge-success"

    # Identify potential target brand mentioned in any rule
    target_brand = None
    for ind in deduped_indicators:
        if "Brand" in ind["title"] or "Typosquatting" in ind["title"]:
            match = ind["title"].split("(")
            if len(match) > 1:
                target_brand = match[1].replace(")", "").strip()
                break

    # 7. Generate Safety Advice
    safety_advice = generate_safety_advice(risk_level, deduped_indicators, target_brand)

    # 8. Token breakdown for UI highlighting
    visual_tokens = {
        "scheme": tokens["scheme"],
        "subdomain": tokens["subdomain"],
        "domain": tokens["domain"],
        "tld": tokens["tld"],
        "port": f":{tokens['port']}" if tokens["port"] else "",
        "path": tokens["path"],
        "query": f"?{tokens['query']}" if tokens["query"] else "",
        "is_ip": tokens["is_ip"]
    }

    # Summary report
    return {
        "url": tokens["raw_url"],
        "normalized_url": tokens["normalized_url"],
        "risk_score": capped_score,
        "risk_level": risk_level,
        "verdict": verdict,
        "status_color": status_color,
        "badge_class": badge_class,
        "target_brand": target_brand,
        "visual_tokens": visual_tokens,
        "indicators_count": len(deduped_indicators),
        "indicators": deduped_indicators,
        "safety_advice": safety_advice,
        "page_inspection": {
            "performed": perform_page_inspection,
            "reachable": page_inspection_data.get("reachable", False) if page_inspection_data else False,
            "status_code": page_inspection_data.get("status_code") if page_inspection_data else None,
            "redirect_count": page_inspection_data.get("redirect_count", 0) if page_inspection_data else 0,
            "has_login_form": page_inspection_data.get("has_login_form", False) if page_inspection_data else False,
            "has_password_input": page_inspection_data.get("has_password_input", False) if page_inspection_data else False,
            "page_title": page_inspection_data.get("page_title", "") if page_inspection_data else "",
            "forms_analyzed": page_inspection_data.get("forms_analyzed", []) if page_inspection_data else [],
            "error_message": page_inspection_data.get("error_message") if page_inspection_data else None
        }
    }
