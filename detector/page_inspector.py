"""
Webpage Content Inspector & DOM Analyzer.
Fetches permitted pages safely, tracks HTTP redirects, inspects login forms,
checks for external credential harvesting actions, and detects brand title spoofing.
"""

from urllib.parse import urlparse, urljoin
import re
import requests
from bs4 import BeautifulSoup
from .brands import TARGET_BRANDS

# Browser-like headers to prevent superficial blocking during benign inspection
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5"
}

def inspect_webpage(url: str, timeout: float = 4.5) -> dict:
    """
    Safely fetches and inspects a webpage for redirect chains and login form security.
    Returns inspection findings and security indicators.
    """
    result = {
        "reachable": False,
        "status_code": None,
        "final_url": url,
        "redirect_count": 0,
        "redirect_history": [],
        "has_login_form": False,
        "has_password_input": False,
        "page_title": "",
        "forms_analyzed": [],
        "indicators": [],
        "error_message": None
    }

    try:
        session = requests.Session()
        response = session.get(
            url,
            headers=DEFAULT_HEADERS,
            timeout=timeout,
            allow_redirects=True,
            verify=False  # Allow analyzing self-signed or invalid SSL certs on phishing sites
        )

        result["reachable"] = True
        result["status_code"] = response.status_code
        result["final_url"] = response.url
        result["redirect_count"] = len(response.history)
        result["redirect_history"] = [resp.url for resp in response.history]

        parsed_initial = urlparse(url)
        parsed_final = urlparse(response.url)

        # 1. Inspect Redirect Behavior
        if len(response.history) > 0:
            # Check for redirect to completely different domain
            initial_host = parsed_initial.netloc.split(":")[0].lower()
            final_host = parsed_final.netloc.split(":")[0].lower()

            if initial_host != final_host and not final_host.endswith(f".{initial_host}"):
                result["indicators"].append({
                    "id": "RULE_SUSPICIOUS_REDIRECT",
                    "category": "Redirect Behavior",
                    "title": "Cross-Domain Redirect Detected",
                    "severity": "high",
                    "points": 20,
                    "suspicious_part": f"{initial_host} ➜ {final_host}",
                    "explanation": f"The page immediately redirects from '{initial_host}' to a different domain '{final_host}'.",
                    "technical_detail": "Threat actors use disposable forwarding domains or open redirects on compromised sites to divert victims to credential collection panels."
                })

            # Check for HTTPS downgrade
            if parsed_initial.scheme == "https" and parsed_final.scheme == "http":
                result["indicators"].append({
                    "id": "RULE_HTTPS_DOWNGRADE",
                    "category": "Redirect Behavior",
                    "title": "Insecure Protocol Downgrade (HTTPS ➜ HTTP)",
                    "severity": "high",
                    "points": 25,
                    "suspicious_part": "HTTPS ➜ HTTP",
                    "explanation": "The website downgraded encryption from secure HTTPS to insecure plaintext HTTP.",
                    "technical_detail": "SSL stripping / protocol downgrade attack exposes transmitted credentials to local network packet inspection."
                })

            # Multiple excessive redirects
            if len(response.history) >= 3:
                result["indicators"].append({
                    "id": "RULE_EXCESSIVE_REDIRECTS",
                    "category": "Redirect Behavior",
                    "title": f"Excessive Redirect Chain ({len(response.history)} hops)",
                    "severity": "medium",
                    "points": 15,
                    "suspicious_part": f"{len(response.history)} redirects",
                    "explanation": f"The request was bounced across {len(response.history)} different redirect URLs before loading.",
                    "technical_detail": "Multi-hop redirect cloaking is employed to evade automated web crawlers and security scanners."
                })

        # 2. Parse DOM with BeautifulSoup
        html_content = response.text
        soup = BeautifulSoup(html_content, "html.parser")

        # Extract Page Title
        title_tag = soup.find("title")
        if title_tag and title_tag.string:
            result["page_title"] = title_tag.string.strip()

        # Check for Brand Impersonation in Title vs Actual Domain
        if result["page_title"]:
            title_lower = result["page_title"].lower()
            final_host = parsed_final.netloc.split(":")[0].lower()

            for brand_key, brand_info in TARGET_BRANDS.items():
                brand_name = brand_info["name"]
                is_official = any(final_host == off or final_host.endswith(f".{off}") for off in brand_info["official_domains"])

                if not is_official and any(kw in title_lower for kw in [f"{brand_key} login", f"{brand_key} sign in", f"{brand_key} account", f"{brand_key} verification"]):
                    result["indicators"].append({
                        "id": "RULE_TITLE_BRAND_MISMATCH",
                        "category": "Page Content",
                        "title": f"Page Title Spoofing ({brand_name})",
                        "severity": "high",
                        "points": 25,
                        "suspicious_part": result["page_title"],
                        "explanation": f"The webpage title claims to be '{result['page_title']}', but the domain is '{final_host}', which is NOT an official {brand_name} website.",
                        "technical_detail": "Visual brand impersonation detected in HTML <title> metadata without corresponding authoritative domain infrastructure."
                    })
                    break

        # 3. Inspect Login Forms & Password Fields
        forms = soup.find_all("form")
        password_inputs = soup.find_all("input", attrs={"type": re.compile(r"^password$", re.I)})

        if password_inputs:
            result["has_password_input"] = True

        for idx, form in enumerate(forms):
            form_passwords = form.find_all("input", attrs={"type": re.compile(r"^password$", re.I)})
            has_password = len(form_passwords) > 0
            if has_password:
                result["has_login_form"] = True

            raw_action = form.get("action", "").strip()
            method = form.get("method", "get").upper()

            # Resolve relative action to absolute URL
            action_url = urljoin(response.url, raw_action) if raw_action else response.url
            action_parsed = urlparse(action_url)

            form_data = {
                "form_index": idx + 1,
                "action": raw_action or "(Same Page / Empty)",
                "resolved_action": action_url,
                "method": method,
                "has_password": has_password,
                "inputs_count": len(form.find_all("input"))
            }
            result["forms_analyzed"].append(form_data)

            if has_password:
                # Check A: Cross-Domain Form Action (Credentials posted to 3rd party domain)
                form_host = action_parsed.netloc.split(":")[0].lower()
                current_host = parsed_final.netloc.split(":")[0].lower()

                # Identify known third-party collector services
                suspicious_collectors = ["telegram.org", "discord.com", "formspree.io", "forms.gle", "pastebin.com", "glitch.me"]
                is_exfiltration_service = any(srv in form_host for srv in suspicious_collectors)

                if is_exfiltration_service:
                    result["indicators"].append({
                        "id": "RULE_CREDENTIAL_EXFILTRATION",
                        "category": "Login Form Behavior",
                        "title": f"Known Exfiltration Service in Form Action ({form_host})",
                        "severity": "high",
                        "points": 30,
                        "suspicious_part": action_url,
                        "explanation": f"This login form sends user passwords directly to an external third-party service ({form_host}).",
                        "technical_detail": "Threat actor exfiltration pipeline: Login credentials are submitted straight to an external API or webhook."
                    })
                elif form_host and form_host != current_host and not form_host.endswith(f".{current_host}"):
                    result["indicators"].append({
                        "id": "RULE_EXTERNAL_FORM_ACTION",
                        "category": "Login Form Behavior",
                        "title": "Login Form Submits to External Domain",
                        "severity": "high",
                        "points": 25,
                        "suspicious_part": form_host,
                        "explanation": f"The login form collects passwords on '{current_host}' but transmits them to a different domain: '{form_host}'.",
                        "technical_detail": "Cross-origin form submission vulnerability: Credential harvesting forms frequently submit victim inputs to a centralized dropper server."
                    })

                # Check B: Password submitted over insecure HTTP
                if action_parsed.scheme == "http":
                    result["indicators"].append({
                        "id": "RULE_INSECURE_FORM_ACTION",
                        "category": "Login Form Behavior",
                        "title": "Password Submitted Over Unencrypted HTTP",
                        "severity": "high",
                        "points": 25,
                        "suspicious_part": action_url,
                        "explanation": "The login form action transmits sensitive passwords via unencrypted HTTP, exposing credentials to network interception.",
                        "technical_detail": "CWE-319: Cleartext Transmission of Sensitive Information via HTTP POST."
                    })

                # Check C: Empty or dummy form action (# or javascript:) with password field
                if raw_action in ("#", "javascript:void(0)", "javascript:;", ""):
                    result["indicators"].append({
                        "id": "RULE_EMPTY_OR_SCRIPT_ACTION",
                        "category": "Login Form Behavior",
                        "title": "Suspicious JavaScript / In-Memory Form Capture",
                        "severity": "medium",
                        "points": 15,
                        "suspicious_part": f"action='{raw_action}'",
                        "explanation": "The login form has no standard destination URL and likely intercepts your password using client-side JavaScript.",
                        "technical_detail": "AJAX / Fetch credential snatching: The page prevents standard POST submission and sends harvested data asynchronously via obscured scripts."
                    })

        # 4. Anti-Analysis Scripts (Disabled Right-Click / Context Menu)
        body_tag = soup.find("body")
        if body_tag:
            body_attrs = " ".join(body_tag.attrs.keys()) + " " + " ".join(str(v) for v in body_tag.attrs.values())
            if "oncontextmenu" in body_attrs or "return false" in body_attrs:
                result["indicators"].append({
                    "id": "RULE_ANTI_ANALYSIS",
                    "category": "Page Content",
                    "title": "Anti-Inspection Scripting Detected",
                    "severity": "medium",
                    "points": 10,
                    "suspicious_part": "oncontextmenu disabled",
                    "explanation": "The webpage disables right-clicking or developer tools to prevent visitors from inspecting its underlying source code.",
                    "technical_detail": "Evasion & Anti-Analysis: Phishing kits commonly disable context menus to hinder manual inspection by non-technical victims."
                })

    except requests.exceptions.Timeout:
        result["error_message"] = "Connection timed out during page inspection (Site may be offline or blocking scanners)."
    except requests.exceptions.SSLError:
        result["error_message"] = "SSL Certificate validation failed (Invalid or self-signed certificate)."
        result["indicators"].append({
            "id": "RULE_INVALID_SSL",
            "category": "Protocol Security",
            "title": "Invalid or Untrusted SSL/TLS Certificate",
            "severity": "high",
            "points": 25,
            "suspicious_part": "SSL Handshake Failed",
            "explanation": "The server presented an untrusted, self-signed, or expired SSL certificate.",
            "technical_detail": "TLS handshake error: untrusted certificate authority or hostname mismatch, common when phishing domains reuse generic self-signed certificates."
        })
    except requests.exceptions.ConnectionError:
        result["error_message"] = "Could not establish connection to the remote host (Host is unreachable or offline)."
    except Exception as e:
        result["error_message"] = f"Inspection failed: {str(e)}"

    return result
