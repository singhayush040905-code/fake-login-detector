"""
URL & Domain Analysis Rules Engine.
Evaluates domain spelling, homoglyphs, brand impersonation, subdomain deception,
protocol safety, and structural anomalies.
"""

import math
import re
from urllib.parse import urlparse, unquote
from .brands import (
    TARGET_BRANDS,
    SUSPICIOUS_TLDS,
    SUSPICIOUS_KEYWORDS,
    normalize_homoglyphs,
    string_similarity,
    levenshtein_distance
)

# Multi-part TLD suffixes commonly encountered
MULTI_PART_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk",
    "co.in", "net.in", "org.in", "gen.in", "gov.in",
    "com.au", "net.au", "org.au", "edu.au",
    "co.nz", "co.za", "com.br", "co.jp", "com.sg", "com.mx"
}

def calculate_entropy(text: str) -> float:
    """Calculates the Shannon entropy of a string to detect randomized DGA domains."""
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    text_len = len(text)
    for count in freq.values():
        prob = count / text_len
        entropy -= prob * math.log2(prob)
    return round(entropy, 2)

def extract_domain_parts(raw_host: str) -> dict:
    """
    Splits hostname into subdomain, main domain, and TLD.
    Handles multi-part TLDs (e.g., .co.in, .co.uk) and IP addresses.
    """
    host = raw_host.lower().strip()
    if not host:
        return {"subdomain": "", "domain": "", "tld": "", "is_ip": False}

    # Check for IPv4
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ipv4_pattern, host):
        return {"subdomain": "", "domain": host, "tld": "", "is_ip": True}

    # Check for IPv6
    if ":" in host and not host.startswith("["):
        return {"subdomain": "", "domain": host, "tld": "", "is_ip": True}

    parts = host.split(".")
    if len(parts) == 1:
        return {"subdomain": "", "domain": parts[0], "tld": "", "is_ip": False}

    # Check multi-part TLD
    if len(parts) >= 3:
        possible_multi = f"{parts[-2]}.{parts[-1]}"
        if possible_multi in MULTI_PART_TLDS:
            tld = possible_multi
            domain = parts[-3]
            subdomain = ".".join(parts[:-3])
            return {"subdomain": subdomain, "domain": domain, "tld": tld, "is_ip": False}

    tld = parts[-1]
    domain = parts[-2]
    subdomain = ".".join(parts[:-2])
    return {"subdomain": subdomain, "domain": domain, "tld": tld, "is_ip": False}

def parse_and_tokenize_url(raw_url: str) -> dict:
    """
    Normalizes and tokenizes a user-supplied URL for analysis and UI highlighting.
    """
    url = raw_url.strip()
    has_explicit_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url))
    
    if not has_explicit_scheme:
        # Prepend http:// for parsing purposes if missing
        parsed = urlparse(f"http://{url}")
        detected_scheme = "missing"
    else:
        parsed = urlparse(url)
        detected_scheme = parsed.scheme.lower()

    netloc = parsed.netloc or parsed.path.split("/")[0]
    
    # Check for @ userinfo
    userinfo = ""
    host_port = netloc
    if "@" in netloc:
        userinfo, host_port = netloc.split("@", 1)

    port = None
    hostname = host_port
    if ":" in host_port and not host_port.startswith("["):
        parts = host_port.split(":")
        hostname = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            port = None

    domain_parts = extract_domain_parts(hostname)

    return {
        "raw_url": raw_url,
        "normalized_url": parsed.geturl() if has_explicit_scheme else f"http://{url}",
        "scheme": detected_scheme,
        "userinfo": userinfo,
        "netloc": netloc,
        "hostname": hostname,
        "port": port,
        "subdomain": domain_parts["subdomain"],
        "domain": domain_parts["domain"],
        "tld": domain_parts["tld"],
        "is_ip": domain_parts["is_ip"],
        "path": parsed.path or "/",
        "query": parsed.query,
        "fragment": parsed.fragment,
        "has_explicit_scheme": has_explicit_scheme
    }

def analyze_url_heuristics(tokens: dict) -> list:
    """
    Executes rule-based checks on the tokenized URL components.
    Returns list of indicator dictionaries.
    """
    indicators = []
    hostname = tokens["hostname"]
    domain = tokens["domain"]
    subdomain = tokens["subdomain"]
    tld = tokens["tld"]
    scheme = tokens["scheme"]
    path = tokens["path"]
    full_host = f"{tokens['subdomain']}.{tokens['domain']}.{tokens['tld']}".strip(".")

    # Rule 1: HTTPS Check
    if scheme in ("http", "missing"):
        indicators.append({
            "id": "RULE_MISSING_HTTPS",
            "category": "Protocol Security",
            "title": "Missing HTTPS Encryption",
            "severity": "high" if scheme == "http" else "medium",
            "points": 20,
            "suspicious_part": "http://" if scheme == "http" else "No Protocol Specified",
            "explanation": "This connection does not use HTTPS. Any login credentials entered will travel unencrypted over the network.",
            "technical_detail": "Plaintext HTTP allows Man-in-the-Middle (MitM) attacks, credential eavesdropping, and session hijacking. Legitimate authentication portals mandate TLS (HTTPS)."
        })

    # Rule 2: IP Address as Hostname
    if tokens["is_ip"]:
        indicators.append({
            "id": "RULE_IP_HOST",
            "category": "Domain Analysis",
            "title": "Direct IP Address Used Instead of Domain Name",
            "severity": "high",
            "points": 25,
            "suspicious_part": hostname,
            "explanation": f"The website uses a raw IP address ({hostname}) rather than a legitimate registered domain name.",
            "technical_detail": "Phishing hosts often deploy kits on compromised servers or direct IP addresses to bypass domain registrar takedowns and DNS reputation lists."
        })

    # Rule 3: '@' Symbol in URL
    if tokens["userinfo"] or "@" in tokens["raw_url"]:
        indicators.append({
            "id": "RULE_AT_SYMBOL",
            "category": "URL Structure",
            "title": "Deceptive '@' Credential Delimiter",
            "severity": "high",
            "points": 20,
            "suspicious_part": f"{tokens['userinfo']}@",
            "explanation": "The URL contains an '@' character, which causes browsers to ignore the fake domain in front and connect to the host behind it.",
            "technical_detail": "In RFC 3986, content prior to '@' is treated as user authentication data (userinfo). Attackers use 'https://google.com@attacker.com' to deceive users."
        })

    # Rule 4: Internationalized Domain Name / Punycode Homograph
    if "xn--" in hostname:
        indicators.append({
            "id": "RULE_PUNYCODE",
            "category": "Domain Analysis",
            "title": "Punycode / IDN Homograph Detected",
            "severity": "high",
            "points": 25,
            "suspicious_part": [p for p in hostname.split(".") if "xn--" in p][0] if any("xn--" in p for p in hostname.split(".")) else hostname,
            "explanation": "This domain uses Punycode (xn--) to render non-Latin characters that look virtually identical to legitimate letters.",
            "technical_detail": "IDN Homograph attacks register visually deceptive Unicode glyphs (e.g., Cyrillic 'а' replacing Latin 'a') to spoof official brand names."
        })

    # Rule 5: Brand Impersonation & Typosquatting Analysis
    detected_brand_match = None
    target_match_type = None

    normalized_domain = normalize_homoglyphs(domain)
    clean_domain = re.sub(r"[^a-z0-9]", "", domain.lower())

    for brand_key, brand_info in TARGET_BRANDS.items():
        official_domains = brand_info["official_domains"]
        is_official = any(full_host == off or full_host.endswith(f".{off}") for off in official_domains)
        if is_official:
            # Verified official brand domain! Skip flagging
            continue

        brand_name = brand_info["name"]

        # Check A: Exact brand string or homoglyph-substituted brand embedded in domain
        if (brand_key in domain.lower() or brand_key in normalized_domain) and not is_official:
            is_homoglyph = brand_key in normalized_domain and brand_key not in domain.lower()
            detected_brand_match = brand_name
            target_match_type = "homoglyph_embedded" if is_homoglyph else "embedded"
            
            rule_id = "RULE_TYPOSQUATTING" if is_homoglyph else "RULE_BRAND_EMBEDDED"
            rule_title = f"Homoglyph Brand Impersonation ({brand_name})" if is_homoglyph else f"Suspicious Brand Keyword Impersonation ({brand_name})"
            explanation = (
                f"The domain uses lookalike characters to mimic '{brand_name}' inside '{domain}.{tld}'."
                if is_homoglyph else
                f"The domain embeds the brand name '{brand_name}' inside '{domain}.{tld}', which is not an authorized official domain."
            )
            
            indicators.append({
                "id": rule_id,
                "category": "Domain Analysis",
                "title": rule_title,
                "severity": "high",
                "points": 30,
                "suspicious_part": domain,
                "explanation": explanation,
                "technical_detail": f"Unauthorized domain name crafting targeting '{brand_key}' (homoglyph variant: {is_homoglyph})."
            })
            break

        # Check B: Token-level and whole-domain typosquatting (Levenshtein distance & substitution)
        sub_tokens = re.split(r"[-_.]+", domain.lower())
        token_matched = False
        for tok in sub_tokens:
            tok_norm = normalize_homoglyphs(tok)
            sim = string_similarity(tok, brand_key)
            dist = levenshtein_distance(tok_norm, brand_key)
            if (sim >= 0.75 and sim < 1.0) or (dist == 1 and len(brand_key) >= 4) or (tok_norm == brand_key and tok != brand_key):
                detected_brand_match = brand_name
                token_matched = True
                indicators.append({
                    "id": "RULE_TYPOSQUATTING",
                    "category": "Domain Analysis",
                    "title": f"Lookalike Typosquatting of Brand ({brand_name})",
                    "severity": "high",
                    "points": 30,
                    "suspicious_part": tok,
                    "explanation": f"The domain token '{tok}' appears to be a deliberate visual lookalike or misspelling of '{brand_name}'.",
                    "technical_detail": f"High Levenshtein proximity (edit distance: {dist}) detected against registered brand '{brand_key}' in token '{tok}'."
                })
                break

        if token_matched:
            break

        # Whole domain similarity check
        whole_sim = string_similarity(clean_domain, brand_key)
        whole_dist = levenshtein_distance(normalized_domain, brand_key)
        if (whole_sim >= 0.75 and whole_sim < 1.0) or (whole_dist == 1 and len(brand_key) >= 4):
            detected_brand_match = brand_name
            indicators.append({
                "id": "RULE_TYPOSQUATTING",
                "category": "Domain Analysis",
                "title": f"Lookalike Typosquatting of Brand ({brand_name})",
                "severity": "high",
                "points": 30,
                "suspicious_part": domain,
                "explanation": f"The domain '{domain}' appears to be a deliberate visual lookalike of '{brand_name}'.",
                "technical_detail": f"Whole domain similarity: {round(whole_sim*100)}% with brand '{brand_key}'."
            })
            break

    # Rule 6: Deceptive Subdomain Brand Hijacking (e.g. paypal.com.attacker.com)
    if subdomain and not detected_brand_match:
        for brand_key, brand_info in TARGET_BRANDS.items():
            official_domains = brand_info["official_domains"]
            if any(full_host == off or full_host.endswith(f".{off}") for off in official_domains):
                continue

            for off in official_domains:
                if off in subdomain:
                    indicators.append({
                        "id": "RULE_SUBDOMAIN_HIJACK",
                        "category": "URL Structure",
                        "title": f"Misleading Subdomain Brand Placement ({brand_info['name']})",
                        "severity": "high",
                        "points": 25,
                        "suspicious_part": f"{subdomain}.",
                        "explanation": f"The official brand domain '{off}' is placed in the subdomain to trick users, but the actual domain you are connecting to is '{domain}.{tld}'.",
                        "technical_detail": "Subdomain spoofing: users often inspect only the initial words of a URL. Browsers actually resolve to the base domain, sending credentials to the attacker's server."
                    })
                    break

    # Rule 7: Excessive Subdomains / Subdomain Nesting
    subdomain_parts = [p for p in subdomain.split(".") if p]
    if len(subdomain_parts) >= 3:
        indicators.append({
            "id": "RULE_EXCESSIVE_SUBDOMAINS",
            "category": "URL Structure",
            "title": "Deep Subdomain Nesting (> 2 subdomains)",
            "severity": "medium",
            "points": 15,
            "suspicious_part": subdomain,
            "explanation": f"The URL has {len(subdomain_parts)} nested subdomains. Attackers frequently use long subdomains to push the real domain off the browser screen on mobile devices.",
            "technical_detail": "Obfuscation via subdomain layering: pushes the apex domain outside the visible URL address bar viewport."
        })

    # Rule 8: High-Risk TLD with Sensitive Authentication Keywords
    has_sensitive_keyword = any(kw in (domain.lower() + " " + path.lower() + " " + subdomain.lower()) for kw in SUSPICIOUS_KEYWORDS)
    if tld.lower() in SUSPICIOUS_TLDS:
        pts = 15 if has_sensitive_keyword else 10
        indicators.append({
            "id": "RULE_HIGH_RISK_TLD",
            "category": "Domain Analysis",
            "title": f"High-Risk Top-Level Domain (.{tld})",
            "severity": "medium" if not has_sensitive_keyword else "high",
            "points": pts,
            "suspicious_part": f".{tld}",
            "explanation": f"The top-level domain '.{tld}' is frequently abused in automated phishing campaigns, especially alongside authentication keywords.",
            "technical_detail": f"TLD reputation analysis: registrar pricing and relaxed verification policies make .{tld} popular among threat actors deploying disposable credential harvesting sites."
        })

    # Rule 9: Excessive Hyphens in Domain Name
    hyphen_count = domain.count("-")
    if hyphen_count >= 2:
        indicators.append({
            "id": "RULE_EXCESSIVE_HYPHENS",
            "category": "Domain Analysis",
            "title": f"Abnormal Hyphen Density ({hyphen_count} hyphens)",
            "severity": "medium",
            "points": 10,
            "suspicious_part": domain,
            "explanation": f"The domain contains {hyphen_count} hyphens. Legitimate financial and tech services rarely use multiple hyphens in their primary domain name.",
            "technical_detail": "Delimiters are concatenated by attackers to bypass simple keyword blocklists while remaining recognizable to unsuspecting victims."
        })

    # Rule 10: High Shannon Entropy (Random-looking domain name)
    domain_entropy = calculate_entropy(domain)
    if len(domain) >= 9 and domain_entropy >= 3.3 and not tokens["is_ip"]:
        indicators.append({
            "id": "RULE_HIGH_ENTROPY",
            "category": "Domain Analysis",
            "title": f"High Domain Entropy / Randomized String (Score: {domain_entropy})",
            "severity": "medium",
            "points": 15,
            "suspicious_part": domain,
            "explanation": f"The domain string '{domain}' exhibits high mathematical randomness, resembling an algorithmic or auto-generated phishing domain.",
            "technical_detail": f"Shannon Entropy = {domain_entropy} bits. Entropy above 3.3 in domain names correlates heavily with Domain Generation Algorithms (DGA) and fast-flux botnets."
        })

    # Rule 11: Non-Standard Web Port
    if tokens["port"] and tokens["port"] not in (80, 443, 8000, 5000):
        indicators.append({
            "id": "RULE_NON_STANDARD_PORT",
            "category": "Protocol Security",
            "title": f"Non-Standard Port Specified (:{tokens['port']})",
            "severity": "medium",
            "points": 10,
            "suspicious_part": f":{tokens['port']}",
            "explanation": f"The URL attempts to connect through port {tokens['port']} instead of standard web ports (80 or 443).",
            "technical_detail": "Phishing kits on compromised administrative panels or staging servers frequently run on uncommon ports to bypass standard perimeter security."
        })

    # Rule 12: Abnormally Long URL
    if len(tokens["raw_url"]) > 90:
        indicators.append({
            "id": "RULE_LONG_URL",
            "category": "URL Structure",
            "title": f"Abnormally Long URL ({len(tokens['raw_url'])} characters)",
            "severity": "low",
            "points": 10,
            "suspicious_part": tokens["raw_url"][:40] + "..." + tokens["raw_url"][-20:],
            "explanation": "The URL is unusually long. Phishers frequently append extensive query parameters or directory paths to obscure the destination.",
            "technical_detail": "URL padding is a known social engineering technique to hide the real destination address in truncated browser address bars."
        })

    return indicators
