"""
Database of commonly impersonated brands, high-risk TLDs, suspicious keywords,
and phonetic/homoglyph/typosquatting distance algorithms.
"""

import re

# High-profile brands frequently targeted by login phishing campaigns
TARGET_BRANDS = {
    "google": {
        "name": "Google",
        "official_domains": ["google.com", "accounts.google.com", "gmail.com", "google.co.in", "google.co.uk"],
        "keywords": ["google", "gmail", "googledrive", "gsuite"]
    },
    "paypal": {
        "name": "PayPal",
        "official_domains": ["paypal.com", "paypal-community.com"],
        "keywords": ["paypal", "pay-pal"]
    },
    "microsoft": {
        "name": "Microsoft",
        "official_domains": ["microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com", "login.microsoftonline.com"],
        "keywords": ["microsoft", "office365", "outlook", "onedrive", "sharepoint", "msft"]
    },
    "apple": {
        "name": "Apple",
        "official_domains": ["apple.com", "icloud.com", "appleid.apple.com"],
        "keywords": ["apple", "icloud", "appleid", "itunes"]
    },
    "amazon": {
        "name": "Amazon",
        "official_domains": ["amazon.com", "amazon.co.uk", "amazon.in", "amazon.de"],
        "keywords": ["amazon", "primevideo", "aws"]
    },
    "facebook": {
        "name": "Facebook / Meta",
        "official_domains": ["facebook.com", "meta.com", "fb.com", "messenger.com"],
        "keywords": ["facebook", "meta", "fb-login"]
    },
    "instagram": {
        "name": "Instagram",
        "official_domains": ["instagram.com"],
        "keywords": ["instagram", "ig-login"]
    },
    "netflix": {
        "name": "Netflix",
        "official_domains": ["netflix.com"],
        "keywords": ["netflix", "nflx"]
    },
    "chase": {
        "name": "Chase Bank",
        "official_domains": ["chase.com"],
        "keywords": ["chase", "chasebank"]
    },
    "wellsfargo": {
        "name": "Wells Fargo",
        "official_domains": ["wellsfargo.com"],
        "keywords": ["wellsfargo", "wells-fargo"]
    },
    "bankofamerica": {
        "name": "Bank of America",
        "official_domains": ["bankofamerica.com", "bofa.com"],
        "keywords": ["bankofamerica", "bofa", "boa-login"]
    },
    "binance": {
        "name": "Binance",
        "official_domains": ["binance.com"],
        "keywords": ["binance", "bnb"]
    },
    "coinbase": {
        "name": "Coinbase",
        "official_domains": ["coinbase.com"],
        "keywords": ["coinbase"]
    },
    "github": {
        "name": "GitHub",
        "official_domains": ["github.com"],
        "keywords": ["github"]
    },
    "twitter": {
        "name": "Twitter / X",
        "official_domains": ["twitter.com", "x.com"],
        "keywords": ["twitter", "x-login"]
    },
    "steam": {
        "name": "Steam",
        "official_domains": ["steampowered.com", "steamcommunity.com"],
        "keywords": ["steampowered", "steamcommunity", "steamlogin"]
    },
    "dropbox": {
        "name": "Dropbox",
        "official_domains": ["dropbox.com"],
        "keywords": ["dropbox"]
    },
    "yahoo": {
        "name": "Yahoo",
        "official_domains": ["yahoo.com", "login.yahoo.com"],
        "keywords": ["yahoo", "yahoomail"]
    },
    "linkedin": {
        "name": "LinkedIn",
        "official_domains": ["linkedin.com"],
        "keywords": ["linkedin"]
    }
}

# Top-level domains historically abused due to low-cost or anonymous registration
SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "work", "buzz", "icu", "cam", "tk", "ml", "ga", 
    "cf", "gq", "online", "site", "website", "rest", "fit", "link", "support", 
    "center", "security", "vip", "gdn", "country", "stream", "bid", "loan",
    "cfd", "monster", "sbs", "quest", "click"
}

# Keywords indicative of authentication or sensitive account actions
SUSPICIOUS_KEYWORDS = {
    "login", "signin", "sign-in", "log-in", "verify", "verification", "secure", 
    "security", "account", "update", "auth", "banking", "password", "credential", 
    "recover", "portal", "support", "confirm", "billing", "wallet", "session", 
    "authorize", "unlock", "validate", "reauth", "dispute", "refund", "kyc"
}

# Homoglyph character substitutions commonly used to deceive human eye
HOMOGLYPH_MAP = {
    '0': 'o',
    '1': 'l',
    '3': 'e',
    '4': 'a',
    '5': 's',
    '7': 't',
    '8': 'b',
    'vv': 'w',
    'cl': 'd',
    'rn': 'm',
}

def normalize_homoglyphs(text: str) -> str:
    """Replaces common visually similar numbers and character pairs with canonical letters."""
    norm = text.lower()
    for sub, target in HOMOGLYPH_MAP.items():
        norm = norm.replace(sub, target)
    return norm

def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes the classic Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]

def string_similarity(s1: str, s2: str) -> float:
    """Calculates ratio (0.0 to 1.0) of similarity based on Levenshtein distance."""
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0
    dist = levenshtein_distance(s1.lower(), s2.lower())
    return (max_len - dist) / max_len
