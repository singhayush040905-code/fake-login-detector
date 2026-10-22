# Fake Login Page Awareness Detector
### Third-Year Cybersecurity Mini-Project & Viva Demonstration System

---

## 🛡️ Project Overview

**Fake Login Page Awareness Detector** is a cybersecurity tool developed in Python and Flask designed to help everyday internet users identify potentially fake, deceptive, or phishing login pages **before** entering their credentials.

Unlike traditional antivirus tools that return a simple "Safe" or "Blocked" binary output without explanation, this application provides an **explainable, educational breakdown**:
1. **Visual Domain Decomposition:** Highlights individual URL components (protocol, subdomains, registered domain, TLD, path).
2. **Transparent Scoring System:** Calculates a risk score from **0 to 100** based on rule-based heuristic weights.
3. **Deep Page Inspection:** Examines permitted HTML DOM structure for login forms, password inputs, cross-domain form actions, and protocol downgrades.
4. **Actionable Remediation Advice:** Offers clear recommendations so users understand how to verify official portals.
5. **Offline Viva Demonstration Targets:** Built-in mock legitimate and phishing pages allow students to demonstrate all features during a viva or evaluation without requiring live internet access or external malicious sites.

---

## ⚙️ Architecture & Dataflow

```
                    +------------------------------------+
                    |        User Enters Web URL         |
                    +------------------------------------+
                                      |
                                      v
                    +------------------------------------+
                    |       URL Tokenizer & Parser       |
                    |  (Protocol, Subdomain, Domain, TLD)|
                    +------------------------------------+
                                      |
                 +--------------------+--------------------+
                 |                                         |
                 v                                         v
   +---------------------------+             +---------------------------+
   |   URL Heuristic Rules     |             |   Live DOM Page Inspector |
   | - Brand Typosquatting     |             | - HTTP Redirect Chain     |
   | - Levenshtein Distance    |             | - Form Password Inputs    |
   | - Subdomain Hijacking     |             | - Form Action Destinations|
   | - Punycode / IDN Attacks  |             | - Page Title vs Domain    |
   | - IP Address as Hostname  |             | - Anti-Analysis Scripts   |
   | - Shannon Entropy > 3.3   |             +---------------------------+
   +---------------------------+                           |
                 |                                         |
                 +--------------------+--------------------+
                                      |
                                      v
                    +------------------------------------+
                    |   Scoring Aggregator (0 - 100)     |
                    |    0-29: Low | 30-59: Med | 60+: Hi|
                    +------------------------------------+
                                      |
                                      v
                    +------------------------------------+
                    | SQLite Persistence & Visual Report |
                    | (Gauge Meter, Badges, Advice)     |
                    +------------------------------------+
```

---

## 🧮 Rule-Based Risk Scoring Matrix

| Rule ID | Indicator / Heuristic Checked | Severity | Points | Technical Rationale |
|---|---|---|---|---|
| `RULE_TYPOSQUATTING` | Lookalike Brand Typosquatting (e.g. `paypa1.com`) | High | +30 | Levenshtein edit distance & homoglyph substitution matching known targets |
| `RULE_BRAND_EMBEDDED` | Brand Keyword Embedded (e.g. `paypal-security.com`) | High | +30 | Unauthorized brand string combined with deceptive action keywords |
| `RULE_SUBDOMAIN_HIJACK` | Deceptive Subdomain (e.g. `paypal.com.attacker.com`) | High | +25 | User-interface deception pushing actual apex domain out of focus |
| `RULE_EXTERNAL_FORM_ACTION` | Form Submits Password to External Host | High | +25 | Cross-domain credential exfiltration pipeline |
| `RULE_CREDENTIAL_EXFILTRATION` | Form Action Points to Webhook / API Drop | High | +30 | Known exfiltration drops (Telegram, Discord, Formspree, etc.) |
| `RULE_IP_HOST` | Host is a Direct IP Address (e.g. `http://192.168.1.1`) | High | +25 | Legitimate consumer services never demand logins on raw IP hosts |
| `RULE_MISSING_HTTPS` | Missing HTTPS / Plaintext HTTP | High/Med | +20 | Exposes plaintext credentials to on-path interception (CWE-319) |
| `RULE_AT_SYMBOL` | Deceptive `@` Credential Delimiter | High | +20 | RFC 3986 trick where browsers connect only to host after `@` |
| `RULE_PUNYCODE` | IDN Homograph Attack (`xn--` prefix) | High | +25 | Cyrillic / Greek Unicode lookalikes spoofing Latin alphabets |
| `RULE_SUSPICIOUS_REDIRECT` | Cross-Domain Redirection | High | +20 | Cloaking hop from clean initial URL to malicious host |
| `RULE_HIGH_RISK_TLD` | Disposable / High-Abuse TLD (e.g. `.xyz`, `.top`) | Med | +15 | Cheap registrar domains frequently used in disposable phishing kits |
| `RULE_HIGH_ENTROPY` | Shannon Entropy > 3.3 in Domain Name | Med | +15 | Algorithmic randomness typical of Domain Generation Algorithms (DGA) |
| `RULE_EXCESSIVE_SUBDOMAINS`| Deep Subdomain Nesting (> 2 levels) | Med | +15 | Visual address-bar overflow obfuscation on mobile devices |
| `RULE_EXCESSIVE_HYPHENS` | Abnormal Hyphen Count (≥ 2 hyphens) | Med | +10 | Delimiter padding to bypass simple keyword blocklists |

### Risk Level Thresholds:
- **0 – 29: Low Risk (Safe / Low Threat)** — No suspicious patterns detected.
- **30 – 59: Medium Risk (Suspicious - Proceed with Caution)** — Multiple structural or protocol warnings present.
- **60 – 100: High Risk (Dangerous - Likely Fake Login / Phishing)** — Strong indicators of credential harvesting or brand spoofing.

---

## 📂 Project Structure

```
pro/
├── app.py                      # Flask server, routing, REST API endpoints
├── detector/
│   ├── __init__.py             # Module package exports
│   ├── analyzer.py             # Master orchestrator combining URL & DOM inspection & scoring
│   ├── url_rules.py            # Heuristic checks (typosquatting, homoglyphs, entropy, TLDs)
│   ├── page_inspector.py       # Live DOM parser & redirect checker (BeautifulSoup & Requests)
│   ├── brands.py               # Database of target brands, homoglyphs, and Levenshtein algorithm
│   └── database.py             # SQLite database layer for audit logs and scan statistics
├── templates/
│   ├── index.html              # Main dashboard: URL scanner, quick demo buttons, risk meter
│   ├── history.html            # Scan audit log, search/filter, interactive modal inspector
│   ├── about.html              # Project documentation, architecture, and Viva preparation guide
│   └── demo/
│       ├── legitimate_demo.html# Safe mock login page for demonstration
│       └── phishing_demo.html  # Suspicious mock login page for demonstration
├── static/
│   ├── css/
│   │   └── style.css           # Modern cybersecurity dark theme UI
│   └── js/
│       └── main.js             # Client-side input validation, animated gauge, dynamic rendering
├── test_detector.py            # Automated unit test suite (9 test cases covering all rules)
├── requirements.txt            # Project dependencies (Flask, requests, beautifulsoup4)
└── README.md                   # Complete academic documentation and viva reference
```

---

## 🚀 How to Run the Project Locally

### 1. Prerequisites
- Python 3.9, 3.10, 3.11, or 3.12 installed on your computer.

### 2. Install Required Dependencies
Open your terminal / command prompt in this project folder and run:
```bash
python -m pip install -r requirements.txt
```

### 3. Run the Unit Test Suite
To verify that all algorithms, homoglyphs, and rules are functioning correctly:
```bash
python test_detector.py
```
*(You should see `Ran 9 tests ... OK`)*

### 4. Start the Application
Run the Flask server:
```bash
python app.py
```

### 5. Access the Web Dashboard
Open your web browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 🧪 Demonstration Test Cases (Perfect for Viva Presentations)

When presenting this project to your professor or viva examiner, you can test both online and offline cases:

1. **Legitimate Brand Login (Score: 0 / Low Risk)**
   - Click preset button: **🟢 Legitimate Google Login** (`https://accounts.google.com/signin`)
   - *Result:* Shows 0 points, official verified domain, clean bill of health.

2. **Typosquatting & Homoglyph Attack (Score: 80 / High Risk)**
   - Click preset button: **🔴 Typosquat Brand Lookalike** (`http://paypa1-security-verify.xyz/login`)
   - *Result:* Flags homoglyph `1` for `l`, unauthorized brand impersonation, missing HTTPS, high-abuse `.xyz` TLD.

3. **Subdomain Hijack Deception (Score: 65 / High Risk)**
   - Click preset button: **🔴 Subdomain Hijack Attack** (`http://paypal.com.account-update.xyz/login`)
   - *Result:* Identifies that `paypal.com` is disguised as a subdomain while the actual domain is `account-update.xyz`.

4. **Direct IP Address Host (Score: 45 / Medium Risk)**
   - Click preset button: **⚠️ Direct IP Address Host** (`http://192.168.1.105/bank/signin`)
   - *Result:* Flags raw IP usage and missing encryption.

5. **Local Phishing Simulation (Works 100% Offline!)**
   - Click preset button: **🧪 Local Mock Phishing Demo** (`http://127.0.0.1:5000/demo/phishing-login`)
   - *Result:* Deep DOM inspection flags `<form action="http://fake-credential-stealer.xyz/harvester.php">`, missing HTTPS, and page title spoofing.

---

## 🎓 Viva Oral Exam Preparation (Top Questions & Model Answers)

### Q1. Why did you use a rule-based engine instead of Machine Learning?
**Answer:** Machine Learning models (like SVM or Random Forests) operate as black boxes, making it difficult to explain *why* a particular URL was flagged. For security education and viva demonstration, **explainability is crucial**. A rule-based approach provides deterministic, auditable evidence for each penalty point (e.g., Levenshtein distance, missing HTTPS, external form action) and allows users to learn specific signs of credential theft.

### Q2. How does your typosquatting algorithm work?
**Answer:** We implement two complementary layers in `detector/brands.py`:
1. **Homoglyph Normalization:** We map visual substitutions (such as `0` to `o`, `1` to `l`, `rn` to `m`, `vv` to `w`) into canonical characters.
2. **Levenshtein Distance:** A dynamic programming matrix calculates the minimum edit distance (insertions, deletions, substitutions). If a token closely matches an official brand name with similarity ≥ 0.75 outside the verified official domain whitelist, it triggers a high-severity alert.

### Q3. Does an active HTTPS padlock mean a website is legitimate?
**Answer:** No. An HTTPS certificate only guarantees that communications between client and server are encrypted against network eavesdropping. Threat actors easily register free SSL certificates (via Let's Encrypt or Cloudflare) for malicious domains. Therefore, while missing HTTPS is a definite warning sign for a login page, the presence of HTTPS alone does not prove the website is safe.

### Q4. How does the live page inspector detect credential exfiltration?
**Answer:** Using `requests` and `BeautifulSoup`, the backend inspects the webpage DOM to locate `<form>` elements containing `<input type="password">`. It then resolves the form's `action` attribute:
- If the action posts credentials to a third-party domain different from the host, it flags **Cross-Domain Credential Exfiltration**.
- If the action is unencrypted `http://`, it flags **CWE-319 (Cleartext Transmission of Sensitive Information)**.
- If the action is empty, `#`, or `javascript:void(0)`, it flags **In-Memory Asynchronous Script Capture**.

### Q5. What is Shannon Entropy and why is it useful in cybersecurity?
**Answer:** Shannon Entropy measures the degree of unpredictability or randomness in a string of text. Standard English words typically range between 2.0 and 2.8 bits of entropy. Attackers deploying Domain Generation Algorithms (DGA) generate random looking domains (such as `x8k29a0qzb.info`) with entropy above 3.3. Our scanner flags high-entropy domains as probable automated disposable phishing infrastructure.

---

## 🔒 Ethical & Security Notice

This application is created **strictly for academic, educational, and defensive cybersecurity awareness purposes**. It does not collect, record, or store passwords. All local demonstration endpoints use simulated benign forms.
