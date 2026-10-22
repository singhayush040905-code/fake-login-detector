"""
Unit Test Suite for Fake Login Page Awareness Detector.
Validates URL heuristics, brand lookalike algorithms, Shannon entropy,
database persistence, and scoring logic.
"""

import unittest
from detector.url_rules import parse_and_tokenize_url, analyze_url_heuristics, calculate_entropy
from detector.brands import levenshtein_distance, string_similarity, normalize_homoglyphs
from detector.analyzer import analyze_url_and_page
from detector.database import init_db, save_scan, get_recent_scans, clear_history, get_scan_stats

class TestDetectorSuite(unittest.TestCase):

    def setUp(self):
        """Prepare database before each test run."""
        init_db()
        clear_history()

    def test_levenshtein_distance(self):
        """Test edit distance accuracy."""
        self.assertEqual(levenshtein_distance("paypal", "paypal"), 0)
        self.assertEqual(levenshtein_distance("paypal", "paypa1"), 1)
        self.assertEqual(levenshtein_distance("google", "g00gle"), 2)
        self.assertAlmostEqual(string_similarity("paypal", "paypal"), 1.0)

    def test_homoglyph_normalization(self):
        """Test replacement of deceptive numbers/letters."""
        self.assertEqual(normalize_homoglyphs("paypa1"), "paypal")
        self.assertEqual(normalize_homoglyphs("g00gle"), "google")
        self.assertEqual(normalize_homoglyphs("rnicrosoft"), "microsoft")

    def test_shannon_entropy(self):
        """Test randomness calculation."""
        low_entropy = calculate_entropy("google")
        high_entropy = calculate_entropy("a9x2q8km1p0z")
        self.assertGreater(high_entropy, low_entropy)
        self.assertGreater(high_entropy, 3.0)

    def test_legitimate_brand_domain(self):
        """Legitimate official brand domains must NOT be flagged as typosquats."""
        tokens = parse_and_tokenize_url("https://accounts.google.com/signin")
        indicators = analyze_url_heuristics(tokens)
        
        # Verify no typosquatting or embedded brand indicators
        brand_flags = [ind for ind in indicators if "TYPOSQUATTING" in ind["id"] or "BRAND_EMBEDDED" in ind["id"]]
        self.assertEqual(len(brand_flags), 0, "Official Google domain incorrectly flagged!")

    def test_typosquatting_detection(self):
        """Detect typosquat lookalikes like paypa1-security.xyz."""
        report = analyze_url_and_page("http://paypa1-security-verify.xyz/login", perform_page_inspection=False)
        self.assertGreaterEqual(report["risk_score"], 60)
        self.assertEqual(report["risk_level"], "high")

        flag_ids = [ind["id"] for ind in report["indicators"]]
        self.assertTrue(
            "RULE_TYPOSQUATTING" in flag_ids or "RULE_BRAND_EMBEDDED" in flag_ids,
            "Failed to flag brand typosquatting"
        )
        self.assertIn("RULE_MISSING_HTTPS", flag_ids)
        self.assertIn("RULE_HIGH_RISK_TLD", flag_ids)

    def test_subdomain_hijack_detection(self):
        """Detect deceptive subdomain brand positioning (e.g. paypal.com.attacker.com)."""
        report = analyze_url_and_page("http://paypal.com.account-update.xyz/login", perform_page_inspection=False)
        self.assertEqual(report["risk_level"], "high")

        flag_ids = [ind["id"] for ind in report["indicators"]]
        self.assertIn("RULE_SUBDOMAIN_HIJACK", flag_ids)

    def test_ip_address_host(self):
        """Detect direct IP address usage."""
        report = analyze_url_and_page("http://192.168.1.100/login", perform_page_inspection=False)
        flag_ids = [ind["id"] for ind in report["indicators"]]
        self.assertIn("RULE_IP_HOST", flag_ids)
        self.assertIn("RULE_MISSING_HTTPS", flag_ids)
        self.assertGreaterEqual(report["risk_score"], 45)

    def test_at_symbol_credential_lure(self):
        """Detect @ delimiter URL obfuscation."""
        report = analyze_url_and_page("http://google.com@attacker-portal.net/login", perform_page_inspection=False)
        flag_ids = [ind["id"] for ind in report["indicators"]]
        self.assertIn("RULE_AT_SYMBOL", flag_ids)

    def test_database_lifecycle(self):
        """Test SQLite persistence, retrieval, and statistics."""
        report = analyze_url_and_page("http://test-phish-domain.xyz/login", perform_page_inspection=False)
        scan_id = save_scan(report)
        self.assertIsNotNone(scan_id)

        history = get_recent_scans()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["url"], "http://test-phish-domain.xyz/login")

        stats = get_scan_stats()
        self.assertEqual(stats["total_scans"], 1)

        clear_history()
        self.assertEqual(len(get_recent_scans()), 0)

if __name__ == "__main__":
    unittest.main()
