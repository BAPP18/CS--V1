import unittest

from modules.phishing_detector import analyze_url


class PhishingDetectorTests(unittest.TestCase):
    def test_exact_shortener_domain_is_detected(self):
        result = analyze_url("https://bit.ly/example")
        self.assertTrue(any("shortener" in reason.lower() for reason in result["reasons"]))

    def test_shortener_substring_does_not_trigger(self):
        result = analyze_url("https://notbit.ly.example.com/path")
        self.assertFalse(any("shortener" in reason.lower() for reason in result["reasons"]))

    def test_ip_host_is_flagged(self):
        result = analyze_url("http://192.0.2.10/login")
        self.assertGreaterEqual(result["score"], 3)

    def test_result_is_structured(self):
        result = analyze_url("https://example.com")
        self.assertIn("score", result)
        self.assertIn("verdict", result)
        self.assertIn("reasons", result)


if __name__ == "__main__":
    unittest.main()
