import unittest

from modules.vuln_scanner import _extract_cvss


class VulnerabilityLookupTests(unittest.TestCase):
    def test_extract_cvss_v31(self):
        cve = {
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "version": "3.1",
                            "baseSeverity": "HIGH",
                            "baseScore": 8.1,
                        }
                    }
                ]
            }
        }
        result = _extract_cvss(cve)
        self.assertEqual(result["version"], "3.1")
        self.assertEqual(result["severity"], "HIGH")
        self.assertEqual(result["score"], 8.1)

    def test_missing_cvss(self):
        result = _extract_cvss({})
        self.assertEqual(result["score"], "N/A")


if __name__ == "__main__":
    unittest.main()
