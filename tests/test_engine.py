import unittest
from unittest.mock import patch

from ipintel.config import Settings
from ipintel.engine import Analyzer


class EngineTests(unittest.TestCase):
    def test_private_ip_skips_remote_sources(self) -> None:
        with patch("ipintel.engine.reverse_dns", return_value={"status": "not_found", "hostname": None}):
            report = Analyzer(Settings()).analyze("10.0.0.1")
        self.assertEqual(report["rdap"]["status"], "skipped")
        self.assertEqual(report["risk"]["confidence"], "none")
        self.assertTrue(report["classification"]["is_bogon"])

    def test_optional_providers_are_not_configured_without_keys(self) -> None:
        with patch("ipintel.engine.reverse_dns", return_value={"status": "not_found", "hostname": None}):
            report = Analyzer(Settings()).analyze("8.8.8.8", use_keyless=False)
        self.assertEqual(set(report["providers"]), {"abuseipdb", "virustotal", "shodan", "greynoise"})
        self.assertTrue(all(item["status"] == "not_configured" for item in report["providers"].values()))


if __name__ == "__main__":
    unittest.main()


