import ipaddress
import unittest

from ipintel.core import classify_ip, parse_ip


class CoreTests(unittest.TestCase):
    def test_public_ipv4(self) -> None:
        result = classify_ip(parse_ip("8.8.8.8"))
        self.assertEqual(result["version"], 4)
        self.assertTrue(result["is_global"])
        self.assertFalse(result["is_bogon"])

    def test_private_ipv4_is_bogon(self) -> None:
        result = classify_ip(parse_ip("192.168.1.10"))
        self.assertTrue(result["is_private"])
        self.assertTrue(result["is_bogon"])

    def test_ipv6_normalization(self) -> None:
        address = parse_ip("2001:4860:4860::8888")
        self.assertIsInstance(address, ipaddress.IPv6Address)
        self.assertEqual(address.compressed, "2001:4860:4860::8888")

    def test_invalid_ip(self) -> None:
        with self.assertRaisesRegex(ValueError, "Invalid IP address"):
            parse_ip("not-an-ip")


if __name__ == "__main__":
    unittest.main()


