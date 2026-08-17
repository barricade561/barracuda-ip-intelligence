import unittest
from unittest.mock import patch

from ipintel.keyless import fetch_network


class KeylessTests(unittest.TestCase):
    @patch("ipintel.keyless.get_json")
    def test_current_ripestat_asn_shape_is_normalized(self, get_json) -> None:
        get_json.return_value = {
            "data": {
                "announced": True,
                "asns": [{"asn": 15169, "holder": "GOOGLE - Google LLC"}],
                "resource": "8.8.8.0/24",
                "block": {"resource": "8.0.0.0/8", "desc": "Administered by ARIN"},
            }
        }
        result = fetch_network("8.8.8.8")
        self.assertEqual(result["asn"], 15169)
        self.assertEqual(result["prefix"], "8.8.8.0/24")
        self.assertEqual(result["rir"], "ARIN")


if __name__ == "__main__":
    unittest.main()


