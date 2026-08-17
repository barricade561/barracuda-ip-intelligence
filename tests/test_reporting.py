import csv
import json
import tempfile
import unittest
from pathlib import Path

from ipintel.reporting import flatten, write_csv, write_json


class ReportingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = {"target": "8.8.8.8", "risk": {"score": 10}, "tags": ["dns"]}

    def test_flatten(self) -> None:
        row = flatten(self.report)
        self.assertEqual(row["risk.score"], 10)
        self.assertEqual(row["tags"], '["dns"]')

    def test_writers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            json_path = write_json(self.report, Path(directory) / "report.json")
            csv_path = write_csv(self.report, Path(directory) / "report.csv")
            self.assertEqual(json.loads(json_path.read_text(encoding="utf-8"))["target"], "8.8.8.8")
            with csv_path.open(encoding="utf-8-sig", newline="") as handle:
                row = next(csv.DictReader(handle))
            self.assertEqual(row["risk.score"], "10")


if __name__ == "__main__":
    unittest.main()


