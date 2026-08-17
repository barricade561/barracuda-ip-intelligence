from __future__ import annotations

from typing import Any

from ..http import get_json
from .base import Provider


class AbuseIPDBProvider(Provider):
    name = "abuseipdb"
    weight = 0.35

    def lookup(self, ip: str) -> dict[str, Any]:
        data = get_json(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            headers={"Key": self.api_key},
            timeout=self.timeout,
        ).get("data", {})
        score = max(0, min(100, int(data.get("abuseConfidenceScore") or 0)))
        return {
            "status": "ok",
            "provider": self.name,
            "score": score,
            "abuse_confidence_score": score,
            "total_reports": data.get("totalReports"),
            "last_reported_at": data.get("lastReportedAt"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "country_code": data.get("countryCode"),
            "is_tor": data.get("isTor"),
        }


