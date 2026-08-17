from __future__ import annotations

from typing import Any

from ..http import get_json
from .base import Provider


class VirusTotalProvider(Provider):
    name = "virustotal"
    weight = 0.35

    def lookup(self, ip: str) -> dict[str, Any]:
        response = get_json(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": self.api_key},
            timeout=self.timeout,
        )
        attributes = (response.get("data") or {}).get("attributes") or {}
        stats = attributes.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        harmless = int(stats.get("harmless") or 0)
        undetected = int(stats.get("undetected") or 0)
        total = malicious + suspicious + harmless + undetected
        score = round(100 * (malicious + suspicious * 0.5) / total) if total else 0
        return {
            "status": "ok",
            "provider": self.name,
            "score": max(0, min(100, score)),
            "analysis_stats": stats,
            "reputation": attributes.get("reputation"),
            "network": attributes.get("network"),
            "as_owner": attributes.get("as_owner"),
            "country": attributes.get("country"),
            "tags": attributes.get("tags", []),
        }


