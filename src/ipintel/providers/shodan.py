from __future__ import annotations

from typing import Any

from ..http import get_json
from .base import Provider


class ShodanProvider(Provider):
    name = "shodan"
    weight = 0.15

    def lookup(self, ip: str) -> dict[str, Any]:
        data = get_json(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": self.api_key},
            timeout=self.timeout,
        )
        vulnerabilities = data.get("vulns") or []
        tags = data.get("tags") or []
        suspicious_tags = {"malware", "botnet", "compromised", "scanner", "tor"}
        matched_tags = sorted(suspicious_tags.intersection(str(tag).lower() for tag in tags))
        score = min(100, len(vulnerabilities) * 12 + len(matched_tags) * 20)
        return {
            "status": "ok",
            "provider": self.name,
            "score": score,
            "organization": data.get("org"),
            "isp": data.get("isp"),
            "asn": data.get("asn"),
            "ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "tags": tags,
            "vulnerabilities": vulnerabilities,
            "last_update": data.get("last_update"),
        }


