from __future__ import annotations

from typing import Any

from ..http import get_json
from .base import Provider


class GreyNoiseProvider(Provider):
    name = "greynoise"
    weight = 0.15

    def lookup(self, ip: str) -> dict[str, Any]:
        data = get_json(
            f"https://api.greynoise.io/v3/community/{ip}",
            headers={"key": self.api_key},
            timeout=self.timeout,
        )
        classification = str(data.get("classification") or "unknown").lower()
        score = {"malicious": 100, "suspicious": 60, "benign": 0}.get(classification, 10 if data.get("noise") else 0)
        return {
            "status": "ok",
            "provider": self.name,
            "score": score,
            "classification": classification,
            "noise": data.get("noise"),
            "riot": data.get("riot"),
            "name": data.get("name"),
            "link": data.get("link"),
            "last_seen": data.get("last_seen"),
            "message": data.get("message"),
        }


