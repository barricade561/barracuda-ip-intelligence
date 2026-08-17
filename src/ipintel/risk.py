"""Transparent risk score aggregation."""

from __future__ import annotations

from typing import Any


PROVIDER_WEIGHTS = {
    "abuseipdb": 0.35,
    "virustotal": 0.35,
    "shodan": 0.15,
    "greynoise": 0.15,
}


def calculate_risk(provider_results: dict[str, dict[str, Any]]) -> dict[str, Any]:
    evidence: list[dict[str, Any]] = []
    weighted_sum = 0.0
    active_weight = 0.0
    for name, result in provider_results.items():
        if result.get("status") != "ok" or "score" not in result:
            continue
        score = max(0.0, min(100.0, float(result["score"])))
        weight = PROVIDER_WEIGHTS.get(name, 0.1)
        weighted_sum += score * weight
        active_weight += weight
        evidence.append({"provider": name, "score": round(score), "weight": weight})

    final_score = round(weighted_sum / active_weight) if active_weight else 0
    if final_score >= 75:
        level = "critical"
    elif final_score >= 50:
        level = "high"
    elif final_score >= 25:
        level = "medium"
    else:
        level = "low"
    return {
        "score": final_score,
        "level": level,
        "evidence": evidence,
        "provider_count": len(evidence),
        "confidence": "none" if not evidence else ("limited" if len(evidence) == 1 else "corroborated"),
        "notice": "A low score with no provider evidence means unknown, not verified clean."
        if not evidence
        else "Risk is a weighted indicator and must be reviewed with the source evidence.",
    }


