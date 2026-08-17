"""Analysis orchestration."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable

from .config import Settings
from .core import classify_ip, parse_ip, reverse_dns
from .keyless import fetch_geolocation, fetch_network, fetch_rdap
from .providers import AbuseIPDBProvider, GreyNoiseProvider, ShodanProvider, VirusTotalProvider
from .providers.base import Provider
from .risk import calculate_risk


class Analyzer:
    """Run passive lookups and return a serializable report."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings.from_environment()
        self.providers: dict[str, Provider] = {
            "abuseipdb": AbuseIPDBProvider(self.settings.abuseipdb_api_key, self.settings.timeout),
            "virustotal": VirusTotalProvider(self.settings.virustotal_api_key, self.settings.timeout),
            "shodan": ShodanProvider(self.settings.shodan_api_key, self.settings.timeout),
            "greynoise": GreyNoiseProvider(self.settings.greynoise_api_key, self.settings.timeout),
        }

    @staticmethod
    def _safe_lookup(name: str, lookup: Callable[[], dict[str, Any]]) -> tuple[str, dict[str, Any]]:
        try:
            return name, lookup()
        except Exception as exc:  # remote sources must not abort the whole report
            return name, {"status": "error", "source": name, "error": str(exc)}

    def analyze(
        self,
        value: str,
        *,
        use_keyless: bool = True,
        provider_names: set[str] | None = None,
    ) -> dict[str, Any]:
        address = parse_ip(value)
        ip = address.compressed
        classification = classify_ip(address)
        report: dict[str, Any] = {
            "schema_version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target": ip,
            "classification": classification,
            "reverse_dns": reverse_dns(ip),
            "rdap": {"status": "skipped"},
            "network": {"status": "skipped"},
            "geolocation": {"status": "skipped"},
            "providers": {},
            "warnings": [
                "Use only for lawful, authorized, passive intelligence gathering.",
                "IP geolocation is approximate and is not a physical device location.",
            ],
        }

        if not address.is_global:
            report["warnings"].append("Network lookups were skipped because the address is not globally routable.")
            report["risk"] = calculate_risk({})
            return report

        jobs: dict[str, Callable[[], dict[str, Any]]] = {}
        if use_keyless:
            jobs.update(
                {
                    "rdap": lambda: fetch_rdap(ip, self.settings.timeout),
                    "network": lambda: fetch_network(ip, self.settings.timeout),
                    "geolocation": lambda: fetch_geolocation(ip, self.settings.timeout),
                }
            )

        selected = provider_names if provider_names is not None else set(self.providers)
        for name, provider in self.providers.items():
            if name not in selected:
                continue
            if provider.configured:
                jobs[f"provider:{name}"] = lambda provider=provider: provider.lookup(ip)
            else:
                report["providers"][name] = provider.disabled_result()

        with ThreadPoolExecutor(max_workers=min(8, max(1, len(jobs)))) as executor:
            futures = {executor.submit(self._safe_lookup, name, lookup): name for name, lookup in jobs.items()}
            for future in as_completed(futures):
                name, result = future.result()
                if name.startswith("provider:"):
                    report["providers"][name.split(":", 1)[1]] = result
                else:
                    report[name] = result

        report["risk"] = calculate_risk(report["providers"])
        return report


