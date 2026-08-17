"""Public, keyless intelligence sources."""

from __future__ import annotations

from typing import Any

from .http import get_json


def _entity_roles(entities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for entity in entities:
        vcard = entity.get("vcardArray") or []
        contact: dict[str, Any] = {"handle": entity.get("handle"), "roles": entity.get("roles", [])}
        if len(vcard) == 2 and isinstance(vcard[1], list):
            for item in vcard[1]:
                if isinstance(item, list) and len(item) >= 4 and item[0] in {"fn", "email"}:
                    contact[item[0]] = item[3]
        result.append(contact)
    return result


def fetch_rdap(ip: str, timeout: float = 10.0) -> dict[str, Any]:
    data = get_json(f"https://rdap.org/ip/{ip}", timeout=timeout)
    events = {
        event.get("eventAction"): event.get("eventDate")
        for event in data.get("events", [])
        if isinstance(event, dict)
    }
    return {
        "status": "ok",
        "handle": data.get("handle"),
        "name": data.get("name"),
        "type": data.get("type"),
        "country": data.get("country"),
        "start_address": data.get("startAddress"),
        "end_address": data.get("endAddress"),
        "ip_version": data.get("ipVersion"),
        "port43": data.get("port43"),
        "events": events,
        "contacts": _entity_roles(data.get("entities", [])),
        "source": "rdap.org bootstrap service",
    }


def fetch_network(ip: str, timeout: float = 10.0) -> dict[str, Any]:
    response = get_json(
        "https://stat.ripe.net/data/prefix-overview/data.json",
        params={"resource": ip},
        timeout=timeout,
    )
    data = response.get("data", {})
    asns = data.get("asns") or []
    first_asn = asns[0] if asns else None
    if isinstance(first_asn, dict):
        asn = first_asn.get("asn")
        holder = first_asn.get("holder")
        asn_numbers = [item.get("asn") for item in asns if isinstance(item, dict) and item.get("asn")]
    else:
        asn = first_asn
        holder = data.get("holder")
        asn_numbers = asns
    block = data.get("block") or {}
    block_description = str(block.get("desc") or "")
    rir = block_description.removeprefix("Administered by ") or None
    return {
        "status": "ok",
        "asn": asn,
        "asns": asn_numbers,
        "prefix": data.get("resource") or data.get("prefix"),
        "holder": holder,
        "rir": rir,
        "allocation_block": block.get("resource"),
        "announced": data.get("announced"),
        "source": "RIPEstat",
    }


def fetch_geolocation(ip: str, timeout: float = 10.0) -> dict[str, Any]:
    data = get_json(f"https://ipwho.is/{ip}", timeout=timeout)
    if not data.get("success", True):
        raise RuntimeError(str(data.get("message", "Geolocation lookup failed")))
    connection = data.get("connection") or {}
    security = data.get("security") or {}
    timezone = data.get("timezone") or {}
    return {
        "status": "ok",
        "country": data.get("country"),
        "country_code": data.get("country_code"),
        "region": data.get("region"),
        "city": data.get("city"),
        "latitude": data.get("latitude"),
        "longitude": data.get("longitude"),
        "timezone": timezone.get("id"),
        "asn": connection.get("asn"),
        "isp": connection.get("isp"),
        "domain": connection.get("domain"),
        "proxy": security.get("proxy"),
        "vpn": security.get("vpn"),
        "tor": security.get("tor"),
        "hosting": security.get("hosting"),
        "source": "ipwho.is",
        "accuracy_notice": "IP geolocation is approximate and is not a physical device location.",
    }

