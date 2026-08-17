"""Dependency-free IP validation, classification, and reverse DNS."""

from __future__ import annotations

import ipaddress
import socket
from typing import Any


def parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {value!r}") from exc


def classify_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> dict[str, Any]:
    """Return explicit flags; bogon means not globally routable here."""
    return {
        "address": address.compressed,
        "version": address.version,
        "type": f"IPv{address.version}",
        "is_global": address.is_global,
        "is_private": address.is_private,
        "is_loopback": address.is_loopback,
        "is_link_local": address.is_link_local,
        "is_multicast": address.is_multicast,
        "is_reserved": address.is_reserved,
        "is_unspecified": address.is_unspecified,
        "is_bogon": not address.is_global,
    }


def reverse_dns(address: str) -> dict[str, Any]:
    try:
        hostname, aliases, addresses = socket.gethostbyaddr(address)
        return {
            "status": "ok",
            "hostname": hostname,
            "aliases": aliases,
            "addresses": addresses,
        }
    except (socket.herror, socket.gaierror, OSError) as exc:
        return {"status": "not_found", "hostname": None, "error": str(exc)}


