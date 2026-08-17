"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import sys

from .engine import Analyzer
from .reporting import write_csv, write_json


PROVIDER_NAMES = {"abuseipdb", "virustotal", "shodan", "greynoise"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Passive IP OSINT and threat-intelligence analyzer")
    parser.add_argument("ip", help="IPv4 or IPv6 address")
    parser.add_argument("--no-keyless", action="store_true", help="Disable RDAP, ASN, and geolocation web lookups")
    parser.add_argument(
        "--providers",
        default="all",
        help="Comma-separated optional providers, or 'all' (default)",
    )
    parser.add_argument("--json", dest="json_path", help="Write the full report to a JSON file")
    parser.add_argument("--csv", dest="csv_path", help="Write a flattened report to a CSV file")
    parser.add_argument("--print-json", action="store_true", help="Print the full JSON report")
    return parser


def _provider_selection(value: str) -> set[str]:
    if value.strip().lower() == "all":
        return set(PROVIDER_NAMES)
    selected = {item.strip().lower() for item in value.split(",") if item.strip()}
    unknown = selected - PROVIDER_NAMES
    if unknown:
        raise ValueError(f"Unknown provider(s): {', '.join(sorted(unknown))}")
    return selected


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        providers = _provider_selection(args.providers)
        report = Analyzer().analyze(args.ip, use_keyless=not args.no_keyless, provider_names=providers)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.json_path:
        write_json(report, args.json_path)
    if args.csv_path:
        write_csv(report, args.csv_path)
    if args.print_json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        classification = report["classification"]
        risk = report["risk"]
        print(f"Target:      {report['target']} ({classification['type']})")
        print(f"Global:      {classification['is_global']}")
        print(f"PTR:         {report['reverse_dns'].get('hostname') or '-'}")
        print(f"ASN:         {report['network'].get('asn') or '-'}")
        print(f"Prefix:      {report['network'].get('prefix') or '-'}")
        print(f"RIR:         {report['network'].get('rir') or '-'}")
        print(f"Country:     {report['geolocation'].get('country') or report['rdap'].get('country') or '-'}")
        print(f"Risk:        {risk['score']}/100 ({risk['level'].upper()})")
        print(f"Confidence:  {risk['confidence']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

