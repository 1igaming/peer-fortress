"""CLI entry point for peer-fortress."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from peer_fortress import __version__
from peer_fortress.diversity import analyze_sync_info
from peer_fortress.monerosim import format_scenario_summary, list_scenarios, load_scenario
from peer_fortress.report import format_diversity_report, format_tor_report
from peer_fortress.rpc import fetch_sync_info, load_fixture
from peer_fortress.tor_health import check_socks5, format_tor_health

DEFAULT_FIXTURE = Path(__file__).parent / "fixtures" / "sample_sync_info.json"
DEFAULT_SCENARIOS = Path(__file__).parent.parent / "scenarios"


def _format_text(report) -> str:
    lines = [
        f"Peer Fortress v{__version__} — diversity report",
        f"Score: {report.score}/100 ({report.grade})",
        f"Peers: {report.total_peers} total | {report.onion_peers} .onion | {report.clearnet_peers} clearnet",
        f"Buckets: {report.unique_buckets} unique | max concentration {report.max_bucket_share:.0%} in {report.max_bucket_label or 'n/a'}",
    ]
    if report.duplicate_hosts:
        lines.append(f"Duplicates: {report.duplicate_hosts} repeated host(s)")
    if report.warnings:
        lines.append("Warnings:")
        lines.extend(f"  - {w}" for w in report.warnings)
    if report.bucket_counts:
        lines.append("Top buckets:")
        for bucket, count in sorted(report.bucket_counts.items(), key=lambda x: -x[1])[:5]:
            lines.append(f"  {bucket}: {count}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    epilog = (
        "Examples:\n"
        "  peer-fortress                    # mock fixture, compact score\n"
        "  peer-fortress --report           # extended report + rotation hints\n"
        "  peer-fortress --json             # schema JSON (advisory rotation only)\n"
        "  peer-fortress --out report.json  # write JSON to file\n"
        "  peer-fortress --out r.json --validate-schema  # file + schema check\n"
        "  peer-fortress --rpc URL          # live monerod JSON-RPC\n"
        "  peer-fortress --tor-check        # SOCKS5 health then exit\n"
    )
    p = argparse.ArgumentParser(
        prog="peer-fortress",
        description="Analyze monerod peer diversity from sync_info (mock or live RPC).",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    src = p.add_mutually_exclusive_group()
    src.add_argument(
        "--mock",
        nargs="?",
        const=str(DEFAULT_FIXTURE),
        metavar="FIXTURE",
        help=f"Use fixture JSON (default: {DEFAULT_FIXTURE.name})",
    )
    src.add_argument(
        "--rpc",
        metavar="URL",
        help="Live monerod JSON-RPC URL, e.g. http://127.0.0.1:18081/json_rpc",
    )
    p.add_argument(
        "--expect-tor",
        action="store_true",
        help="Penalize low .onion ratio (use when monerod runs with --proxy)",
    )
    p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    p.add_argument(
        "--out",
        metavar="FILE",
        help="Write machine-readable JSON report to FILE (e.g. report.json)",
    )
    p.add_argument(
        "--validate-schema",
        action="store_true",
        help="Validate JSON output against schemas/diversity-report.schema.json",
    )
    p.add_argument(
        "--report",
        action="store_true",
        help="Extended human-readable report with recommendations",
    )
    p.add_argument(
        "--tor-check",
        action="store_true",
        help="Check Tor SOCKS5 proxy reachability (default 127.0.0.1:9050) and exit",
    )
    p.add_argument("--socks-host", default="127.0.0.1", help="SOCKS5 host for --tor-check")
    p.add_argument("--socks-port", type=int, default=9050, help="SOCKS5 port for --tor-check")
    p.add_argument(
        "--scenario",
        metavar="YAML",
        help="Load monerosim scenario template and print rehearsal summary",
    )
    p.add_argument(
        "--list-scenarios",
        action="store_true",
        help="List monerosim scenario templates in scenarios/",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_scenarios:
        scenarios = list_scenarios(DEFAULT_SCENARIOS)
        if args.json:
            print(json.dumps([s.to_dict() for s in scenarios], indent=2))
        elif not scenarios:
            print(f"No scenarios found in {DEFAULT_SCENARIOS}")
        else:
            for s in scenarios:
                print(format_scenario_summary(s))
                print("-" * 60)
        return 0

    if args.scenario:
        scenario = load_scenario(Path(args.scenario))
        if args.json:
            print(json.dumps(scenario.to_dict(), indent=2))
        else:
            print(format_scenario_summary(scenario))
        return 0

    if args.tor_check:
        report = check_socks5(args.socks_host, args.socks_port)
        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
        elif args.report:
            print(format_tor_report(report))
        else:
            print(format_tor_health(report))
        return 0 if report.reachable else 1

    if args.rpc:
        sync_info = fetch_sync_info(args.rpc)
        source = args.rpc
    elif args.mock is not None:
        fixture = Path(args.mock)
        sync_info = load_fixture(fixture)
        source = str(fixture)
    else:
        # Default: mock mode — no daemon required.
        sync_info = load_fixture(DEFAULT_FIXTURE)
        source = str(DEFAULT_FIXTURE)

    report = analyze_sync_info(sync_info, expect_tor=args.expect_tor)

    if args.json or args.out:
        from peer_fortress import __version__
        from peer_fortress.schema_validate import validate_diversity_report

        payload = report.to_schema_dict(tool_version=__version__, source=source)
        if args.validate_schema:
            validate_diversity_report(payload)
        text = json.dumps(payload, indent=2)
        if args.out:
            out_path = Path(args.out)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(text + "\n", encoding="utf-8")
        if args.json:
            print(text)
    elif args.report:
        print(format_diversity_report(report, source=source))
    else:
        print(_format_text(report))
        print(f"\nSource: {source}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
