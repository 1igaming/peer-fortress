"""CLI entry point for peer-fortress."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from peer_fortress import __version__
from peer_fortress.diversity import analyze_sync_info
from peer_fortress.rpc import fetch_sync_info, load_fixture
from peer_fortress.tor_health import check_socks5, format_tor_health

DEFAULT_FIXTURE = Path(__file__).parent / "fixtures" / "sample_sync_info.json"


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
    p = argparse.ArgumentParser(
        prog="peer-fortress",
        description="Analyze monerod peer diversity from sync_info (mock or live RPC).",
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
        "--tor-check",
        action="store_true",
        help="Check Tor SOCKS5 proxy reachability (default 127.0.0.1:9050) and exit",
    )
    p.add_argument("--socks-host", default="127.0.0.1", help="SOCKS5 host for --tor-check")
    p.add_argument("--socks-port", type=int, default=9050, help="SOCKS5 port for --tor-check")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.tor_check:
        report = check_socks5(args.socks_host, args.socks_port)
        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
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

    if args.json:
        out = report.to_dict()
        out["source"] = source
        print(json.dumps(out, indent=2))
    else:
        print(_format_text(report))
        print(f"\nSource: {source}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
