"""Human-readable report formatting for Peer Fortress."""

from __future__ import annotations

from peer_fortress.diversity import DiversityReport
from peer_fortress.tor_health import TorHealthReport


def _bar(score: int, width: int = 20) -> str:
    filled = int(round(score / 100 * width))
    return f"[{'#' * filled}{'.' * (width - filled)}]"


def format_diversity_report(report: DiversityReport, *, source: str = "") -> str:
    """Extended human-readable diversity report."""
    onion_pct = (report.onion_peers / report.total_peers * 100) if report.total_peers else 0
    lines = [
        "╔══════════════════════════════════════════════════════════════╗",
        "║           PEER FORTRESS — DIVERSITY REPORT                   ║",
        "╚══════════════════════════════════════════════════════════════╝",
        "",
        f"  Score:  {report.score}/100  {_bar(report.score)}  ({report.grade.upper()})",
        "",
        "  PEER MIX",
        f"    Total peers:     {report.total_peers}",
        f"    .onion:          {report.onion_peers}  ({onion_pct:.0f}%)",
        f"    Clearnet:        {report.clearnet_peers}",
        "",
        "  SUBNET DIVERSITY",
        f"    Unique buckets:  {report.unique_buckets}",
        f"    Max concentration: {report.max_bucket_share:.0%} in {report.max_bucket_label or 'n/a'}",
        f"    Duplicate hosts: {report.duplicate_hosts}",
    ]

    if report.warnings:
        lines.extend(["", "  ⚠ WARNINGS"])
        for w in report.warnings:
            lines.append(f"    • {w}")

    if report.bucket_counts:
        lines.extend(["", "  TOP BUCKETS"])
        for bucket, count in sorted(report.bucket_counts.items(), key=lambda x: -x[1])[:5]:
            pct = count / report.total_peers * 100 if report.total_peers else 0
            lines.append(f"    {bucket:<24} {count:>3} peers  ({pct:.0f}%)")

    lines.extend(["", "  RECOMMENDATIONS"])
    if report.score >= 80:
        lines.append("    ✓ Peer diversity looks healthy. Re-check after major network events.")
    elif report.score >= 60:
        lines.append("    → Consider adding priority nodes from diverse /24 subnets.")
        lines.append("    → Review whether Tor proxy is configured if you expect .onion peers.")
    else:
        lines.append("    ✗ High concentration risk — review peer list and consider rotation.")
        lines.append("    → See funded milestone playbooks for human-approved rotation steps.")

    if report.rotation_recommendations:
        lines.extend(["", "  ROTATION (advisory — no auto-ban)"])
        for rec in report.rotation_recommendations:
            pri = rec.get("priority", "low").upper()
            lines.append(f"    [{pri}] {rec.get('summary', '')}")
            detail = rec.get("detail", "")
            if detail:
                lines.append(f"          {detail}")
    
    if report.spy_report:
        spy = report.spy_report
        sat_score = spy.get("spy_saturation_score", 0)
        lines.extend([
            "",
            "  SPY HEURISTICS & SYBIL AUDIT",
            f"    Spy saturation score: {sat_score}/100",
        ])
        for sig in spy.get("signals", []):
            sev = sig.get("severity", "low").upper()
            lines.append(f"    [{sev}] {sig.get('description', '')}")

    if report.peers_to_review:
        lines.extend(["", "  PEERS TO REVIEW (hot bucket)"])
        for p in report.peers_to_review[:5]:
            lines.append(f"    {p.get('host', '?')}  ({p.get('bucket', '')})")

    if source:
        lines.extend(["", f"  Source: {source}"])

    return "\n".join(lines)


def format_tor_report(report: TorHealthReport) -> str:
    """Extended human-readable Tor health report."""
    status = "REACHABLE" if report.reachable else "UNREACHABLE"
    lines = [
        "╔══════════════════════════════════════════════════════════════╗",
        "║           PEER FORTRESS — TOR SOCKS5 HEALTH                  ║",
        "╚══════════════════════════════════════════════════════════════╝",
        "",
        f"  Status:    {status}",
        f"  Endpoint:  {report.host}:{report.port}",
    ]
    if report.latency_ms is not None:
        lines.append(f"  Latency:   {report.latency_ms:.1f} ms (handshake)")
    if report.error:
        lines.append(f"  Error:     {report.error}")
    lines.extend([
        "",
        "  NOTE: Tor health is a prerequisite for trusting .onion peer ratios.",
        "        Run diversity report with --expect-tor when monerod uses --proxy.",
    ])
    return "\n".join(lines)
