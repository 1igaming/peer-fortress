"""Peer diversity scoring heuristics for monerod peer lists."""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any


ONION_RE = re.compile(r"\.onion(?::\d+)?$", re.IGNORECASE)


@dataclass
class PeerRecord:
    host: str
    address: str
    kind: str  # onion | ipv4 | ipv6 | unknown
    bucket: str  # /24, /48, onion, or unknown


@dataclass
class DiversityReport:
    total_peers: int = 0
    onion_peers: int = 0
    clearnet_peers: int = 0
    unique_buckets: int = 0
    max_bucket_share: float = 0.0
    max_bucket_label: str = ""
    duplicate_hosts: int = 0
    score: int = 0
    grade: str = "unknown"
    warnings: list[str] = field(default_factory=list)
    bucket_counts: dict[str, int] = field(default_factory=dict)
    peers: list[PeerRecord] = field(default_factory=list)
    rotation_recommendations: list[dict[str, Any]] = field(default_factory=list)
    peers_to_review: list[dict[str, str]] = field(default_factory=list)
    spy_report: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        base = {
            "total_peers": self.total_peers,
            "onion_peers": self.onion_peers,
            "clearnet_peers": self.clearnet_peers,
            "onion_ratio": round(self.onion_peers / self.total_peers, 3)
            if self.total_peers
            else 0.0,
            "unique_buckets": self.unique_buckets,
            "max_bucket_share": round(self.max_bucket_share, 3),
            "max_bucket_label": self.max_bucket_label,
            "duplicate_hosts": self.duplicate_hosts,
            "score": self.score,
            "grade": self.grade,
            "warnings": self.warnings,
            "bucket_counts": self.bucket_counts,
        }
        if self.rotation_recommendations:
            base["rotation_recommendations"] = self.rotation_recommendations
        if self.peers_to_review:
            base["peers_to_review"] = self.peers_to_review
        if self.spy_report:
            base["spy_report"] = self.spy_report
        return base

    def to_schema_dict(self, *, tool_version: str, source: str = "") -> dict[str, Any]:
        """JSON output aligned with schemas/diversity-report.schema.json."""
        out = self.to_dict()
        out.update({
            "schema_version": "1.0",
            "tool_version": tool_version,
            "report_type": "diversity",
            "source": source,
        })
        return out


def _extract_host(raw: str) -> str:
    """Pull host from monerod host:port or bracketed IPv6."""
    raw = raw.strip()
    if raw.startswith("["):
        end = raw.find("]")
        if end != -1:
            return raw[1:end]
    if ONION_RE.search(raw):
        # Strip optional :port so duplicate onion hosts collapse to one entry.
        host, _, port = raw.rpartition(":")
        if port.isdigit():
            return host
        return raw
    # A bare (unbracketed) IPv6 address contains multiple colons and carries
    # no port — stripping after the last colon would mangle it.
    if raw.count(":") == 1:
        host, _, port = raw.rpartition(":")
        if port.isdigit():
            return host
    return raw


def _classify_host(host: str) -> tuple[str, str]:
    if ONION_RE.search(host) or host.endswith(".onion"):
        return "onion", "onion"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "unknown", "unknown"
    if isinstance(ip, ipaddress.IPv4Address):
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
        return "ipv4", str(net)
    net = ipaddress.ip_network(f"{ip}/48", strict=False)
    return "ipv6", str(net)


def _parse_peers(sync_info: dict[str, Any]) -> list[PeerRecord]:
    records: list[PeerRecord] = []
    for entry in sync_info.get("peers", []):
        if not isinstance(entry, dict):
            continue
        addr = str(entry.get("address", ""))
        host = str(entry.get("host", "")) or _extract_host(addr)
        kind, bucket = _classify_host(host)
        records.append(PeerRecord(host=host, address=addr, kind=kind, bucket=bucket))
    return records


def _grade(score: int) -> str:
    if score >= 80:
        return "good"
    if score >= 60:
        return "fair"
    if score >= 40:
        return "weak"
    return "poor"


def analyze_sync_info(sync_info: dict[str, Any], *, expect_tor: bool = False) -> DiversityReport:
    """Score peer diversity from a monerod sync_info payload."""
    peers = _parse_peers(sync_info)
    report = DiversityReport(total_peers=len(peers), peers=peers)

    if not peers:
        report.warnings.append("No peers in sync_info — node may be offline or still syncing.")
        report.score = 0
        report.grade = "poor"
        return report

    host_counts = Counter(p.host for p in peers)
    report.duplicate_hosts = sum(c - 1 for c in host_counts.values() if c > 1)

    bucket_counts = Counter(p.bucket for p in peers if p.bucket != "unknown")
    report.bucket_counts = dict(bucket_counts)
    report.unique_buckets = len(bucket_counts)

    report.onion_peers = sum(1 for p in peers if p.kind == "onion")
    report.clearnet_peers = report.total_peers - report.onion_peers

    if bucket_counts:
        top_bucket, top_count = bucket_counts.most_common(1)[0]
        report.max_bucket_label = top_bucket
        report.max_bucket_share = top_count / report.total_peers

    score = 100.0

    # Subnet concentration — same /24 holding many peers is an eclipse risk signal.
    if report.max_bucket_share > 0.5:
        score -= 35
        report.warnings.append(
            f"Over 50% of peers share bucket {report.max_bucket_label} "
            f"({report.max_bucket_share:.0%})."
        )
    elif report.max_bucket_share > 0.35:
        score -= 20
        report.warnings.append(
            f"Subnet concentration high: {report.max_bucket_share:.0%} in {report.max_bucket_label}."
        )
    elif report.max_bucket_share > 0.25:
        score -= 10

    # Low bucket spread relative to peer count.
    spread_ratio = report.unique_buckets / report.total_peers if report.total_peers else 0
    if spread_ratio < 0.3 and report.total_peers >= 8:
        score -= 15
        report.warnings.append(
            f"Low bucket spread ({report.unique_buckets} buckets for {report.total_peers} peers)."
        )

    if report.duplicate_hosts:
        score -= min(25, report.duplicate_hosts * 8)
        report.warnings.append(f"{report.duplicate_hosts} duplicate host entries detected.")

    onion_ratio = report.onion_peers / report.total_peers
    if expect_tor and onion_ratio < 0.15:
        score -= 20
        report.warnings.append(
            f"Tor mode expected but only {onion_ratio:.0%} peers are .onion."
        )
    elif not expect_tor and report.total_peers >= 10 and onion_ratio == 0:
        score -= 5
        report.warnings.append("No .onion peers — fine for clearnet-only, but limits Tor path diversity.")

    if report.total_peers < 8:
        score -= 10
        report.warnings.append(f"Low peer count ({report.total_peers}) — diversity score less meaningful.")

    report.score = max(0, min(100, int(round(score))))
    report.grade = _grade(report.score)

    from peer_fortress.rotation import peers_to_review, recommend_rotations
    from peer_fortress.spy_heuristics import analyze_spy_heuristics

    recs = recommend_rotations(report)
    report.rotation_recommendations = [r.to_dict() for r in recs]
    report.peers_to_review = peers_to_review(report)
    report.spy_report = analyze_spy_heuristics(sync_info, report).to_dict()
    return report
