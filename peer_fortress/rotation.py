"""Advisory peer rotation recommendations (no auto-ban)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from peer_fortress.diversity import DiversityReport, PeerRecord


@dataclass
class RotationRecommendation:
    """Human-approved action hint — never executed automatically."""

    priority: str  # high | medium | low
    category: str  # concentration | duplicates | tor | peer_count
    summary: str
    detail: str
    advisory_only: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "priority": self.priority,
            "category": self.category,
            "summary": self.summary,
            "detail": self.detail,
            "advisory_only": self.advisory_only,
        }


def recommend_rotations(report: DiversityReport) -> list[RotationRecommendation]:
    """Suggest peer rotation steps from diversity analysis (advisory only)."""
    recs: list[RotationRecommendation] = []

    if report.total_peers == 0:
        recs.append(
            RotationRecommendation(
                priority="high",
                category="peer_count",
                summary="Wait for peers before rotation decisions",
                detail="sync_info has no peers — ensure monerod is synced and reachable.",
            )
        )
        return recs

    if report.max_bucket_share > 0.5:
        recs.append(
            RotationRecommendation(
                priority="high",
                category="concentration",
                summary=f"Rotate peers away from {report.max_bucket_label}",
                detail=(
                    f"{report.max_bucket_share:.0%} of peers share one bucket. "
                    "Add priority nodes from other /24 subnets; remove sticky duplicates "
                    "via monerod peer management (human-approved only)."
                ),
            )
        )
    elif report.max_bucket_share > 0.35:
        recs.append(
            RotationRecommendation(
                priority="medium",
                category="concentration",
                summary="Broaden subnet spread",
                detail=(
                    f"Bucket {report.max_bucket_label} holds {report.max_bucket_share:.0%} of peers. "
                    "Consider adding 2–3 priority nodes on distinct /24s."
                ),
            )
        )

    if report.duplicate_hosts:
        recs.append(
            RotationRecommendation(
                priority="medium",
                category="duplicates",
                summary="Deduplicate repeated host entries",
                detail=(
                    f"{report.duplicate_hosts} duplicate host(s) detected. "
                    "Review peer list for stuck connections; rotate only after manual review."
                ),
            )
        )

    spread = report.unique_buckets / report.total_peers if report.total_peers else 0
    if spread < 0.3 and report.total_peers >= 8:
        recs.append(
            RotationRecommendation(
                priority="medium",
                category="concentration",
                summary="Increase bucket diversity",
                detail=(
                    f"Only {report.unique_buckets} buckets for {report.total_peers} peers. "
                    "Prefer inbound peers from new subnets over quantity in same /24."
                ),
            )
        )

    onion_ratio = report.onion_peers / report.total_peers if report.total_peers else 0
    if report.total_peers >= 10 and onion_ratio < 0.1:
        recs.append(
            RotationRecommendation(
                priority="low",
                category="tor",
                summary="Optional: enable Tor proxy for .onion diversity",
                detail=(
                    "Few or no .onion peers. If Tor egress is configured, run with --expect-tor "
                    "and verify SOCKS5 with --tor-check before expecting onion peer growth."
                ),
            )
        )

    if report.score >= 80 and not recs:
        recs.append(
            RotationRecommendation(
                priority="low",
                category="peer_count",
                summary="No rotation needed",
                detail="Peer diversity looks healthy. Re-run after network events or peer list changes.",
            )
        )

    return recs


def peers_to_review(report: DiversityReport, *, limit: int = 5) -> list[dict[str, str]]:
    """Peers in the hottest bucket — candidates for manual review (not auto-ban)."""
    if not report.bucket_counts or not report.peers:
        return []
    hot_bucket = report.max_bucket_label
    if not hot_bucket:
        return []
    candidates = [p for p in report.peers if p.bucket == hot_bucket][:limit]
    return [{"host": p.host, "address": p.address, "bucket": p.bucket} for p in candidates]
