"""Heuristics for identifying potential spy-node floods and sybil networks (advisory only)."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from peer_fortress.diversity import DiversityReport, PeerRecord


@dataclass
class SpyHeuristicReport:
    """Detailed audit of potential spy-node clusters and sybil networks."""

    spy_saturation_score: int = 0  # 0 (clean) to 100 (highly saturated / vulnerable)
    sybil_clusters_detected: int = 0
    warnings: list[str] = field(default_factory=list)
    signals: list[dict[str, Any]] = field(default_factory=list)
    advisory_only: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "spy_saturation_score": self.spy_saturation_score,
            "sybil_clusters_detected": self.sybil_clusters_detected,
            "warnings": self.warnings,
            "signals": self.signals,
            "advisory_only": self.advisory_only,
        }


def analyze_spy_heuristics(
    sync_info: dict[str, Any], report: DiversityReport
) -> SpyHeuristicReport:
    """Analyze peer properties (from sync_info) to flag potential spy-node clusters.

    Based on Rucknium's research on P2P Sybil attacks and MRL Issue #1124.
    """
    spy_report = SpyHeuristicReport()
    peers = sync_info.get("result", sync_info).get("peers", [])
    if not peers:
        return spy_report

    signals = []
    warnings = []
    score = 0

    # Heuristic 1: Support Flags Uniformity
    # Standard monerod nodes usually have support_flags = 1 (standard) or other flags.
    # If 80%+ clearnet peers share the EXACT same support_flags, pruning_seed, and rpc_port
    # and are concentrated in /24 buckets, they may be a uniform cluster of spy instances.
    clearnet_peers = [p for p in peers if ".onion" not in str(p.get("address", "")).lower()]
    total_clearnet = len(clearnet_peers)

    if total_clearnet >= 5:
        # Check support flags concentration
        flag_counts = Counter(p.get("support_flags", 0) for p in clearnet_peers)
        most_common_flag, count = flag_counts.most_common(1)[0]
        flag_ratio = count / total_clearnet

        if flag_ratio > 0.8:
            score += 15
            signals.append({
                "type": "support_flags_concentration",
                "severity": "medium",
                "description": f"{flag_ratio:.0%} of clearnet peers share uniform support_flags ({most_common_flag})."
            })
            warnings.append("High uniformity in peer support flags; possible automated sybil cluster.")

        # Check pruning seed uniformity (0 is default, but non-zero should be random)
        seeds = [p.get("pruning_seed", 0) for p in clearnet_peers if p.get("pruning_seed", 0) != 0]
        if seeds:
            seed_counts = Counter(seeds)
            most_common_seed, seed_count = seed_counts.most_common(1)[0]
            if seed_count > 1 and (seed_count / len(seeds)) > 0.5:
                score += 20
                signals.append({
                    "type": "duplicate_pruning_seeds",
                    "severity": "high",
                    "description": f"Multiple peers sharing identical active pruning seed ({most_common_seed})."
                })
                warnings.append("Identical pruning seeds across distinct P2P addresses; highly suspicious.")

    # Heuristic 2: Subnet Concentration (Sybil Bucketing)
    # If a /24 bucket contains multiple distinct peer hosts, it's highly likely to be
    # a single operator running multiple spy instances on the same host or subnet.
    for bucket, count in report.bucket_counts.items():
        if count >= 3 and bucket != "onion":
            score += min(25, count * 5)
            signals.append({
                "type": "subnet_sybil_cluster",
                "severity": "high",
                "description": f"Subnet {bucket} has {count} active connections."
            })
            warnings.append(f"Subnet {bucket} has {count} active clearnet peer connections (potential sybil group).")
            spy_report.sybil_clusters_detected += 1

    # Heuristic 3: onion vs Clearnet Egress saturation
    # If the operator expects Tor but clearnet connections are overwhelming the peer list,
    # or vice versa, the node's circuit could be saturated or eclipsed.
    if report.total_peers >= 10:
        onion_ratio = report.onion_peers / report.total_peers
        if onion_ratio < 0.05:
            score += 10
            signals.append({
                "type": "clearnet_saturation",
                "severity": "low",
                "description": "Fewer than 5% of connections are over Tor (.onion)."
            })
            warnings.append("Extremely low Tor path ratio; node is clearnet-heavy, increasing macro eclipse risks.")

    # Final score normalization
    spy_report.spy_saturation_score = max(0, min(100, score))
    spy_report.warnings = warnings
    spy_report.signals = signals

    return spy_report
