"""Read-only advisory playbook templates for Peer Fortress operators.

Playbooks are never auto-applied. They produce human-readable action plans
that the operator must review and execute manually.

Milestone 2 deliverable — citing Rucknium / MRL #1124 recommendations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from peer_fortress.diversity import DiversityReport


@dataclass
class PlaybookStep:
    """A single manual action step in a remediation playbook."""

    step: int
    action: str
    command: str | None = None  # example monerod CLI snippet, advisory only
    rationale: str = ""
    risk: str = "low"  # low | medium | high

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "step": self.step,
            "action": self.action,
            "rationale": self.rationale,
            "risk": self.risk,
        }
        if self.command:
            out["example_command"] = self.command
        return out


@dataclass
class Playbook:
    """A named, read-only remediation playbook for a detected threat scenario."""

    name: str
    trigger: str
    severity: str  # low | medium | high | critical
    steps: list[PlaybookStep] = field(default_factory=list)
    advisory_only: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "trigger": self.trigger,
            "severity": self.severity,
            "advisory_only": self.advisory_only,
            "steps": [s.to_dict() for s in self.steps],
        }

    def format_text(self) -> str:
        lines = [
            f"=== PLAYBOOK: {self.name} ===",
            f"  Trigger:  {self.trigger}",
            f"  Severity: {self.severity.upper()}",
            f"  Advisory: {self.advisory_only} (no changes applied automatically)",
            "",
            "  STEPS:",
        ]
        for s in self.steps:
            lines.append(f"    [{s.step}] {s.action}")
            if s.rationale:
                lines.append(f"         Rationale: {s.rationale}")
            if s.command:
                lines.append(f"         Example:   {s.command}")
            lines.append(f"         Risk:      {s.risk.upper()}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Playbook factory functions
# ---------------------------------------------------------------------------

def _subnet_concentration_playbook(bucket: str, count: int, total: int) -> Playbook:
    pct = int(count / total * 100) if total else 0
    return Playbook(
        name="Subnet Concentration Remediation",
        trigger=f"Bucket {bucket} holds {count}/{total} peers ({pct}%) — eclipse risk elevated.",
        severity="high" if pct > 50 else "medium",
        steps=[
            PlaybookStep(
                step=1,
                action=f"Identify which peers occupy subnet {bucket}.",
                rationale="Confirm this is not a legitimate Tor exit / well-known relay cluster.",
                risk="low",
            ),
            PlaybookStep(
                step=2,
                action="Add priority_nodes from geographically and topologically diverse /24 subnets.",
                command="monerod --add-priority-node=<diverse_ip>:18080",
                rationale="New priority peers pre-empt slot exhaustion from concentrated subnets.",
                risk="low",
            ),
            PlaybookStep(
                step=3,
                action=f"Consider banning hosts in {bucket} if confirmed adversarial (human-approved only).",
                command=f"# monerod ban_list -- add {bucket}.0/24 manually after review",
                rationale="Eclipse attacks require all slots to be controlled; banning excess subnet peers breaks the monopoly.",
                risk="medium",
            ),
            PlaybookStep(
                step=4,
                action="Re-run peer-fortress after 30 minutes to confirm diversity recovery.",
                command="python -m peer_fortress --rpc http://127.0.0.1:18081/json_rpc --report",
                rationale="Verify the new peers connected and the max_bucket_share has dropped.",
                risk="low",
            ),
        ],
    )


def _sybil_flood_playbook(seed: int, count: int) -> Playbook:
    return Playbook(
        name="Sybil Pruning-Seed Flood Remediation",
        trigger=f"{count} peers share pruning_seed={seed} — likely co-administered spy nodes.",
        severity="high",
        steps=[
            PlaybookStep(
                step=1,
                action=f"List all peer IPs with pruning_seed={seed} from the --json report.",
                rationale="Build the adversarial set to target for rotation.",
                risk="low",
            ),
            PlaybookStep(
                step=2,
                action="Connect to 3+ priority nodes with confirmed diverse ownership before banning.",
                command="monerod --add-priority-node=<trusted_node>:18080",
                rationale="Maintain connectivity before evicting suspected sybil cluster.",
                risk="low",
            ),
            PlaybookStep(
                step=3,
                action=f"Ban peers sharing pruning_seed={seed} after operator review.",
                command=f"# Add IPs to ban_list in monerod config after verifying this report",
                rationale=(
                    "Identical non-zero pruning seeds across distinct IPs indicate shared control. "
                    "See Rucknium / MRL Issue #1124."
                ),
                risk="medium",
            ),
            PlaybookStep(
                step=4,
                action="Monitor for 24 hours. File a network observation report on getmonero.org/forum if persistent.",
                rationale="Community awareness enables coordinated defenses against sybil floods.",
                risk="low",
            ),
        ],
    )


def _low_tor_ratio_playbook(onion_ratio: float) -> Playbook:
    return Playbook(
        name="Low Tor Egress Ratio Remediation",
        trigger=f"Only {onion_ratio:.0%} of peers are .onion — clearnet exposure is high.",
        severity="medium",
        steps=[
            PlaybookStep(
                step=1,
                action="Verify monerod is configured with --proxy=127.0.0.1:9050.",
                command="monerod --proxy=127.0.0.1:9050 --anonymous-inbound=<onion>:18083",
                rationale="Without --proxy, monerod cannot make outgoing .onion connections.",
                risk="low",
            ),
            PlaybookStep(
                step=2,
                action="Run --tor-check to verify the SOCKS5 proxy is reachable.",
                command="python -m peer_fortress --tor-check",
                rationale="A stale or dead Tor process will silently drop all .onion connections.",
                risk="low",
            ),
            PlaybookStep(
                step=3,
                action="Add known-good .onion seed nodes to monerod config.",
                command=(
                    "# Add to monerod.conf:\n"
                    "# add-peer=moneroxmrxmxmxmxm.onion:18080  # example only — verify independently"
                ),
                rationale="Bootstrapping the .onion peer pool speeds up Tor peer discovery.",
                risk="low",
            ),
        ],
    )


def generate_playbooks(report: DiversityReport) -> list[Playbook]:
    """Generate applicable advisory playbooks for the given DiversityReport.

    Returns an empty list if no threats are detected (healthy node).
    Never applies changes — all output is advisory only.
    """
    books: list[Playbook] = []

    # Subnet concentration
    for bucket, count in report.bucket_counts.items():
        if bucket == "onion":
            continue
        share = count / report.total_peers if report.total_peers else 0
        if share > 0.35:
            books.append(_subnet_concentration_playbook(bucket, count, report.total_peers))

    # Sybil pruning seeds (from spy_report signals)
    spy = report.spy_report
    for sig in spy.get("signals", []):
        if sig.get("type") == "duplicate_pruning_seeds":
            desc = sig.get("description", "")
            # Best-effort parse seed from description
            try:
                seed_val = int(desc.split("(")[1].split(")")[0])
            except (IndexError, ValueError):
                seed_val = 0
            books.append(_sybil_flood_playbook(seed_val, 2))

    # Low Tor ratio
    onion_ratio = report.onion_peers / report.total_peers if report.total_peers else 0
    if report.total_peers >= 10 and onion_ratio < 0.05:
        books.append(_low_tor_ratio_playbook(onion_ratio))

    return books


def format_playbooks(playbooks: list[Playbook]) -> str:
    if not playbooks:
        return "  No actionable playbooks triggered — node health looks clean.\n"
    lines = [f"  {len(playbooks)} playbook(s) triggered:\n"]
    for pb in playbooks:
        lines.append(pb.format_text())
        lines.append("")
    return "\n".join(lines)
