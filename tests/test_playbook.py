"""Tests for peer_fortress.playbook module."""

from __future__ import annotations

from peer_fortress.diversity import DiversityReport
from peer_fortress.playbook import (
    Playbook,
    PlaybookStep,
    format_playbooks,
    generate_playbooks,
)


def _concentrated_report(share: float = 0.5, total: int = 20) -> DiversityReport:
    """Return a DiversityReport with a concentrated subnet."""
    count = int(share * total)
    report = DiversityReport(
        total_peers=total,
        onion_peers=0,
        clearnet_peers=total,
        unique_buckets=3,
        max_bucket_share=share,
        max_bucket_label="203.0.113.0/24",
        score=45,
        grade="weak",
        bucket_counts={"203.0.113.0/24": count, "192.168.1.0/24": 2, "10.0.0.0/24": 1},
        spy_report={
            "spy_saturation_score": 20,
            "sybil_clusters_detected": 0,
            "signals": [],
            "warnings": [],
            "advisory_only": True,
        },
    )
    return report


def _low_tor_report() -> DiversityReport:
    """Return a report with very low Tor ratio."""
    return DiversityReport(
        total_peers=15,
        onion_peers=0,
        clearnet_peers=15,
        unique_buckets=10,
        max_bucket_share=0.2,
        max_bucket_label="10.0.0.0/24",
        score=80,
        grade="good",
        bucket_counts={"10.0.0.0/24": 3},
        spy_report={
            "spy_saturation_score": 10,
            "sybil_clusters_detected": 0,
            "signals": [],
            "warnings": [],
            "advisory_only": True,
        },
    )


def _sybil_seed_report() -> DiversityReport:
    """Return a report with a duplicate pruning seed signal."""
    return DiversityReport(
        total_peers=12,
        onion_peers=1,
        clearnet_peers=11,
        unique_buckets=8,
        max_bucket_share=0.17,
        max_bucket_label="198.51.100.0/24",
        score=65,
        grade="fair",
        bucket_counts={"198.51.100.0/24": 2, "203.0.113.0/24": 1},
        spy_report={
            "spy_saturation_score": 45,
            "sybil_clusters_detected": 0,
            "signals": [
                {
                    "type": "duplicate_pruning_seeds",
                    "severity": "high",
                    "description": "Multiple peers sharing identical active pruning seed (384).",
                }
            ],
            "warnings": ["Identical pruning seeds across distinct P2P addresses."],
            "advisory_only": True,
        },
    )


# ── Playbook generation tests ──────────────────────────────────────────────

def test_no_playbooks_for_healthy_node():
    r = DiversityReport(
        total_peers=20,
        onion_peers=5,
        clearnet_peers=15,
        unique_buckets=15,
        max_bucket_share=0.15,
        max_bucket_label="10.0.0.0/24",
        score=90,
        grade="good",
        bucket_counts={"10.0.0.0/24": 3},
        spy_report={"spy_saturation_score": 5, "sybil_clusters_detected": 0, "signals": [], "warnings": [], "advisory_only": True},
    )
    books = generate_playbooks(r)
    assert books == [], "Healthy node should trigger no playbooks."


def test_subnet_concentration_triggers_playbook():
    r = _concentrated_report(share=0.5)
    books = generate_playbooks(r)
    assert len(books) >= 1
    assert any("Subnet Concentration" in b.name for b in books)


def test_subnet_concentration_high_severity():
    r = _concentrated_report(share=0.6)
    books = generate_playbooks(r)
    subnet_book = next(b for b in books if "Subnet" in b.name)
    assert subnet_book.severity in ("critical", "high")


def test_subnet_concentration_steps_present():
    r = _concentrated_report(share=0.5)
    books = generate_playbooks(r)
    book = next(b for b in books if "Subnet" in b.name)
    assert len(book.steps) >= 3
    assert all(isinstance(s, PlaybookStep) for s in book.steps)


def test_low_tor_ratio_triggers_playbook():
    r = _low_tor_report()
    books = generate_playbooks(r)
    assert any("Tor" in b.name for b in books)


def test_sybil_seed_triggers_playbook():
    r = _sybil_seed_report()
    books = generate_playbooks(r)
    assert any("Sybil" in b.name or "Pruning" in b.name for b in books)


def test_playbook_advisory_only():
    r = _concentrated_report()
    books = generate_playbooks(r)
    for b in books:
        assert b.advisory_only is True


def test_playbook_to_dict():
    r = _concentrated_report()
    books = generate_playbooks(r)
    for b in books:
        d = b.to_dict()
        assert "name" in d
        assert "steps" in d
        assert d["advisory_only"] is True
        for step in d["steps"]:
            assert "step" in step
            assert "action" in step


def test_playbook_format_text():
    r = _concentrated_report()
    books = generate_playbooks(r)
    txt = format_playbooks(books)
    assert "ADVISORY" in txt or "advisory" in txt.lower() or "playbook" in txt.lower()


def test_format_empty_playbooks():
    txt = format_playbooks([])
    assert "No actionable playbooks" in txt or "clean" in txt.lower()


def test_playbook_step_command_optional():
    step = PlaybookStep(step=1, action="Do something", risk="low")
    d = step.to_dict()
    assert "example_command" not in d

    step_with_cmd = PlaybookStep(step=1, action="Do something", command="monerod --help", risk="low")
    d2 = step_with_cmd.to_dict()
    assert d2["example_command"] == "monerod --help"
