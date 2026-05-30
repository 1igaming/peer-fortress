"""monerosim scenario integration stub for Peer Fortress eclipse rehearsal.

Full integration planned for CCS Milestone 4. This module validates scenario
YAML templates and documents the rehearsal workflow without requiring monerosim
to be installed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore


@dataclass
class MonerosimScenario:
    name: str
    description: str
    scenario_type: str
    nodes: int = 0
    duration_seconds: int = 0
    peer_fortress_checks: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "scenario_type": self.scenario_type,
            "nodes": self.nodes,
            "duration_seconds": self.duration_seconds,
            "peer_fortress_checks": self.peer_fortress_checks,
        }


def load_scenario(path: Path) -> MonerosimScenario:
    """Load and validate a monerosim scenario YAML template."""
    if yaml is None:
        raise ImportError("PyYAML required: pip install pyyaml")
    with path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Scenario must be a mapping: {path}")
    required = ("name", "description", "scenario_type")
    missing = [k for k in required if k not in data]
    if missing:
        raise ValueError(f"Missing required keys {missing} in {path}")
    return MonerosimScenario(
        name=str(data["name"]),
        description=str(data["description"]),
        scenario_type=str(data["scenario_type"]),
        nodes=int(data.get("nodes", 0)),
        duration_seconds=int(data.get("duration_seconds", 0)),
        peer_fortress_checks=list(data.get("peer_fortress_checks", [])),
        raw=data,
    )


def list_scenarios(scenarios_dir: Path) -> list[MonerosimScenario]:
    """List all valid scenario templates in a directory."""
    if not scenarios_dir.is_dir():
        return []
    scenarios = []
    for path in sorted(scenarios_dir.glob("*.yaml")):
        try:
            scenarios.append(load_scenario(path))
        except (ValueError, ImportError):
            continue
    return scenarios


def format_scenario_summary(scenario: MonerosimScenario) -> str:
    """Human-readable summary of a monerosim scenario template."""
    lines = [
        f"Scenario: {scenario.name}",
        f"Type:     {scenario.scenario_type}",
        f"Nodes:    {scenario.nodes}",
        f"Duration: {scenario.duration_seconds}s",
        "",
        scenario.description,
    ]
    if scenario.peer_fortress_checks:
        lines.extend(["", "Peer Fortress checks during rehearsal:"])
        for check in scenario.peer_fortress_checks:
            lines.append(f"  • {check}")
    lines.extend([
        "",
        "Status: STUB — run with monerosim once Milestone 4 ships.",
        "See: https://github.com/Fountain5405/monerosim",
    ])
    return "\n".join(lines)
