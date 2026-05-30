"""Optional JSON Schema validation for Peer Fortress reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas"


def load_schema(name: str = "diversity-report.schema.json") -> dict[str, Any]:
    path = _SCHEMA_DIR / name
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def validate_diversity_report(data: dict[str, Any]) -> None:
    """Raise jsonschema.ValidationError if *data* does not match the bundled schema."""
    try:
        import jsonschema
    except ImportError as exc:
        raise RuntimeError(
            "jsonschema is required for --validate-schema (pip install jsonschema)"
        ) from exc

    schema = load_schema()
    jsonschema.validate(instance=data, schema=schema)
