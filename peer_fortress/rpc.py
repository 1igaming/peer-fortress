"""monerod JSON-RPC helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen


def fetch_sync_info(rpc_url: str, timeout: float = 10.0) -> dict[str, Any]:
    """Call sync_info on a running monerod daemon."""
    payload = json.dumps({"jsonrpc": "2.0", "id": "0", "method": "sync_info"}).encode()
    req = Request(
        rpc_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read().decode())
    if "error" in body and body["error"]:
        raise RuntimeError(f"RPC error: {body['error']}")
    result = body.get("result", {})
    if not isinstance(result, dict):
        raise RuntimeError("sync_info returned unexpected payload")
    return result


def load_fixture(path: Path) -> dict[str, Any]:
    """Load a saved sync_info JSON fixture."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if "result" in data and isinstance(data["result"], dict):
        return data["result"]
    if isinstance(data, dict) and "peers" in data:
        return data
    raise ValueError(f"Unrecognized fixture format: {path}")
