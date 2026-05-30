"""Tor SOCKS5 proxy health check (milestone-0 — reachability only)."""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from typing import Any


DEFAULT_SOCKS_HOST = "127.0.0.1"
DEFAULT_SOCKS_PORT = 9050

# SOCKS5: VER=5, NMETHODS=1, METHOD=0 (no auth)
_SOCKS5_GREETING = b"\x05\x01\x00"
# Expected: VER=5, METHOD=0
_SOCKS5_GREETING_OK = b"\x05\x00"


@dataclass
class TorHealthReport:
    reachable: bool
    host: str
    port: int
    latency_ms: float | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "reachable": self.reachable,
            "host": self.host,
            "port": self.port,
            "latency_ms": self.latency_ms,
            "error": self.error,
        }


def check_socks5(
    host: str = DEFAULT_SOCKS_HOST,
    port: int = DEFAULT_SOCKS_PORT,
    timeout: float = 3.0,
) -> TorHealthReport:
    """Verify a SOCKS5 proxy accepts connections and completes the auth handshake."""
    start = time.perf_counter()
    sock: socket.socket | None = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(_SOCKS5_GREETING)
        resp = sock.recv(2)
        if resp != _SOCKS5_GREETING_OK:
            return TorHealthReport(
                reachable=False,
                host=host,
                port=port,
                error=f"unexpected SOCKS5 greeting response: {resp!r}",
            )
        latency = (time.perf_counter() - start) * 1000.0
        return TorHealthReport(
            reachable=True,
            host=host,
            port=port,
            latency_ms=round(latency, 2),
        )
    except OSError as exc:
        return TorHealthReport(
            reachable=False,
            host=host,
            port=port,
            error=str(exc),
        )
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def format_tor_health(report: TorHealthReport) -> str:
    if report.reachable:
        return (
            f"Tor SOCKS5: UP at {report.host}:{report.port} "
            f"({report.latency_ms} ms handshake)"
        )
    detail = report.error or "unknown error"
    return f"Tor SOCKS5: DOWN at {report.host}:{report.port} — {detail}"
