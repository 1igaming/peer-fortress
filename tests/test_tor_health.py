"""Tests for Tor SOCKS5 health checks."""

import socket
import threading
import unittest

from peer_fortress.tor_health import check_socks5


def _mini_socks5_server(host: str, port: int, stop: threading.Event) -> None:
    """Minimal SOCKS5 server that accepts no-auth handshake only."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(1)
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except TimeoutError:
                continue
            with conn:
                data = conn.recv(3)
                if data == b"\x05\x01\x00":
                    conn.sendall(b"\x05\x00")


class TorHealthTests(unittest.TestCase):
    def test_unreachable_port(self):
        report = check_socks5("127.0.0.1", 1, timeout=0.5)
        self.assertFalse(report.reachable)
        self.assertIsNotNone(report.error)

    def test_handshake_ok(self):
        stop = threading.Event()
        port = 19050
        thread = threading.Thread(
            target=_mini_socks5_server,
            args=("127.0.0.1", port, stop),
            daemon=True,
        )
        thread.start()
        try:
            report = check_socks5("127.0.0.1", port, timeout=2.0)
            self.assertTrue(report.reachable)
            self.assertIsNotNone(report.latency_ms)
        finally:
            stop.set()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
