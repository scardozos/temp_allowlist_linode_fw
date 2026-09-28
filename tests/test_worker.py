import logging
import os
import socket
import subprocess
import sys
import time
import unittest

os.environ["TESTING"] = "true"
os.environ["LINODE_TOKEN"] = "dummy_token"
os.environ["FIREWALL_ID"] = "12345"

from temp_allowlist_linode_fw.logging import ClientReadTimeoutFilter

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(port: int, deadline: float):
    while time.monotonic() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("gunicorn did not start listening in time")


def _http_get(port: int, path: str, timeout: float) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        request = f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        s.sendall(request.encode())
        chunks = []
        while chunk := s.recv(4096):
            chunks.append(chunk)
        return b"".join(chunks)


class TestReadTimeoutThreadWorker(unittest.TestCase):
    """Run real gunicorn with a single thread and a client stalled mid-request."""

    def start_gunicorn(self, worker_class: str) -> int:
        port = _free_port()
        env = dict(os.environ, CLIENT_READ_TIMEOUT_SECONDS="1")
        proc = subprocess.Popen(
            [
                sys.executable, "-m", "gunicorn",
                "-k", worker_class,
                "--threads", "1",
                "-b", f"127.0.0.1:{port}",
                "app:app",
            ],
            cwd=REPO_ROOT,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.addCleanup(proc.wait, 5)
        self.addCleanup(proc.kill)
        _wait_for_port(port, time.monotonic() + 10)
        return port

    def stall_client(self, port: int):
        """Send a partial request line and go quiet, like a port scanner."""
        s = socket.create_connection(("127.0.0.1", port))
        self.addCleanup(s.close)
        s.sendall(b"GET /getacc")
        time.sleep(0.5)  # let the only pool thread pick it up

    def test_stalled_client_pins_stock_gthread(self):
        port = self.start_gunicorn("gthread")
        self.stall_client(port)
        with self.assertRaises(TimeoutError):
            _http_get(port, "/nope", timeout=3)

    def test_stalled_client_is_dropped(self):
        port = self.start_gunicorn(
            "temp_allowlist_linode_fw.worker.ReadTimeoutThreadWorker"
        )
        self.stall_client(port)
        response = _http_get(port, "/nope", timeout=5)
        self.assertTrue(response.startswith(b"HTTP/1.1 404"), response)


class TestClientReadTimeoutFilter(unittest.TestCase):
    def make_record(self, exc: BaseException) -> logging.LogRecord:
        return logging.LogRecord(
            "gunicorn.error", logging.ERROR, __file__, 0,
            "Socket error processing request.", None, (type(exc), exc, None),
        )

    def test_read_timeout_suppressed_at_info_level(self):
        logging.getLogger().setLevel(logging.INFO)
        record = self.make_record(TimeoutError())
        self.assertFalse(ClientReadTimeoutFilter().filter(record))

    def test_read_timeout_emitted_at_debug_level(self):
        logging.getLogger().setLevel(logging.DEBUG)
        record = self.make_record(TimeoutError())
        self.assertTrue(ClientReadTimeoutFilter().filter(record))

    def test_other_socket_errors_still_emitted(self):
        logging.getLogger().setLevel(logging.INFO)
        record = self.make_record(OSError(5, "EIO"))
        self.assertTrue(ClientReadTimeoutFilter().filter(record))


if __name__ == "__main__":
    unittest.main()
