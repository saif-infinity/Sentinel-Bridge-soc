"""Fixtures partagées : collecteur HTTP local et port TCP fermé."""

from __future__ import annotations

import socket
import threading
from contextlib import closing
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


@dataclass
class RecordedRequest:
    path: str
    headers: dict[str, str]
    body: bytes

    @property
    def text(self) -> str:
        return self.body.decode("utf-8")


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:  # noqa: N802 - nom imposé par BaseHTTPRequestHandler
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self.server.requests.append(  # type: ignore[attr-defined]
            RecordedRequest(
                self.path,
                {key.lower(): value for key, value in self.headers.items()},
                body,
            )
        )
        status = self.server.response_status  # type: ignore[attr-defined]
        payload = self.server.response_body  # type: ignore[attr-defined]
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args) -> None:  # silence les logs de test
        pass


class RecordingServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.requests: list[RecordedRequest] = []
        self.response_status = 200
        self.response_body = b'{"status":"accepted"}'

    @property
    def url(self) -> str:
        host, port = self.server_address[:2]
        return f"http://{host}:{port}/api/pipeline/ingest"


@dataclass
class ServerFixture:
    server: RecordingServer
    thread: threading.Thread
    requests: list[RecordedRequest] = field(default_factory=list)

    @property
    def url(self) -> str:
        return self.server.url


@pytest.fixture()
def http_collector():
    server = RecordingServer()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield ServerFixture(server=server, thread=thread)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture()
def closed_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    return port


@pytest.fixture()
def listening_port():
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(8)
        port = sock.getsockname()[1]
        yield port
