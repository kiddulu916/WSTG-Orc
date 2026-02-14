# wstg_orchestrator/utils/callback_server.py
import json
import logging
import socket
import threading
import uuid
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler

logger = logging.getLogger(__name__)


class CallbackServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 8443, external_url: str | None = None):
        self.host = host
        self.port = port
        self._external_url = external_url
        self._pending: dict[str, dict] = {}
        self._hits: list[dict] = []
        self._lock = threading.Lock()
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self):
        server_ref = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                token = self.path.strip("/").split("/")[-1].split("?")[0]
                server_ref._record_hit(token, self)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"OK")

            def do_POST(self):
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length).decode("utf-8", errors="replace")
                token = self.path.strip("/").split("/")[-1].split("?")[0]
                server_ref._record_hit(token, self, body=body)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"OK")

            def log_message(self, format, *args):
                logger.debug(f"Callback server: {format % args}")

        self._server = HTTPServer((self.host, self.port), Handler)
        if self.port == 0:
            self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        logger.info(f"Callback server started on {self.host}:{self.port}")

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server = None

    def generate_callback(self, module: str, parameter: str, payload: str) -> tuple[str, str]:
        token = str(uuid.uuid4()).replace("-", "")[:16]
        base = self._external_url or f"http://{self._get_host()}:{self.port}"
        url = f"{base}/{token}"
        entry = {
            "token": token,
            "module": module,
            "parameter": parameter,
            "payload": payload,
            "created": datetime.now(timezone.utc).isoformat(),
        }
        with self._lock:
            self._pending[token] = entry
        return url, token

    def _get_host(self) -> str:
        if self.host == "0.0.0.0":
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                s.close()
                return ip
            except Exception:
                return self.host
        return self.host

    def _record_hit(self, token: str, handler, body: str | None = None):
        with self._lock:
            pending = self._pending.pop(token, None)
            hit = {
                "token": token,
                "module": pending["module"] if pending else "unknown",
                "parameter": pending["parameter"] if pending else "unknown",
                "payload": pending["payload"] if pending else "unknown",
                "source_ip": handler.client_address[0],
                "method": handler.command,
                "path": handler.path,
                "headers": dict(handler.headers),
                "body": body,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            self._hits.append(hit)
            logger.info(f"Callback hit! Token: {token}, Module: {hit['module']}")

    def get_hits(self) -> list[dict]:
        with self._lock:
            return list(self._hits)

    def get_pending(self) -> list[dict]:
        with self._lock:
            return list(self._pending.values())