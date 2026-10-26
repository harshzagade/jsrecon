"""--verify dead-endpoint checker tests — unit plus a fixture server."""
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from jsrecon.cli import main as cli_main
from jsrecon.report import render_text
from jsrecon.verify import (attach_verification, classify_status,
                            resolve_endpoint, verify_endpoints)

JS = 'var a = "/api/live"; var b = "/api/gone";\n'
INDEX_HTML = '<html><head><script src="/app.js"></script></head></html>'


class _Handler(BaseHTTPRequestHandler):
    def _route(self):
        if self.path == "/":
            body = INDEX_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        elif self.path == "/app.js":
            body = JS.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        elif self.path == "/api/live":
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/api/gone":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    do_GET = _route
    do_HEAD = _route

    def log_message(self, *a):
        pass


import pytest


@pytest.fixture(scope="module")
def server():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


# --- unit ---------------------------------------------------------------

def test_classify_status():
    assert classify_status(200) == "live"
    assert classify_status(301) == "live"
    assert classify_status(403) == "live"  # answered, just forbidden
    assert classify_status(405) == "live"  # HEAD refused, route exists
    assert classify_status(404) == "dead"
    assert classify_status(410) == "dead"
    assert classify_status(500) == "unknown"
    assert classify_status(429) == "unknown"


def test_resolve_endpoint():
    page = "https://example.com/app/index.html"
    assert resolve_endpoint(page, "/api/users") == "https://example.com/api/users"
    assert resolve_endpoint(page, "https://other.com/x") == "https://other.com/x"
    assert resolve_endpoint(page, "//other.com/x") is None
    assert resolve_endpoint(page, "javascript:alert(1)") is None


def test_verify_with_stub_request():
    seen = []

    def fake_request(url, timeout, user_agent):
        seen.append(url)
        if url.endswith("/api/live"):
            return 200
        if url.endswith("/api/gone"):
            return 404
        raise ConnectionError("boom")

    results = verify_endpoints(
        ["/api/live", "/api/gone", "/api/down"], "https://example.com/",
        request=fake_request)
    assert results["/api/live"] == {"state": "live", "status": 200,
                                    "url": "https://example.com/api/live"}
    assert results["/api/gone"]["state"] == "dead"
    assert results["/api/gone"]["status"] == 404
    assert results["/api/down"]["state"] == "error"
    assert results["/api/down"]["status"] is None
    assert len(seen) == 3


def test_attach_verification_only_touches_endpoints():
    findings = [
        {"kind": "endpoint", "value": "/api/live", "detail": "",
         "sources": ["a.js"]},
        {"kind": "secret", "value": "x", "detail": "JWT", "sources": ["a.js"]},
    ]
    attach_verification(findings, {"/api/live": {"state": "live",
                                                 "status": 200,
                                                 "url": "https://e/api/live"}})
    assert findings[0]["verified"] == "live"
    assert findings[0]["http_status"] == 200
    assert "verified" not in findings[1]


def test_render_text_shows_verify_suffix():
    findings = [
        {"kind": "endpoint", "value": "/api/live", "detail": "",
         "sources": ["a.js"], "verified": "live", "http_status": 200},
        {"kind": "endpoint", "value": "/api/down", "detail": "",
         "sources": ["a.js"], "verified": "error", "http_status": None},
    ]
    out = render_text(findings, "https://example.com", 1, [])
    assert "[live 200]" in out
    assert "[error]" in out


# --- fixture server + cli -------------------------------------------------

def test_cli_verify_marks_live_and_dead(server, capsys):
    assert cli_main([server + "/", "--verify"]) == 0
    out = capsys.readouterr().out
    assert "/api/live [live 200]" in out
    assert "/api/gone [dead 404]" in out


def test_cli_verify_json_carries_status(server, capsys):
    import json
    assert cli_main([server + "/", "--verify", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    by_value = {f["value"]: f for f in data["findings"]
                if f["kind"] == "endpoint"}
    assert by_value["/api/live"]["verified"] == "live"
    assert by_value["/api/live"]["http_status"] == 200
    assert by_value["/api/gone"]["verified"] == "dead"


def test_cli_without_verify_has_no_suffix(server, capsys):
    assert cli_main([server + "/"]) == 0
    out = capsys.readouterr().out
    assert "[live" not in out and "[dead" not in out
