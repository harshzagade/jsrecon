"""--html report tests — unit plus a fixture server end-to-end."""
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from jsrecon.cli import main as cli_main
from jsrecon.report import render_html

JS_A = 'var a = "/api/users";\n'
JS_B = 'var b = "/api/login";\n'
INDEX_HTML = """<html><head>
<script src="/a.js"></script>
<script src="/b.js"></script>
</head></html>"""


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        routes = {"/": ("text/html", INDEX_HTML),
                  "/a.js": ("application/javascript", JS_A),
                  "/b.js": ("application/javascript", JS_B)}
        if self.path in routes:
            ctype, body = routes[self.path]
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def server():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def _findings():
    return [
        {"kind": "endpoint", "value": "/api/users", "detail": "",
         "sources": ["http://x/a.js"]},
        {"kind": "endpoint", "value": "/api/login", "detail": "",
         "sources": ["http://x/b.js", "http://x/a.js"]},
        {"kind": "secret", "value": "tok", "detail": "JWT",
         "sources": ["http://x/a.js"]},
    ]


def test_one_details_section_per_script_file():
    out = render_html(_findings(), "http://x", 2, [])
    assert out.count("<details") == 2
    assert "http://x/a.js (2 finding(s))" in out
    assert "http://x/b.js (1 finding(s))" in out
    # The login finding lives under b.js but notes its other source.
    assert "also in: http://x/a.js" in out


def test_values_are_escaped():
    findings = [{"kind": "interesting", "value": "<img onerror=alert(1)>",
                 "detail": "x", "sources": ["http://x/a.js"]}]
    out = render_html(findings, "http://x", 1, [])
    assert "<img onerror" not in out
    assert "&lt;img onerror=alert(1)&gt;" in out


def test_single_file_no_external_resources():
    out = render_html(_findings(), "http://x", 2, [])
    assert "<link" not in out and "<script" not in out
    assert out.startswith("<!doctype html>")


def test_verify_suffix_and_empty_state():
    findings = [{"kind": "endpoint", "value": "/api/users", "detail": "",
                 "sources": ["http://x/a.js"], "verified": "live",
                 "http_status": 200}]
    out = render_html(findings, "http://x", 1, [])
    assert "[live 200]" in out
    assert "(no findings)" in render_html([], "http://x", 0, [])


def test_cli_html_groups_by_script_file(server, capsys):
    assert cli_main([server + "/", "--html"]) == 0
    out = capsys.readouterr().out
    assert out.count("<details") == 2
    assert "/api/users" in out and "/api/login" in out
    assert "a.js (1 finding(s))" in out


def test_cli_html_rejects_json_combo(server, capsys):
    assert cli_main([server + "/", "--html", "--json"]) == 2
    assert "mutually exclusive" in capsys.readouterr().err
