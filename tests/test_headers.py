"""--headers check tests — unit tests plus a fixture HTTP server."""
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from jsrecon import fetch as fe
from jsrecon.cli import main as cli_main
from jsrecon.headers import check_js_headers

GOOD_JS = 'var a = "/api/v1/ok";\n'
BAD_JS = 'var b = "/api/v1/bad";\n'

INDEX_HTML = """<html><head>
<script src="/good.js"></script>
<script src="/bad.js"></script>
</head></html>"""


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        routes = {
            "/": ("text/html", INDEX_HTML, {}),
            "/good.js": ("application/javascript; charset=utf-8", GOOD_JS, {}),
            "/bad.js": ("text/plain", BAD_JS,
                         {"Access-Control-Allow-Origin": "*"}),
        }
        if self.path in routes:
            ctype, body, extra = routes[self.path]
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            for k, v in extra.items():
                self.send_header(k, v)
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


# --- unit ---------------------------------------------------------------

def test_accepted_content_types():
    for ctype in ("application/javascript",
                  "text/javascript",
                  "application/x-javascript",
                  "application/javascript; charset=utf-8",
                  "Text/JavaScript"):
        assert check_js_headers("a.js", ctype) == [], ctype


def test_missing_and_wrong_content_type():
    hits = check_js_headers("a.js", "")
    assert len(hits) == 1 and hits[0]["value"] == "missing Content-Type"
    hits = check_js_headers("a.js", "text/html")
    assert any("text/html" in h["value"] for h in hits)
    assert hits[0]["detail"] == "content-type"


def test_permissive_cors():
    assert check_js_headers("a.js", "application/javascript") == []
    hits = check_js_headers("a.js", "application/javascript", "*")
    assert len(hits) == 1 and "Allow-Origin: *" in hits[0]["value"]
    assert hits[0]["detail"] == "cors"
    # A specific origin is fine.
    assert check_js_headers("a.js", "application/javascript",
                            "https://app.example.com") == []


def test_wildcard_plus_credentials_flagged_together():
    hits = check_js_headers("a.js", "application/javascript", "*", "true")
    assert len(hits) == 1
    assert "Allow-Credentials: true" in hits[0]["value"]


# --- fetch + cli ----------------------------------------------------------

def test_headers_out_populated(server):
    headers_out = {}
    scripts, errors = fe.fetch_js_sources(server + "/", headers_out=headers_out)
    assert not errors and len(scripts) == 2
    assert headers_out[server + "/good.js"]["content_type"].startswith(
        "application/javascript")
    bad = headers_out[server + "/bad.js"]
    assert bad["content_type"] == "text/plain"
    assert bad["allow_origin"] == "*"


def test_cli_headers_flag(server, capsys):
    assert cli_main([server + "/", "--headers"]) == 0
    out = capsys.readouterr().out
    assert "HEADERS" in out
    assert "text/plain" in out
    assert "Allow-Origin: *" in out
    assert "good.js" in out  # bad file named as the finding's source


def test_cli_without_headers_flag_hides_findings(server, capsys):
    # Report sections always render (even empty); the flag gates findings.
    assert cli_main([server + "/"]) == 0
    out = capsys.readouterr().out
    assert "text/plain" not in out
    assert "Allow-Origin" not in out
    assert "== HEADERS (0) ==" in out
