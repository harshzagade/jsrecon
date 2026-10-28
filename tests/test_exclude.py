"""--exclude script filter: fixture HTTP server, no real targets."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from jsrecon.cli import main as cli_main

APP_JS = 'var API = "/api/app-only";\n'
VENDOR_JS = 'var V = "/api/vendor-only";\n'
ANALYTICS_JS = 'var T = "/api/analytics-only";\n'
INDEX_HTML = """<html><head>
<script src="/static/app.js"></script>
<script src="/vendor.js"></script>
<script src="/analytics.js"></script>
</head></html>"""


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        routes = {
            "/": ("text/html", INDEX_HTML),
            "/static/app.js": ("application/javascript", APP_JS),
            "/vendor.js": ("application/javascript", VENDOR_JS),
            "/analytics.js": ("application/javascript", ANALYTICS_JS),
        }
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


def test_exclude_drops_matching_script(server, capsys):
    assert cli_main([server + "/", "--exclude", "vendor"]) == 0
    out = capsys.readouterr().out
    assert "/api/app-only" in out
    assert "/api/vendor-only" not in out
    assert "[i] 1 script(s) excluded by --exclude" in out
    assert "(2 script file(s))" in out


def test_exclude_repeatable(server, capsys):
    assert cli_main([server + "/", "--exclude", "vendor",
                     "--exclude", "analytics"]) == 0
    out = capsys.readouterr().out
    assert "/api/app-only" in out
    assert "/api/vendor-only" not in out
    assert "/api/analytics-only" not in out
    assert "[i] 2 script(s) excluded by --exclude" in out


def test_exclude_regex_matches_url(server, capsys):
    assert cli_main([server + "/", "--exclude", r"analytics\.js$"]) == 0
    out = capsys.readouterr().out
    assert "/api/analytics-only" not in out
    assert "/api/vendor-only" in out


def test_exclude_no_match_changes_nothing(server, capsys):
    assert cli_main([server + "/", "--exclude", "nomatch"]) == 0
    out = capsys.readouterr().out
    assert "/api/app-only" in out and "/api/vendor-only" in out
    assert "excluded by --exclude" not in out


def test_exclude_bad_regex_exits_2(server, capsys):
    assert cli_main([server + "/", "--exclude", "(["]) == 2
    assert "not valid regex" in capsys.readouterr().err


def test_exclude_json_field(server, capsys):
    assert cli_main([server + "/", "--exclude", "vendor", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["scripts_excluded"] == 1
    assert data["scripts_fetched"] == 2
