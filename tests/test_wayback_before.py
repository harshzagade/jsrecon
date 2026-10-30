"""--wayback-before tests — fixture server doubles as CDX API + archive."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from jsrecon import fetch as fe
from jsrecon.cli import main as cli_main

CDX_JSON = json.dumps([
    ["urlkey", "timestamp", "original", "mimetype", "statuscode",
     "digest", "length"],
    ["example,com)/a.js", "20240101000000", "http://example.com/a.js",
     "application/javascript", "200", "aaa", "100"],
    ["example,com)/a.js", "20240202000000", "http://example.com/a.js",
     "application/javascript", "200", "bbb", "110"],
    ["example,com)/b.js", "20240303000000", "http://example.com/b.js",
     "application/javascript", "200", "ccc", "50"],
])

A_JS = 'var old = "/api/old";'
B_JS = 'var new_thing = "/api/new";'


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        routes = {
            "/cdx/search/cdx": ("application/json", CDX_JSON),
            "/web/20240202000000id_/http://example.com/a.js":
                ("application/javascript", A_JS),
            "/web/20240303000000id_/http://example.com/b.js":
                ("application/javascript", B_JS),
        }
        if path in routes:
            ctype, body = routes[path]
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


def _wb(server, **kw):
    return fe.fetch_wayback_js(
        "http://example.com/", timeout=5.0, user_agent="t",
        cdx_base=server + "/cdx/search/cdx",
        archive_prefix=server + "/web/", **kw)


def test_wayback_before_keeps_only_older_captures(server):
    scripts, errors = _wb(server, before="2024-02-15")
    assert not errors
    urls = [s for s, _ in scripts]
    # a.js newest at-or-before the cutoff is 20240202; b.js (20240303)
    # is newer than the cutoff and drops out entirely.
    assert urls == [server + "/web/20240202000000id_/http://example.com/a.js"]


def test_wayback_before_whole_day_included(server):
    # 2024-02-02's capture is at 00:00:00 — the cutoff day itself counts.
    scripts, _ = _wb(server, before="2024-02-02")
    assert len(scripts) == 1


def test_wayback_before_nothing_old_enough(server):
    scripts, errors = _wb(server, before="2023-12-31")
    assert scripts == [] and len(errors) == 1


def test_wayback_before_bad_date():
    with pytest.raises(ValueError):
        fe.fetch_wayback_js("http://example.com/", before="15-02-2024")


def test_cli_wayback_before_requires_wayback():
    assert cli_main(["http://example.com/", "--wayback-before",
                     "2024-02-15"]) == 2


def test_cli_wayback_before_bad_date():
    assert cli_main(["http://example.com/", "--wayback",
                     "--wayback-before", "not-a-date"]) == 2
