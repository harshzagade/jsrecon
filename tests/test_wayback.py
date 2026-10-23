"""--wayback mode tests — fixture server doubles as the CDX API + archive."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from jsrecon import fetch as fe
from jsrecon.cli import main as cli_main
from jsrecon.report import render_json, render_text

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

A_JS = 'var wayback_new = "/api/wayback";'
B_JS = 'var old = "AKIAIOSFODNN7EXAMPLE";'


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?", 1)[0]  # CDX queries carry a query string
        routes = {
            "/cdx/search/cdx": ("application/json", CDX_JSON),
            "/cdx-empty/search/cdx": ("application/json", "[]"),
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


# --- fetch_wayback_js --------------------------------------------------------

def test_newest_capture_per_url(server):
    scripts, errors = _wb(server)
    assert not errors
    urls = [s for s, _ in scripts]
    # newest capture of a.js (20240202), not the older one (20240101)
    assert (server + "/web/20240202000000id_/http://example.com/a.js") in urls
    assert not any("20240101000000" in u for u in urls)
    # newest first: b.js (20240303) before a.js (20240202)
    assert urls[0].endswith("http://example.com/b.js")


def test_wayback_content_scanned(server):
    scripts, _ = _wb(server)
    body = dict(scripts)
    key = server + "/web/20240202000000id_/http://example.com/a.js"
    assert "/api/wayback" in body[key]


def test_wayback_max_files(server):
    scripts, _ = _wb(server, max_files=1)
    assert len(scripts) == 1


def test_wayback_empty_cdx(server):
    scripts, errors = fe.fetch_wayback_js(
        "http://example.com/", timeout=5.0, user_agent="t",
        cdx_base=server + "/cdx-empty/search/cdx",
        archive_prefix=server + "/web/")
    assert scripts == [] and len(errors) == 1


def test_wayback_cdx_failure_is_fatal(server):
    with pytest.raises(fe.FetchError):
        fe.fetch_wayback_js(
            "http://example.com/", timeout=5.0, user_agent="t",
            cdx_base=server + "/nope/search/cdx",
            archive_prefix=server + "/web/")


def test_wayback_bad_url():
    with pytest.raises(fe.FetchError):
        fe.fetch_wayback_js("not-a-url", timeout=5.0, user_agent="t")


# --- report mode --------------------------------------------------------------

def test_render_wayback_mode():
    text = render_text([], "http://example.com/", 2, [], mode="wayback")
    assert "via the Wayback Machine" in text
    data = json.loads(render_json([], "http://example.com/", 2, [],
                                  mode="wayback"))
    assert data["mode"] == "wayback"
    data = json.loads(render_json([], "http://example.com/", 2, []))
    assert data["mode"] == "live"  # default unchanged


# --- cli -----------------------------------------------------------------------

def test_cli_wayback_rejects_inline(server):
    assert cli_main([server + "/", "--wayback", "--include-inline"]) == 2


def test_cli_wayback_max_invalid(server):
    assert cli_main([server + "/", "--wayback", "--wayback-max", "0"]) == 2
