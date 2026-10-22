"""JsRecon tests — fixture HTTP server, no real targets."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from jsrecon import extract as ex
from jsrecon import fetch as fe
from jsrecon.cli import main as cli_main

APP_JS = """
var API = "/api/v1/users";
var LOGIN = '/api/v1/login';
var GQL = "/graphql";
var PAY = "https://api.payments.example.com/charge";
var cfg = {api_key: "sk_test_51H7xYzAbC"};
var aws = "AKIAIOSFODNN7EXAMPLE";
var blob = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Qgc3RyaW5nIHdpdGggZW5vdWdoIGNoYXJz";
var noise = "hello";
"""

VENDOR_JS = 'var CDN = "https://cdn.example.com/lib.js";\nvar EP = "/api/v1/users";\n'

INDEX_HTML = """<html><head>
<script src="/static/app.js"></script>
<script src="vendor.js"></script>
<script src="data:text/javascript,alert(1)"></script>
</head><body>
<script>var r = "/inline/route";</script>
</body></html>"""


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        routes = {
            "/": ("text/html", INDEX_HTML),
            "/broken/": ("text/html",
                         '<html><head><script src="/nope.js"></script>'
                         '<script src="/vendor.js"></script></head></html>'),
            "/static/app.js": ("application/javascript", APP_JS),
            "/vendor.js": ("application/javascript", VENDOR_JS),
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


# --- fetch ---------------------------------------------------------------

def test_script_srcs_resolved(server):
    scripts, errors = fe.fetch_js_sources(server + "/")
    urls = [s for s, _ in scripts]
    assert not errors
    assert server + "/static/app.js" in urls
    assert server + "/vendor.js" in urls  # relative src resolved


def test_data_url_skipped(server):
    scripts, _ = fe.fetch_js_sources(server + "/")
    assert all(not s.startswith("data:") for s, _ in scripts)


def test_missing_script_reported_not_fatal(server):
    scripts, errors = fe.fetch_js_sources(server + "/broken/")
    assert len(scripts) == 1  # vendor.js still fetched
    assert len(errors) == 1 and "nope.js" in errors[0]


def test_inline_blocks_opt_in(server):
    scripts, _ = fe.fetch_js_sources(server + "/", include_inline=True)
    inline = [s for s, _ in scripts if "#inline-" in s]
    assert len(inline) == 1
    scripts2, _ = fe.fetch_js_sources(server + "/")
    assert not any("#inline-" in s for s, _ in scripts2)


# --- extract -------------------------------------------------------------

def test_endpoint_classification():
    assert ex.is_endpoint("https://a.example/x")
    assert ex.is_endpoint("/api/v1/users")
    assert not ex.is_endpoint("//comment")
    assert not ex.is_endpoint("/")
    assert not ex.is_endpoint("hello")


def test_secret_patterns():
    assert ex.find_secret("AKIAIOSFODNN7EXAMPLE") == "AWS Access Key ID"
    assert ex.find_secret("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c")
    assert ex.find_secret("just a string") is None


def test_assignment_secret_needs_context():
    hits = ex.extract('var cfg = {api_key: "sk_test_51H7xYzAbC"};', "s.js")
    secrets = [h for h in hits if h["kind"] == "secret"]
    assert any(h["detail"] == "Generic secret assignment" for h in secrets)


def test_interesting_blobs():
    assert ex.is_interesting("a!b@c#d$e%f^g&h*i(j)") is None  # symbols: not blob-shaped
    assert ex.is_interesting("x" * 31) is None  # too short
    note = ex.is_interesting("aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Qgc3RyaW5nIHdpdGggZW5vdWdoIGNoYXJz")
    assert note and "base64" in note
    note = ex.is_interesting("deadbeef" * 8)
    assert note and "hex" in note


def test_dedupe_merges_sources():
    f1 = {"kind": "endpoint", "value": "/x", "detail": "", "source": "a.js"}
    f2 = {"kind": "endpoint", "value": "/x", "detail": "", "source": "b.js"}
    out = ex.dedupe([f1, f2])
    assert len(out) == 1 and set(out[0]["sources"]) == {"a.js", "b.js"}


# --- cli -----------------------------------------------------------------

def test_cli_end_to_end(server, capsys):
    assert cli_main([server + "/"]) == 0
    out = capsys.readouterr().out
    assert "/api/v1/users" in out
    assert "AKIAIOSFODNN7EXAMPLE" in out
    assert "sk_test_51H7xYzAbC" in out


def test_cli_secrets_only(server, capsys):
    assert cli_main([server + "/", "--secrets-only"]) == 0
    out = capsys.readouterr().out
    assert "SECRETS" in out and "ENDPOINTS" not in out


def test_cli_json(server, capsys):
    assert cli_main([server + "/", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["target"] == server + "/"
    assert data["scripts_fetched"] == 2
    kinds = {f["kind"] for f in data["findings"]}
    assert {"endpoint", "secret"} <= kinds


def test_cli_bad_url():
    assert cli_main(["http://127.0.0.1:1/"]) == 1
