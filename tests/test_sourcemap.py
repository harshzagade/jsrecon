"""Source-map tests — fixture HTTP server, no real targets."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from jsrecon import sourcemap as sm
from jsrecon.cli import main as cli_main

MAP_JSON = json.dumps({
    "version": 3,
    "sources": ["webpack:///./src/admin/panel.js", "src/utils/auth.js"],
    "sourcesContent": [
        'var ep = "/api/admin/secret"; var k = "AKIAIOSFODNN7EXAMPLE";',
        "var helper = 1;",
    ],
    "names": [],
    "mappings": "AAAA",
})

MAPPED_JS = 'var x = "/api/mapped";\n//# sourceMappingURL=app.js.map\n'
LEGACY_JS = 'var x = 1;\n//@ sourceMappingURL=legacy.js.map\n'
BLOCK_JS = 'var x = 1;\n/*# sourceMappingURL=block.js.map */\n'
BUNDLE_JS = 'var y = "/api/bundle";\n'  # no comment -> <file>.js.map probe
BUNDLE_MAP = json.dumps({
    "version": 3,
    "sources": ["src/bundle/main.js"],
    "names": [],
    "mappings": "AAAA",
})
PLAIN_JS = 'var z = "/api/plain";\n'  # no map anywhere

import base64 as _b64
INLINE_MAP = json.dumps({
    "version": 3, "sources": ["src/inline/app.js"],
    "names": [], "mappings": "AAAA",
})
INLINE_JS = ('var w = "/api/inline";\n//# sourceMappingURL=data:application/json'
             ';base64,' + _b64.b64encode(INLINE_MAP.encode()).decode() + '\n')

PAGE_HTML = ('<html><head><script src="/mapped/app.js"></script>'
             '</head><body></body></html>')


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        routes = {
            "/page/": ("text/html", PAGE_HTML),
            "/mapped/app.js": ("application/javascript", MAPPED_JS),
            "/mapped/app.js.map": ("application/json", MAP_JSON),
            "/mapped2/bundle.js": ("application/javascript", BUNDLE_JS),
            "/mapped2/bundle.js.map": ("application/json", BUNDLE_MAP),
            "/plain.js": ("application/javascript", PLAIN_JS),
            "/inline.js": ("application/javascript", INLINE_JS),
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


# --- comment parsing ------------------------------------------------------

def test_find_mapping_url_forms():
    assert sm.find_mapping_url(MAPPED_JS) == "app.js.map"
    assert sm.find_mapping_url(LEGACY_JS) == "legacy.js.map"
    assert sm.find_mapping_url(BLOCK_JS) == "block.js.map"
    assert sm.find_mapping_url(PLAIN_JS) is None


# --- fetch_map ------------------------------------------------------------

def test_fetch_map_from_comment(server):
    got = sm.fetch_map(server + "/mapped/app.js", MAPPED_JS, 5.0, "t")
    assert got is not None
    map_url, paths, contents = got
    assert map_url == server + "/mapped/app.js.map"
    assert paths == ["webpack:///./src/admin/panel.js", "src/utils/auth.js"]
    assert len(contents) == 2 and contents[0][0].endswith("panel.js")


def test_fetch_map_probe_fallback(server):
    got = sm.fetch_map(server + "/mapped2/bundle.js", BUNDLE_JS, 5.0, "t")
    assert got is not None
    map_url, paths, _ = got
    assert map_url == server + "/mapped2/bundle.js.map"
    assert paths == ["src/bundle/main.js"]


def test_fetch_map_missing_is_silent(server):
    assert sm.fetch_map(server + "/plain.js", PLAIN_JS, 5.0, "t") is None


def test_fetch_map_inline_data_url(server):
    got = sm.fetch_map(server + "/inline.js", INLINE_JS, 5.0, "t")
    assert got is not None
    map_url, paths, _ = got
    assert "inline sourceMappingURL" in map_url
    assert paths == ["src/inline/app.js"]


def test_sourcemap_findings_kind(server):
    fs = sm.sourcemap_findings(server + "/mapped/app.js",
                               server + "/mapped/app.js.map",
                               ["a.js", "a.js", "b.js"])
    assert len(fs) == 2  # deduped, order kept
    assert all(f["kind"] == "sourcemap" for f in fs)
    assert fs[0]["value"] == "a.js"


# --- cli -------------------------------------------------------------------

def test_cli_sourcemap_section(server, capsys):
    assert cli_main([server + "/page/"]) == 0
    out = capsys.readouterr().out
    assert "SOURCE MAPS" in out
    assert "src/admin/panel.js" in out          # original path from the map
    assert "/api/admin/secret" in out           # endpoint from sourcesContent
    assert "AKIAIOSFODNN7EXAMPLE" in out         # secret from sourcesContent


def test_cli_no_sourcemaps(server, capsys):
    assert cli_main([server + "/page/", "--no-sourcemaps"]) == 0
    out = capsys.readouterr().out
    assert "== SOURCE MAPS (0) ==" in out  # section renders empty, nothing probed
    assert "src/admin/panel.js" not in out
    assert "/api/admin/secret" not in out  # sourcesContent not scanned
    assert "/api/mapped" in out  # base scan still works
