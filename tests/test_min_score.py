"""--min-score scoring tests: unit rules + CLI end-to-end."""
from jsrecon import extract as ex
from jsrecon.cli import main as cli_main

SRC = "https://target.com/app.js"


def _endpoint(value):
    findings = ex.extract(f'var u = "{value}";', SRC)
    eps = [f for f in findings if f["kind"] == "endpoint"]
    assert len(eps) == 1, f"expected one endpoint for {value!r}"
    return eps[0]


# --- scoring rules ---------------------------------------------------------

def test_api_route_scores_high():
    assert ex.score_endpoint("/api/v1/users") >= 2


def test_versioned_route_scores_high():
    assert ex.score_endpoint("/v2/orders") >= 2


def test_graphql_scores():
    assert ex.score_endpoint("/graphql") >= 2


def test_query_string_adds_a_point():
    assert ex.score_endpoint("/search?q=x") > ex.score_endpoint("/search")


def test_handler_extension_scores():
    assert ex.score_endpoint("/data.json") > ex.score_endpoint("/data")


def test_favicon_scores_negative():
    assert ex.score_endpoint("/favicon.ico") < 0


def test_static_asset_scores_negative():
    assert ex.score_endpoint("/static/app.png") < 0
    assert ex.score_endpoint("/fonts/a.woff2") < 0


def test_single_char_path_penalized():
    assert ex.score_endpoint("/a") < 0


def test_admin_segment_adds_a_point():
    assert ex.score_endpoint("/admin/panel") > ex.score_endpoint("/user/panel")


def test_extract_attaches_score():
    f = _endpoint("/api/v1/users")
    assert f["score"] == ex.score_endpoint("/api/v1/users")


def test_dedupe_preserves_score():
    f1 = _endpoint("/api/v1/users")
    merged = ex.dedupe([f1, dict(f1, source="other.js")])
    assert len(merged) == 1
    assert merged[0]["score"] == f1["score"]


# --- CLI -------------------------------------------------------------------

def test_cli_min_score_rejects_negative(capsys):
    assert cli_main(["https://example.com", "--min-score", "-1"]) == 2
    assert "must be >= 0" in capsys.readouterr().err


def test_cli_min_score_zero_keeps_all(capsys):
    out = None
    from jsrecon.report import render_text
    findings = ex.dedupe(ex.extract('var a = "/favicon.ico";', SRC))
    assert any(f["value"] == "/favicon.ico" for f in findings)
    # render with min_score=0 shows the noisy hit
    out = render_text(findings, "https://target.com", 1, [])
    assert "favicon.ico" in out


def test_cli_min_score_hides_noise(capsys, monkeypatch):
    from jsrecon import cli as cli_mod
    js = ('var n = "/favicon.ico";\n'
          'var a = "/api/v1/users";\n')
    monkeypatch.setattr(cli_mod, "fetch_js_sources",
                        lambda *a, **k: ([("app.js", js)], []))
    monkeypatch.setattr(cli_mod.sourcemap, "fetch_map", lambda *a: None)
    assert cli_main(["https://target.com", "--min-score", "2"]) == 0
    out = capsys.readouterr().out
    assert "/api/v1/users" in out
    assert "favicon.ico" not in out
    assert "hidden by --min-score 2" in out


def test_cli_min_score_json_reports_dropped(capsys, monkeypatch):
    import json
    from jsrecon import cli as cli_mod
    js = 'var n = "/favicon.ico";\n'
    monkeypatch.setattr(cli_mod, "fetch_js_sources",
                        lambda *a, **k: ([("app.js", js)], []))
    monkeypatch.setattr(cli_mod.sourcemap, "fetch_map", lambda *a: None)
    assert cli_main(["https://target.com", "--min-score", "1", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["endpoints_dropped"] == 1
    assert data["min_score"] == 1
    assert not any(f["value"] == "/favicon.ico"
                   for f in data["findings"])
