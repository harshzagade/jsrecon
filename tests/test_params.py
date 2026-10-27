"""Query-param harvest tests — parsing, collection, report output."""
import json

from jsrecon.params import collect_params, parse_query_params
from jsrecon.report import render_html, render_json, render_text


def _endpoint(value):
    return {"kind": "endpoint", "value": value, "detail": "",
            "sources": ["a.js"]}


def test_parse_query_params():
    assert parse_query_params("/api/users?id=1&name=x") == ["id", "name"]
    assert parse_query_params("/api/search?q=") == ["q"]
    assert parse_query_params("/api/search?flag") == ["flag"]
    assert parse_query_params("/api/users") == []
    assert parse_query_params("/api/users?=x&id=1") == ["id"]
    # Percent-encoded names decode to what the server sees.
    assert parse_query_params("/api/?user%5Fid=1") == ["user_id"]


def test_collect_counts_distinct_endpoints_with_first_example():
    findings = [
        _endpoint("/api/users?id=1"),
        _endpoint("/api/users?id=2&verbose=1"),
        _endpoint("/api/posts?id=9"),
        _endpoint("/search?q=x"),
    ]
    params = collect_params(findings)
    by_name = {p["param"]: p for p in params}
    assert by_name["id"]["count"] == 3
    assert by_name["id"]["example"] == "/api/users?id=1"
    assert by_name["verbose"]["count"] == 1
    assert by_name["q"]["count"] == 1
    # Most common first, ties broken alphabetically.
    assert [p["param"] for p in params] == ["id", "q", "verbose"]


def test_collect_ignores_non_endpoints_and_repeated_param_in_one_url():
    findings = [
        _endpoint("/api/?a=1&a=2"),  # one endpoint, not two hits
        {"kind": "secret", "value": "/api/?b=1", "detail": "x",
         "sources": ["a.js"]},
    ]
    params = collect_params(findings)
    assert params == [{"param": "a", "count": 1, "example": "/api/?a=1&a=2"}]


def test_render_text_params_section():
    out = render_text([_endpoint("/api/users?id=1"),
                       _endpoint("/api/posts?id=2&tag=x")],
                      "https://example.com", 1, [])
    assert "== PARAMS (2) ==" in out
    assert "  id (2 endpoint(s)): /api/users?id=1" in out
    assert "  tag (1 endpoint(s)): /api/posts?id=2&tag=x" in out


def test_render_text_no_params_section_without_query_strings():
    out = render_text([_endpoint("/api/users")], "https://example.com", 1, [])
    assert "== PARAMS" not in out


def test_render_text_params_hidden_when_endpoints_filtered_out():
    findings = [_endpoint("/api/users?id=1")]
    out = render_text(findings, "https://example.com", 1, [],
                      only=("secret",))
    assert "== PARAMS" not in out


def test_render_json_and_html_carry_params():
    findings = [_endpoint("/api/users?id=1")]
    data = json.loads(render_json(findings, "https://example.com", 1, []))
    assert data["query_params"] == [{"param": "id", "count": 1,
                                     "example": "/api/users?id=1"}]
    out = render_html(findings, "https://example.com", 1, [])
    assert "<h2>Query parameters</h2>" in out
    assert "id (1 endpoint(s))" in out
