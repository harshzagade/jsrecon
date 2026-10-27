"""Host-grouping tests — grouping rules and text-report rendering."""
from jsrecon.hosts import endpoint_host, group_endpoints
from jsrecon.report import render_text


def _endpoint(value):
    return {"kind": "endpoint", "value": value, "detail": "",
            "sources": ["a.js"]}


def test_endpoint_host():
    assert endpoint_host("https://API.Example.com/charge") == "api.example.com"
    assert endpoint_host("wss://ws.example.com/feed") == "ws.example.com"
    assert endpoint_host("https://example.com:8443/x") == "example.com"
    assert endpoint_host("/api/users") is None
    assert endpoint_host("//cdn.example.com/x.js") is None


def test_group_relative_first_then_hosts_in_first_seen_order():
    findings = [_endpoint("https://cdn.example.com/a"),
                _endpoint("/api/users"),
                _endpoint("https://api.example.com/b"),
                _endpoint("https://cdn.example.com/c")]
    blocks = group_endpoints(findings, "https://example.com")
    assert [label for label, _ in blocks] == [
        None, "cdn.example.com", "api.example.com"]
    assert [f["value"] for _, b in blocks for f in b] == [
        "/api/users", "https://cdn.example.com/a",
        "https://cdn.example.com/c", "https://api.example.com/b"]


def test_group_marks_the_scanned_sites_own_host():
    blocks = group_endpoints(
        [_endpoint("https://example.com/a"),
         _endpoint("https://other.com/b")],
        "https://example.com/page")
    assert [label for label, _ in blocks] == [
        "example.com (this site)", "other.com"]


def test_render_text_groups_absolute_urls_under_host_headers():
    findings = [_endpoint("/api/users"),
                _endpoint("https://api.payments.example.com/charge"),
                _endpoint("https://api.payments.example.com/refund"),
                _endpoint("https://example.com/direct")]
    out = render_text(findings, "https://example.com", 1, [])
    assert "== ENDPOINTS (4) ==" in out
    # Relative path stays flat; absolute URLs sit under host headers.
    assert "\n  /api/users\n" in out
    assert "  api.payments.example.com:" in out
    assert "    https://api.payments.example.com/charge" in out
    assert "  example.com (this site):" in out
    assert "    https://example.com/direct" in out


def test_render_text_relative_only_report_unchanged():
    findings = [_endpoint("/api/users"), _endpoint("/api/login")]
    out = render_text(findings, "https://example.com", 1, [])
    assert "api.payments" not in out
    assert "  /api/users\n" in out
    assert "  /api/login\n" in out
    # No host subheaders appear when nothing is absolute.
    assert "  example.com" not in out
