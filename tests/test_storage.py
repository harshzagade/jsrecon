"""Storage/cookie key harvest tests."""
from jsrecon.extract import dedupe
from jsrecon.report import build_stats, render_text
from jsrecon.storage import extract_storage


def _values(js):
    return sorted(f["value"] for f in extract_storage(js, "a.js"))


def test_storage_method_calls():
    js = ('localStorage.setItem("auth_token", t);\n'
          'const u = sessionStorage.getItem("user_id");\n'
          'localStorage.removeItem("old_pref");')
    assert _values(js) == ["localStorage:auth_token",
                           "localStorage:old_pref",
                           "sessionStorage:user_id"]


def test_storage_bracket_access():
    js = ("const t = localStorage['session_key'];\n"
          'sessionStorage["theme"] = "dark";')
    assert _values(js) == ["localStorage:session_key",
                           "sessionStorage:theme"]


def test_storage_dedupes_within_file():
    js = ('localStorage.setItem("k", 1); localStorage.getItem("k");')
    assert _values(js) == ["localStorage:k"]


def test_storage_same_key_two_stores_stays_two_findings():
    js = ('localStorage.setItem("token", a);'
          'sessionStorage.setItem("token", b);')
    findings = dedupe(extract_storage(js, "a.js"))
    assert sorted(f["value"] for f in findings) == [
        "localStorage:token", "sessionStorage:token"]


def test_storage_template_keys_skipped():
    js = "localStorage.getItem(`user_${id}`);"
    assert _values(js) == []


def test_cookie_name_only():
    js = ('document.cookie = "session=abc123; Path=/; Secure";\n'
          "document.cookie = 'prefs=dark; Max-Age=3600';")
    assert _values(js) == ["cookie:prefs", "cookie:session"]


def test_cookie_value_and_attributes_not_kept():
    vals = _values('document.cookie = "session=abc123; Path=/";')
    assert vals == ["cookie:session"]
    assert not any("abc123" in v or "Path" in v for v in vals)


def test_storage_report_section_and_stats():
    findings = dedupe(extract_storage(
        'localStorage.setItem("auth_token", t);', "a.js"))
    text = render_text(findings, "http://example.com/", 1, [])
    assert "== STORAGE (1) ==" in text
    assert "localStorage:auth_token" in text
    assert build_stats(findings, 1)["findings_by_kind"]["storage"] == 1
