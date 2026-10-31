"""Cookie attribute audit tests (STORAGE section detail notes)."""
from jsrecon.extract import dedupe
from jsrecon.report import render_text
from jsrecon.storage import audit_cookie_attributes, extract_storage


def _cookies(js):
    return {f["value"]: f["detail"]
            for f in extract_storage(js, "a.js")
            if f["value"].startswith("cookie:")}


def test_audit_missing_all():
    assert audit_cookie_attributes("session=abc") == (
        "Secure", "HttpOnly", "SameSite")


def test_audit_present_attrs_case_insensitive():
    assert audit_cookie_attributes(
        "session=abc; path=/; SECURE; samesite=Lax; httponly") == ()


def test_audit_partial_missing():
    assert audit_cookie_attributes("prefs=dark; Secure") == (
        "HttpOnly", "SameSite")


def test_audit_ignores_unrelated_attributes():
    assert audit_cookie_attributes(
        "session=abc; Path=/; Max-Age=3600; Secure; HttpOnly; SameSite=Strict") == ()


def test_cookie_detail_flags_missing_attrs():
    cookies = _cookies('document.cookie = "session=abc123; Path=/";')
    assert cookies == {"cookie:session":
                       "missing Secure, HttpOnly, SameSite"}


def test_cookie_all_attrs_no_detail():
    cookies = _cookies(
        'document.cookie = "session=abc; Secure; HttpOnly; SameSite=Lax";')
    assert cookies == {"cookie:session": ""}


def test_cookie_value_still_not_kept():
    findings = extract_storage(
        'document.cookie = "session=abc123; Path=/";', "a.js")
    assert not any("abc123" in f["value"] or "abc123" in f["detail"]
                   for f in findings)


def test_cookie_worst_case_kept_across_writes():
    # A secure write followed by an insecure write of the same cookie
    # must not hide the insecure one, and vice versa.
    js = ('document.cookie = "s=a; Secure; HttpOnly; SameSite=Lax";\n'
          'document.cookie = "s=b; Path=/";')
    assert _cookies(js) == {"cookie:s": "missing Secure, HttpOnly, SameSite"}
    js_reversed = ('document.cookie = "s=b; Path=/";\n'
                   'document.cookie = "s=a; Secure; HttpOnly; SameSite=Lax";')
    assert _cookies(js_reversed) == {
        "cookie:s": "missing Secure, HttpOnly, SameSite"}


def test_cookie_audit_in_text_report():
    findings = dedupe(extract_storage(
        'document.cookie = "session=abc; Path=/";', "a.js"))
    text = render_text(findings, "http://x/", 1, [])
    assert "missing Secure, HttpOnly, SameSite: cookie:session" in text


def test_storage_keys_unaffected():
    findings = extract_storage('localStorage.setItem("k", 1);', "a.js")
    assert findings == [{"kind": "storage", "value": "localStorage:k",
                         "detail": "", "source": "a.js"}]
