"""JWT claim decoding tests (decode only, never signature-verified)."""
import base64
import json

from jsrecon import extract as ex
from jsrecon.jwt import decode_jwt_claims
from jsrecon.report import render_html, render_text


def _b64(obj):
    raw = json.dumps(obj).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _token(payload, signature="sig"):
    return f"eyJhbGciOiJIUzI1NiJ9.{_b64(payload)}.{signature}"


def test_decode_lists_claims_in_payload_order():
    token = _token({"sub": "42", "role": "admin", "exp": 999})
    assert decode_jwt_claims(token) == ["sub", "role", "exp"]


def test_decode_tampered_signature_still_decodes():
    # Decode only: the signature is never checked, so a token with a
    # garbage signature still yields its (untrusted) claim names.
    token = _token({"sub": "42"}) + "tampered"
    assert decode_jwt_claims(token) == ["sub"]


def test_decode_rejects_malformed_tokens():
    assert decode_jwt_claims("not-a-jwt") is None
    assert decode_jwt_claims("a.b") is None
    assert decode_jwt_claims("a..c") is None
    assert decode_jwt_claims("eyJhbGciOiJIUzI1NiJ9.!!!.sig") is None


def test_decode_rejects_non_object_payloads():
    assert decode_jwt_claims(_token(["sub", "role"])) is None
    assert decode_jwt_claims(_token("just a string")) is None


def test_decode_rejects_non_json_payload():
    raw = base64.urlsafe_b64encode(b"not json").decode().rstrip("=")
    assert decode_jwt_claims(f"eyJhbGciOiJIUzI1NiJ9.{raw}.sig") is None


def test_extract_attaches_claims_to_jwt_secret():
    token = _token({"sub": "42", "role": "admin"})
    findings = [f for f in ex.extract(f'var t = "{token}";', "a.js")
                if f["kind"] == "secret"]
    assert len(findings) == 1
    assert findings[0]["detail"] == "JWT"
    assert findings[0]["severity"] == "MED"
    assert findings[0]["claims"] == ["sub", "role"]


def test_extract_undecodable_jwt_has_no_claims_field():
    # Payload segment "eyJhYmM" is base64url for '{"abc' — it matches
    # the JWT shape but is not valid JSON, so the secret is reported
    # with no claim list attached.
    findings = [f for f in ex.extract(
        'var t = "eyJhbGciOiJIUzI1NiJ9.eyJhYmM.sig";', "a.js")
        if f["kind"] == "secret"]
    assert len(findings) == 1
    assert findings[0]["detail"] == "JWT"
    assert "claims" not in findings[0]


def test_dedupe_preserves_claims():
    token = _token({"sub": "42"})
    f1 = {"kind": "secret", "value": token, "detail": "JWT",
          "severity": "MED", "claims": ["sub"], "source": "a.js"}
    merged = ex.dedupe([f1, dict(f1, source="b.js")])
    assert len(merged) == 1
    assert merged[0]["claims"] == ["sub"]
    assert merged[0]["sources"] == ["a.js", "b.js"]


def test_report_shows_claims():
    token = _token({"sub": "42", "role": "admin"})
    findings = ex.dedupe([f for f in ex.extract(f'var t = "{token}";', "a.js")
                          if f["kind"] == "secret"])
    text = render_text(findings, "http://x/", 1, [])
    assert "(claims: sub, role)" in text
    html_out = render_html(findings, "http://x/", 1, [])
    assert "(claims: sub, role)" in html_out
