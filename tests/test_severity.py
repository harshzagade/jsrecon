"""Secret severity grading: pattern -> severity, header counts, dedupe."""
from jsrecon import extract as ex
from jsrecon.report import render_text

AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"  # concatenated: literal keys get redacted
STRIPE_LIVE = "sk_live_51H7xYzAbCdefGhIjKlMn"
PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
JWT = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0."
       "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c")
GOOGLE_KEY = "AIzaSyA1234567890abcdefghijklmnopqrstuv"  # AIza + 35 chars


def _secrets(js):
    return [f for f in ex.extract(js, "a.js") if f["kind"] == "secret"]


def test_high_patterns():
    assert ex.find_secret_detail(AWS_KEY) == ("AWS Access Key ID", "HIGH")
    assert ex.find_secret_detail(STRIPE_LIVE)[1] == "HIGH"
    assert ex.find_secret_detail(PRIVATE_KEY)[1] == "HIGH"
    assert ex.find_secret_detail("ghp_" + "a" * 36)[1] == "HIGH"


def test_med_and_low_patterns():
    assert ex.find_secret_detail(JWT) == ("JWT", "MED")
    assert ex.find_secret_detail("Bearer " + "x" * 20)[1] == "MED"
    assert ex.find_secret_detail(GOOGLE_KEY) == ("Google API key", "LOW")


def test_find_secret_still_returns_label_only():
    assert ex.find_secret(AWS_KEY) == "AWS Access Key ID"
    assert ex.find_secret("just a string") is None


def test_extract_attaches_severity():
    hits = {f["detail"]: f["severity"]
            for f in _secrets(f"var k = \"{AWS_KEY}\";\nvar t = \"{JWT}\";\n"
                            f"var g = \"{GOOGLE_KEY}\";")}
    assert hits == {"AWS Access Key ID": "HIGH", "JWT": "MED",
                    "Google API key": "LOW"}


def test_dedupe_preserves_severity():
    f1 = {"kind": "secret", "value": AWS_KEY, "detail": "AWS Access Key ID",
          "severity": "HIGH", "source": "a.js"}
    f2 = dict(f1, source="b.js")
    merged = ex.dedupe([f1, f2])
    assert len(merged) == 1
    assert merged[0]["severity"] == "HIGH"
    assert merged[0]["sources"] == ["a.js", "b.js"]


def test_text_header_counts_per_severity():
    findings = ex.dedupe(_secrets(
        f"var k = \"{AWS_KEY}\";\nvar t = \"{JWT}\";\n"
        f"var g = \"{GOOGLE_KEY}\";"))
    out = render_text(findings, "http://x/", 1, [])
    assert "[i] Secrets: 3 (HIGH: 1, MED: 1, LOW: 1)" in out
    assert "[!] [HIGH] AWS Access Key ID:" in out


def test_text_header_absent_without_secrets():
    out = render_text([], "http://x/", 0, [])
    assert "Secrets:" not in out
