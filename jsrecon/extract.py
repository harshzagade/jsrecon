"""Classify quoted strings pulled out of JavaScript.

Three buckets:
- endpoint: absolute URL or root-relative path that looks like a route
- secret:   matches a known credential/token pattern
- interesting: long base64/hex blobs that smell like encoded data
"""
import re

QUOTED_RE = re.compile(r"[\"'`]([^\"'`]{1,500})[\"'`]")

# (label, severity, compiled pattern) — order matters: first match wins.
# Severity: HIGH = live credential usable as-is (cloud keys, private keys,
# personal tokens); MED = session/assignment secrets whose exploitability
# depends on context; LOW = keys commonly embedded in public clients
# (Google API keys are usually referrer-restricted, but still worth a look).
SECRET_PATTERNS = [
    ("AWS Access Key ID", "HIGH",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS secret key assignment", "HIGH",
     re.compile(r"(?i)aws[_-]?secret[^A-Za-z0-9]{0,4}[A-Za-z0-9/+=]{32,}")),
    ("Google API key", "LOW",
     re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("GitHub token", "HIGH",
     re.compile(r"\bgh[op]_[A-Za-z0-9]{36}\b")),
    ("Slack token", "HIGH",
     re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
    ("Stripe secret key", "HIGH",
     re.compile(r"\bsk_(live|test)_[A-Za-z0-9]{16,}\b")),
    ("JWT", "MED",
     re.compile(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")),
    ("Bearer token", "MED",
     re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/=]{16,}")),
    ("Private key block", "HIGH",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("Generic secret assignment", "MED",
     re.compile(r"(?i)\b(secret|passwd|password|pwd|api[_-]?key|apikey|auth[_-]?token)"
                r"\b\s*[:=]\s*[\"']([^\"']{8,120})[\"']")),
]

BASE64_BLOB_RE = re.compile(r"^[A-Za-z0-9+/]{40,}={0,2}$")
HEX_BLOB_RE = re.compile(r"^[0-9a-fA-F]{32,}$")

# Extensions that mark an endpoint as static-asset noise rather than a route.
_STATIC_EXT_RE = re.compile(
    r"(?i)\.(png|jpe?g|gif|svg|ico|css|woff2?|ttf|eot|map)$")
# Extensions that mark an endpoint as a real server-side handler.
_HANDLER_EXT_RE = re.compile(r"(?i)\.(json|php|asp|aspx|jsp|do|action|xml)$")
# Path segments that read as API surface rather than UI chrome.
_API_SEG_RE = re.compile(r"(?i)(^|/)api([/_-]|$)|/v[0-9]+(/|$)|\bgraphql\b")
_INTERESTING_SEG_RE = re.compile(
    r"(?i)(admin|login|auth|token|secret|debug|console|webhook|callback)")


def score_endpoint(value):
    """Score an endpoint string by how recon-worthy it looks.

    Positive traits add, noise subtracts:

    - API-shaped paths (``/api/...``, ``/v1/...``, ``/graphql``): +2
    - query string present (parameterised route): +1
    - handler extension (``.json``, ``.php``, ...): +1
    - interesting segment (``admin``, ``login``, ``webhook``, ...): +1
    - single-character final segment (``/a``, ``/x/2``): -2
    - very short path (< 4 chars): -1
    - static-asset extension (``.png``, ``.css``, ``favicon.ico``, ...): -2

    Typical API routes land at 2-4; ``/favicon.ico`` lands at -2.
    """
    score = 0
    path = value.split("?", 1)[0].rstrip("/")
    segments = [s for s in path.split("/") if s]
    if not segments:
        return -2
    last = segments[-1]
    if len(last) == 1:
        score -= 2
    if len(path) < 4:
        score -= 1
    if _API_SEG_RE.search(path):
        score += 2
    if "?" in value:
        score += 1
    if _STATIC_EXT_RE.search(last):
        score -= 2
    elif _HANDLER_EXT_RE.search(last):
        score += 1
    if _INTERESTING_SEG_RE.search(path):
        score += 1
    return score


def is_endpoint(s):
    """True for absolute URLs and plausible root-relative routes."""
    if re.match(r"^(https?|wss?)://", s):
        return True
    if (s.startswith("/") and not s.startswith("//")
            and len(s) > 2 and re.search(r"[A-Za-z]", s)):
        return True
    return False


def find_secret(s):
    """Return the secret label if *s* matches a credential pattern, else None."""
    found = find_secret_detail(s)
    return found[0] if found else None


def find_secret_detail(s):
    """Return ``(label, severity)`` for the first matching pattern, else None."""
    for label, severity, pattern in SECRET_PATTERNS:
        if pattern.search(s):
            return label, severity
    return None


def is_interesting(s):
    """Long encoded-looking blobs that are worth a human glance."""
    if len(s) < 32:
        return None
    # hex first: any hex string is also base64-shaped, but a long even run
    # of hex reads as a hash/token to an analyst, not as base64.
    if HEX_BLOB_RE.match(s):
        return f"long hex string ({len(s)} chars)"
    if BASE64_BLOB_RE.match(s):
        return f"long base64 blob ({len(s)} chars)"
    return None


def extract(js_text, source):
    """Pull findings out of one JS file.

    Returns a list of dicts: {kind, value, detail, source} where kind is
    one of "endpoint", "secret", "interesting".

    Secret patterns run against the *full* JS text (assignments like
    ``api_key: "..."`` only make sense with context); endpoints and
    interesting strings are classified from quoted strings.
    """
    findings = []
    secret_spans = []
    for label, severity, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(js_text):
            value = m.group(0)
            if len(value) > 140:
                value = value[:140] + "..."
            findings.append({"kind": "secret", "value": value,
                             "detail": label, "severity": severity,
                             "source": source})
            secret_spans.append((m.start(), m.end()))
    seen = set()

    def _in_secret_span(s):
        # skip quoted strings already captured as part of a secret match
        idx = js_text.find(s)
        return any(a <= idx < b for a, b in secret_spans) if idx >= 0 else False

    for raw in QUOTED_RE.findall(js_text):
        s = raw.strip()
        if not s or s in seen or len(s) < 2 or _in_secret_span(s):
            continue
        seen.add(s)
        secret_detail = find_secret_detail(s)
        if secret_detail:
            label, severity = secret_detail
            findings.append({"kind": "secret", "value": s,
                             "detail": label, "severity": severity,
                             "source": source})
        elif is_endpoint(s):
            findings.append({"kind": "endpoint", "value": s,
                             "detail": "", "source": source,
                             "score": score_endpoint(s)})
        else:
            note = is_interesting(s)
            if note:
                findings.append({"kind": "interesting", "value": s,
                                 "detail": note, "source": source})
    return findings


def dedupe(findings):
    """Collapse identical (kind, value) hits, merging their sources.

    Framework findings also union their evidence notes, since different
    script files may carry different markers for the same stack.
    """
    from .fingerprint import merge_framework_detail
    merged = {}
    for f in findings:
        key = (f["kind"], f["value"])
        if key in merged:
            srcs = merged[key]["sources"]
            if f["source"] not in srcs:
                srcs.append(f["source"])
            if f["kind"] == "framework":
                merged[key]["detail"] = merge_framework_detail(
                    merged[key]["detail"], f["detail"])
        else:
            entry = {"kind": f["kind"], "value": f["value"],
                     "detail": f["detail"], "sources": [f["source"]]}
            if "score" in f:  # score is deterministic per value, keep it
                entry["score"] = f["score"]
            if "severity" in f:  # likewise deterministic per pattern
                entry["severity"] = f["severity"]
            merged[key] = entry
    return list(merged.values())
