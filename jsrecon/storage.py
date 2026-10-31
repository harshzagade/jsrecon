"""Harvest browser storage keys and cookie names from JavaScript.

Session and tracking keys are recon-worthy: a ``localStorage`` key like
``auth_token`` or a cookie named ``session`` tells a tester where a site
keeps client-side state, and which names to look for in later requests.
This module only reads key *names* out of the code — it never reads a
visitor's actual stored values, which are not in the JS text anyway.

Covered forms (all stdlib, regex over the JS text):

- ``localStorage``/``sessionStorage`` method calls: ``getItem``,
  ``setItem`` and ``removeItem`` with a quoted key argument.
- Bracket access: ``localStorage["key"]`` / ``sessionStorage['key']``.
- Cookie writes: ``document.cookie = "name=value; ..."`` — only the
  name before the first ``=`` or ``;`` is kept; the value is dropped.
  The write's attributes are audited: a cookie set without ``Secure``,
  ``HttpOnly`` or ``SameSite`` gets a ``missing ...`` detail note in
  the STORAGE section. Note that a ``document.cookie`` write can never
  actually set ``HttpOnly`` (browsers ignore it there), so JS-set
  cookies flag ``HttpOnly`` in practice — the note still correctly
  reports that the cookie lacks that protection; only a server
  ``Set-Cookie`` header can grant it.

Findings carry kind ``"storage"`` and a value of ``"<store>:<key>"``
(``localStorage:auth_token``, ``cookie:session``), so the same key held
in two stores stays two findings through dedupe. Template-literal keys
containing ``${...}`` are skipped: the real key is not knowable from
the text. Library wrappers (``Cookies.set(...)``, ``js-cookie``) are
out of scope — only the platform APIs are matched.
"""
import re

_STORAGE_CALL_RE = re.compile(
    r"\b(localStorage|sessionStorage)\s*\.\s*"
    r"(?:getItem|setItem|removeItem)\s*\(\s*[\"'`]([^\"'`]+)[\"'`]")
_STORAGE_INDEX_RE = re.compile(
    r"\b(localStorage|sessionStorage)\s*\[\s*[\"'`]([^\"'`]+)[\"'`]\s*\]")
_COOKIE_WRITE_RE = re.compile(
    r"\bdocument\s*\.\s*cookie\s*=\s*[\"'`]([^\"'`]+)[\"'`]")

# Attributes whose absence is flagged, in report order.
_AUDITED_ATTRS = (("secure", "Secure"), ("httponly", "HttpOnly"),
                  ("samesite", "SameSite"))


def audit_cookie_attributes(assignment):
    """Return the audited attributes missing from a cookie assignment.

    *assignment* is the full quoted ``document.cookie`` string
    (``"name=value; Path=/; Secure"``). Attribute names are matched
    case-insensitively; ``SameSite=Lax`` counts as present. Returns a
    tuple of canonical names, e.g. ``("Secure", "HttpOnly")``, or ``()``
    when all three are present.
    """
    segments = assignment.split(";")
    present = set()
    for segment in segments[1:]:
        name = segment.split("=", 1)[0].strip().lower()
        if name:
            present.add(name)
    return tuple(label for key, label in _AUDITED_ATTRS if key not in present)


def extract_storage(js_text, source):
    """Pull storage keys and cookie names out of one JS file.

    Returns a list of dicts: {kind, value, detail, source} with kind
    ``"storage"``. Storage-key findings have detail ``""``; cookie
    findings carry ``"missing Secure, HttpOnly"``-style detail when
    the write lacks audited attributes, ``""`` when it has them all.
    When one file sets the same cookie twice, the worst case (most
    missing attributes) is kept, so a secure write cannot hide an
    insecure one.
    """
    findings = []
    seen = {}

    def _add(store, key, detail=""):
        key = key.strip()
        if not key or "${" in key:
            return
        value = f"{store}:{key}"
        if value in seen:
            existing = seen[value]
            if len(detail) > len(existing["detail"]):
                existing["detail"] = detail
            return
        finding = {"kind": "storage", "value": value,
                   "detail": detail, "source": source}
        seen[value] = finding
        findings.append(finding)

    for m in _STORAGE_CALL_RE.finditer(js_text):
        _add(m.group(1), m.group(2))
    for m in _STORAGE_INDEX_RE.finditer(js_text):
        _add(m.group(1), m.group(2))
    for m in _COOKIE_WRITE_RE.finditer(js_text):
        assignment = m.group(1)
        name = assignment.split(";", 1)[0].split("=", 1)[0]
        missing = audit_cookie_attributes(assignment)
        detail = (f"missing {', '.join(missing)}" if missing else "")
        _add("cookie", name, detail)
    return findings
