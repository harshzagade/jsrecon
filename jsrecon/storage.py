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
  name before the first ``=`` or ``;`` is kept; the value and the
  attributes (``Path``, ``Expires``, ...) are dropped.

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
_COOKIE_RE = re.compile(
    r"\bdocument\s*\.\s*cookie\s*=\s*[\"'`]([^\"'`=;\s]+)")


def extract_storage(js_text, source):
    """Pull storage keys and cookie names out of one JS file.

    Returns a list of dicts: {kind, value, detail, source} with kind
    ``"storage"`` and detail ``""`` (the store is part of the value).
    """
    findings = []
    seen = set()

    def _add(store, key):
        key = key.strip()
        if not key or "${" in key:
            return
        value = f"{store}:{key}"
        if value in seen:
            return
        seen.add(value)
        findings.append({"kind": "storage", "value": value,
                         "detail": "", "source": source})

    for m in _STORAGE_CALL_RE.finditer(js_text):
        _add(m.group(1), m.group(2))
    for m in _STORAGE_INDEX_RE.finditer(js_text):
        _add(m.group(1), m.group(2))
    for m in _COOKIE_RE.finditer(js_text):
        _add("cookie", m.group(1))
    return findings
