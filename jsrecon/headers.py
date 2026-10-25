"""Flag JS responses served with the wrong Content-Type or permissive CORS.

Two checks per script response:

- Content-Type: a JS file served as ``text/html`` (or with no
  Content-Type at all) is a misconfiguration worth flagging — it can mean
  a WAF/error page standing in for the script, or a server that never
  configured JS types. Accepted types are ``application/javascript``
  (the long-time convention), ``text/javascript`` (the current RFC 9239
  standard) and the legacy ``application/x-javascript``; parameters such
  as ``; charset=utf-8`` are ignored.
- CORS: ``Access-Control-Allow-Origin: *`` lets any origin read the
  script cross-origin. On its own that is usually low-risk for public
  JS, but combined with ``Access-Control-Allow-Credentials: true`` it
  is a real misconfiguration (browsers refuse that combination), so the
  two are flagged together with a stronger note.
"""
# RFC 9239: text/javascript is the standard type; application/javascript
# is the obsolete-but-universal convention; x-javascript is legacy.
JS_CONTENT_TYPES = frozenset({
    "application/javascript",
    "text/javascript",
    "application/x-javascript",
})


def check_js_headers(source, content_type="",
                     allow_origin="", allow_credentials=""):
    """Return header findings for one JS response: {kind, value, detail, source}."""
    findings = []
    media = content_type.split(";", 1)[0].strip().lower()
    if not media:
        findings.append({"kind": "header",
                         "value": "missing Content-Type",
                         "detail": "content-type", "source": source})
    elif media not in JS_CONTENT_TYPES:
        findings.append({"kind": "header",
                         "value": (f"Content-Type: {media} (expected "
                                  f"application/javascript)"),
                         "detail": "content-type", "source": source})
    if allow_origin.strip() == "*":
        if allow_credentials.strip().lower() == "true":
            findings.append({"kind": "header",
                             "value": ("Access-Control-Allow-Origin: * with "
                                      "Access-Control-Allow-Credentials: true"),
                             "detail": "cors", "source": source})
        else:
            findings.append({"kind": "header",
                             "value": ("Access-Control-Allow-Origin: * "
                                      "(any origin may read this script)"),
                             "detail": "cors", "source": source})
    return findings
