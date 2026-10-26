"""Dead-endpoint checker: HEAD-fetch harvested endpoints, mark live vs dead.

Only used behind the ``--verify`` flag. Endpoints harvested from JS are
often stale (removed routes, renamed APIs), so this pass resolves each
endpoint against the scanned page URL and issues one HEAD request:

- live:    2xx/3xx, or 401/403/405 (the resource answered, but access or
           the HEAD method itself is refused — the route still exists)
- dead:    404/410 (the route is gone)
- unknown: any other status (e.g. 500 — the server answered, but the
           route's state cannot be told from the status alone)
- error:   the request failed entirely (DNS, timeout, connection refused)

Classification is deliberately conservative: only 404/410 are called
dead, because a 403 or 500 on a real route must not be reported as gone.
``request`` is injectable so tests can stub the network out entirely.
"""
import urllib.error
import urllib.request
from urllib.parse import urljoin

LIVE_STATUSES = frozenset(range(200, 400)) | {401, 403, 405}
DEAD_STATUSES = frozenset({404, 410})


def _head(url, timeout, user_agent):
    """HEAD *url*; returns the HTTP status code."""
    req = urllib.request.Request(url, method="HEAD",
                                 headers={"User-Agent": user_agent})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except Exception as exc:
        raise OSError(str(exc)) from exc


def classify_status(status):
    """Map an HTTP status code to live/dead/unknown."""
    if status in LIVE_STATUSES:
        return "live"
    if status in DEAD_STATUSES:
        return "dead"
    return "unknown"


def resolve_endpoint(page_url, value):
    """Resolve a harvested endpoint against the scanned page URL.

    Absolute URLs pass through unchanged; root-relative paths resolve
    against the page's origin; bare relative paths resolve against the
    page URL itself. Returns None for values that cannot be an HTTP(S)
    URL (e.g. protocol-relative or non-HTTP schemes are skipped — a
    ``//host/path`` endpoint has no scheme to HEAD against).
    """
    if value.startswith("//"):
        return None
    resolved = urljoin(page_url, value)
    if not resolved.startswith(("http://", "https://")):
        return None
    return resolved


def verify_endpoints(endpoints, page_url, timeout=10.0,
                     user_agent="jsrecon", request=None):
    """HEAD-check each endpoint value; returns {value: result dict}.

    Each result is ``{"state": ..., "status": int|None, "url": ...}`` where
    ``state`` is one of live/dead/unknown/error and ``url`` is the
    resolved URL that was checked (None when unresolvable, in which
    case the state is "error" with no status).
    """
    request = request or _head
    results = {}
    for value in endpoints:
        url = resolve_endpoint(page_url, value)
        if url is None:
            results[value] = {"state": "error", "status": None, "url": None}
            continue
        try:
            status = request(url, timeout, user_agent)
        except Exception:
            results[value] = {"state": "error", "status": None, "url": url}
            continue
        results[value] = {"state": classify_status(status),
                          "status": status, "url": url}
    return results


def attach_verification(findings, results):
    """Annotate endpoint findings in place with their verify result.

    Adds ``verified`` (state string) and ``http_status`` keys, which the
    text report renders as a suffix and the JSON report carries verbatim.
    Non-endpoint findings are untouched.
    """
    for f in findings:
        if f["kind"] == "endpoint" and f["value"] in results:
            r = results[f["value"]]
            f["verified"] = r["state"]
            f["http_status"] = r["status"]
    return findings
