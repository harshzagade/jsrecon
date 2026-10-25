"""Fetch HTML pages and their linked JavaScript files. Stdlib only."""
import json
import re
import urllib.request
from urllib.parse import quote, urljoin, urlparse

SCRIPT_SRC_RE = re.compile(
    r"<script\b[^>]*\bsrc\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
INLINE_SCRIPT_RE = re.compile(
    r"<script\b(?![^>]*\bsrc\b)[^>]*>(.*?)</script>",
    re.IGNORECASE | re.DOTALL)

DEFAULT_UA = "jsrecon/1.0 (+https://github.com/harshzagade/jsrecon)"

CDX_API = "https://web.archive.org/cdx/search/cdx"
ARCHIVE_PREFIX = "https://web.archive.org/web/"
WAYBACK_CDX_LIMIT = 5000


class FetchError(Exception):
    """Raised when a page or script file cannot be retrieved."""


def _get(url, timeout, user_agent):
    """GET *url*; returns (body, headers, status) with headers lowercased."""
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return body, headers, resp.status
    except Exception as exc:  # URLError, timeout, HTTPError, decode issues
        raise FetchError(f"GET {url}: {exc}") from exc


def _record_headers(headers_out, url, headers):
    """Stash the header fields the --headers check needs, if collecting."""
    if headers_out is not None:
        headers_out[url] = {
            "content_type": headers.get("content-type", ""),
            "allow_origin": headers.get("access-control-allow-origin", ""),
            "allow_credentials": headers.get("access-control-allow-credentials", ""),
        }


def fetch_js_sources(page_url, timeout=10.0, user_agent=DEFAULT_UA,
                     include_inline=False, headers_out=None):
    """Download every script linked from *page_url*.

    Returns ``(scripts, errors)`` where ``scripts`` is a list of
    ``(source, js_text)`` tuples — source is the absolute script URL, or
    ``<page>#inline-<n>`` for inline blocks — and ``errors`` lists any
    fetch failures as strings (reported, never fatal). When *headers_out*
    is a dict, it is filled with ``{script_url: {content_type,
    allow_origin, allow_credentials}}`` for the --headers check; inline
    blocks have no response headers and are not recorded.
    """
    html, _, _ = _get(page_url, timeout, user_agent)
    scripts, errors = [], []
    for src in SCRIPT_SRC_RE.findall(html):
        abs_url = urljoin(page_url, src.strip())
        if urlparse(abs_url).scheme not in ("http", "https"):
            continue  # data:, javascript:, etc.
        try:
            text, headers, _ = _get(abs_url, timeout, user_agent)
            _record_headers(headers_out, abs_url, headers)
            scripts.append((abs_url, text))
        except FetchError as exc:
            errors.append(str(exc))
    if include_inline:
        for i, block in enumerate(INLINE_SCRIPT_RE.findall(html)):
            if block.strip():
                scripts.append((f"{page_url}#inline-{i}", block))
    return scripts, errors


def fetch_wayback_js(page_url, timeout=10.0, user_agent=DEFAULT_UA,
                     max_files=50, cdx_base=CDX_API,
                     archive_prefix=ARCHIVE_PREFIX, headers_out=None):
    """Pull the target domain's archived JS from the Wayback CDX API.

    Queries CDX for ``*.js`` captures under the target's host, keeps the
    newest capture per URL, and downloads up to *max_files* snapshots
    (newest first) via ``<archive_prefix><timestamp>id_/<original>`` — the
    ``id_`` suffix returns the raw, unrewritten file.

    Returns ``(scripts, errors)`` shaped like :func:`fetch_js_sources` —
    source labels are the archived snapshot URLs, so relative
    sourceMappingURL comments still resolve against the archive. A CDX
    failure is fatal (like a failed page fetch); individual snapshot
    download failures are reported, never fatal. *headers_out* works as
    in :func:`fetch_js_sources` (headers are the archive's responses).
    """
    host = urlparse(page_url).hostname
    if not host:
        raise FetchError(f"cannot determine host from {page_url!r}")
    query = (f"{cdx_base}?url={quote(host + '/*.js')}&output=json"
             f"&filter=statuscode:200&limit={WAYBACK_CDX_LIMIT}")
    try:
        raw = _get(query, timeout, user_agent)[0]
        rows = json.loads(raw)
    except FetchError:
        raise
    except Exception as exc:
        raise FetchError(f"Wayback CDX query failed: {exc}") from exc
    if not rows or not isinstance(rows, list):
        return [], [f"wayback: no archived .js captures for {host}"]
    header, data = rows[0], rows[1:]
    try:
        ts_i, url_i = header.index("timestamp"), header.index("original")
    except (ValueError, AttributeError) as exc:
        raise FetchError(f"Wayback CDX returned an unexpected shape: {exc}")
    newest = {}
    for row in data:
        try:
            ts, orig = row[ts_i], row[url_i]
        except IndexError:
            continue
        if not orig or urlparse(orig).scheme not in ("http", "https"):
            continue
        if orig not in newest or ts > newest[orig]:
            newest[orig] = ts
    if not newest:
        return [], [f"wayback: no archived .js captures for {host}"]
    ordered = sorted(newest.items(), key=lambda kv: kv[1],
                     reverse=True)[:max_files]
    scripts, errors = [], []
    for orig, ts in ordered:
        snap = f"{archive_prefix}{ts}id_/{orig}"
        try:
            text, headers, _ = _get(snap, timeout, user_agent)
            _record_headers(headers_out, snap, headers)
            scripts.append((snap, text))
        except FetchError as exc:
            errors.append(str(exc))
    return scripts, errors
