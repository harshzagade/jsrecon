"""Fetch HTML pages and their linked JavaScript files. Stdlib only."""
import re
import urllib.request
from urllib.parse import urljoin, urlparse

SCRIPT_SRC_RE = re.compile(
    r"<script\b[^>]*\bsrc\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
INLINE_SCRIPT_RE = re.compile(
    r"<script\b(?![^>]*\bsrc\b)[^>]*>(.*?)</script>",
    re.IGNORECASE | re.DOTALL)

DEFAULT_UA = "jsrecon/1.0 (+https://github.com/harshzagade/jsrecon)"


class FetchError(Exception):
    """Raised when a page or script file cannot be retrieved."""


def _get(url, timeout, user_agent):
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            return body, resp.headers.get("Content-Type", ""), resp.status
    except Exception as exc:  # URLError, timeout, HTTPError, decode issues
        raise FetchError(f"GET {url}: {exc}") from exc


def fetch_js_sources(page_url, timeout=10.0, user_agent=DEFAULT_UA,
                     include_inline=False):
    """Download every script linked from *page_url*.

    Returns ``(scripts, errors)`` where ``scripts`` is a list of
    ``(source, js_text)`` tuples — source is the absolute script URL, or
    ``<page>#inline-<n>`` for inline blocks — and ``errors`` lists any
    fetch failures as strings (reported, never fatal).
    """
    html, _, _ = _get(page_url, timeout, user_agent)
    scripts, errors = [], []
    for src in SCRIPT_SRC_RE.findall(html):
        abs_url = urljoin(page_url, src.strip())
        if urlparse(abs_url).scheme not in ("http", "https"):
            continue  # data:, javascript:, etc.
        try:
            text, _, _ = _get(abs_url, timeout, user_agent)
            scripts.append((abs_url, text))
        except FetchError as exc:
            errors.append(str(exc))
    if include_inline:
        for i, block in enumerate(INLINE_SCRIPT_RE.findall(html)):
            if block.strip():
                scripts.append((f"{page_url}#inline-{i}", block))
    return scripts, errors
