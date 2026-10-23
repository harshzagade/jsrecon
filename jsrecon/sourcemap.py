"""Source-map support: find, fetch and mine ``*.js.map`` files. Stdlib only.

A source map leaks the *original* file layout behind a minified bundle —
``src/admin/panel.js`` paths that never appear in any URL are pure recon
gold. Resolution order per JS file:

1. the ``//# sourceMappingURL=`` comment (also ``//@`` and ``/*# */`` forms,
   incl. inline ``data:application/json;base64,`` maps);
2. failing that, a probe of the conventional ``<file>.js.map`` location.

Map fetch failures are silent by design: maps are an opportunistic bonus,
not the scan's core, and blind ``.map`` probes 404 constantly.

The ``sources`` list becomes ``sourcemap`` findings (a dedicated report
section); embedded ``sourcesContent`` is fed back through the normal
extraction pipeline, since unminified originals are the richest input we
can get.
"""
import base64
import binascii
import json
import re
import urllib.request
from urllib.parse import urljoin, urlparse

# Matches `//# sourceMappingURL=app.js.map`, the legacy `//@` form, and the
# `/*# sourceMappingURL=app.js.map */` comment style. The comment is a tail
# marker by convention, so only the last few KB of the JS are searched.
MAPPING_URL_RE = re.compile(
    r"(?://|/\*)[#@]\s*sourceMappingURL\s*=\s*(\S+?)\s*(?:\*/)?\s*$",
    re.IGNORECASE | re.MULTILINE)

DATA_URL_RE = re.compile(
    r"^data:application/json(?:;charset=[^;,]+)?;base64,(.+)$", re.IGNORECASE)

TAIL_BYTES = 4096


def find_mapping_url(js_text):
    """Return the sourceMappingURL declared in the JS tail, or None."""
    m = MAPPING_URL_RE.search(js_text[-TAIL_BYTES:])
    return m.group(1).strip() if m else None


def _decode_data_url(mapping_url):
    """Decode an inline base64 source-map data: URL, else None."""
    m = DATA_URL_RE.match(mapping_url.strip())
    if not m:
        return None
    try:
        return base64.b64decode(m.group(1)).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return None


def _fetch_map_url(url, timeout, user_agent):
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


def _parse_map(map_text):
    """Parse source-map JSON -> (paths, [(path, source_text), ...]) or None."""
    try:
        data = json.loads(map_text)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    sources = data.get("sources") or []
    paths = [s for s in sources if isinstance(s, str) and s.strip()]
    contents = []
    sources_content = data.get("sourcesContent") or []
    for path, content in zip(sources, sources_content):
        if (isinstance(path, str) and path.strip()
                and isinstance(content, str) and content.strip()):
            contents.append((path, content))
    return paths, contents


def fetch_map(js_url, js_text, timeout, user_agent):
    """Fetch the source map for one JS file.

    Returns ``(map_url, paths, contents)`` or None when no usable map
    exists (no comment, unresolvable URL, fetch failure, bad JSON).
    Everything here is best-effort and silent on failure.
    """
    map_text, map_url, mapping = None, None, find_mapping_url(js_text)
    if mapping:
        inline = _decode_data_url(mapping)
        if inline is not None:
            map_text = inline
            map_url = f"{js_url} (inline sourceMappingURL)"
        elif urlparse(mapping).scheme in ("", "http", "https"):
            map_url = urljoin(js_url, mapping)
            try:
                map_text = _fetch_map_url(map_url, timeout, user_agent)
            except Exception:
                map_text = None
    elif mapping is None:
        # No comment at all: probe the conventional <file>.js.map location.
        probe = js_url + ".map"
        try:
            map_text = _fetch_map_url(probe, timeout, user_agent)
        except Exception:
            map_text = None
        if map_text is not None:
            map_url = probe
    if map_text is None:
        return None
    parsed = _parse_map(map_text)
    if parsed is None:
        return None
    paths, contents = parsed
    if not paths and not contents:
        return None
    return map_url, paths, contents


def sourcemap_findings(js_url, map_url, paths):
    """Turn original source paths into findings of kind ``sourcemap``."""
    findings = []
    for path in dict.fromkeys(paths):  # dedupe, keep first-seen order
        findings.append({
            "kind": "sourcemap",
            "value": path,
            "detail": "original source path",
            "source": f"{js_url} (map: {map_url.rsplit('/', 1)[-1][:60]})",
        })
    return findings
