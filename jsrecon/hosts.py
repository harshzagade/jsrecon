"""Group absolute-URL endpoints by host for the text report.

A bundle usually mixes first-party API calls with third-party hosts
(analytics, payments, CDNs); listing every endpoint flat hides that
split. Grouping keeps relative paths ungrouped at the top — they
belong to the scanned site by definition — and gathers each absolute
host under its own subheader, marking the scanned site's own host so
first-party vs third-party is visible at a glance.
"""
from urllib.parse import urlparse


def endpoint_host(value):
    """Return the lowercased host of an absolute endpoint URL, else None.

    Only http/https/ws/wss URLs carry a host here; root-relative paths
    (the common case) return None. Port and userinfo are dropped — the
    grouping is by host, not by origin.
    """
    parsed = urlparse(value)
    if parsed.scheme in ("http", "https", "ws", "wss") and parsed.hostname:
        return parsed.hostname.lower()
    return None


def group_endpoints(findings, page_url=None):
    """Split endpoint findings into (label, findings) blocks, in order.

    The first block has label None and holds the relative paths, if
    any. Each following block is labelled with its host, with
    `` (this site)`` appended when the host matches the scanned page's
    host. Hosts appear in first-seen order. When there are no absolute
    endpoints at all, the single relative block is returned unchanged,
    so relative-only reports render exactly as before.
    """
    page_host = None
    if page_url:
        page_host = endpoint_host(page_url)
    relative = []
    hosts = {}
    order = []
    for f in findings:
        if f["kind"] != "endpoint":
            continue
        host = endpoint_host(f["value"])
        if host is None:
            relative.append(f)
        else:
            if host not in hosts:
                hosts[host] = []
                order.append(host)
            hosts[host].append(f)
    blocks = []
    if relative:
        blocks.append((None, relative))
    for host in order:
        label = host + (" (this site)" if host == page_host else "")
        blocks.append((label, hosts[host]))
    return blocks
