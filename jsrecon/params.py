"""Harvest query parameter names from endpoint findings.

For injection-point triage it matters less which exact URLs were found
than which parameter names a site accepts: ``id``, ``q``, ``redirect``
and friends are the names a tester reaches for first. This module
collects those names from the endpoint findings the extractor already
produced — no extra requests, no new parsing of JS.
"""
from urllib.parse import parse_qsl, urlparse


def parse_query_params(value):
    """Return the query parameter names in an endpoint URL, in order.

    Blank values count (``?flag`` and ``?flag=`` both expose ``flag``);
    empty names (``?=x``) and parameter-less URLs yield nothing.
    Percent-encoded names are decoded, matching how a server sees them.
    """
    query = urlparse(value).query
    if not query:
        return []
    return [name for name, _ in parse_qsl(query, keep_blank_values=True)
            if name]


def collect_params(findings):
    """Summarise query parameters across endpoint findings.

    Returns a list of dicts — ``{"param", "count", "example"}`` — where
    ``count`` is the number of distinct endpoint values carrying the
    parameter and ``example`` is the first such endpoint seen.
    Sorted by count (most common first), then parameter name, so the
    most widely used parameters surface at the top of the report.
    """
    by_param = {}
    for f in findings:
        if f["kind"] != "endpoint":
            continue
        value = f["value"]
        for name in set(parse_query_params(value)):
            entry = by_param.get(name)
            if entry is None:
                by_param[name] = {"param": name, "count": 1,
                                  "example": value}
            else:
                entry["count"] += 1
    return sorted(by_param.values(),
                  key=lambda e: (-e["count"], e["param"]))
