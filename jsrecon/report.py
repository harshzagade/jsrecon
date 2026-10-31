"""Render findings as human-readable text or JSON."""
import html
import json

from .hosts import group_endpoints
from .params import collect_params


_KINDS = (("endpoint", "ENDPOINTS", "  "),
          ("framework", "FRAMEWORKS", "[#] "),
          ("secret", "SECRETS", "[!] "),
          ("interesting", "INTERESTING", "[~] "),
          ("comment", "COMMENTS", "[c] "),
          ("storage", "STORAGE", "[s] "),
          ("sourcemap", "SOURCE MAPS", "[*] "),
          ("header", "HEADERS", "[h] "))


def _append_finding(lines, f, marker, indent=None):
    prefix = marker if indent is None else indent
    sev = f"[{f['severity']}] " if "severity" in f else ""
    label = (f"{prefix}{sev}{f['detail'] + ': ' if f['detail'] else ''}"
             f"{_short(f['value'])}")
    if "claims" in f:
        label += f" (claims: {', '.join(f['claims'])})"
    if "verified" in f:
        label += _verify_suffix(f)
    lines.append(label)
    for src in f["sources"]:
        lines.append(f"      <- {src}")


def render_text(findings, page_url, script_count, errors, only=None,
                mode="live", min_score=0, dropped=0, excluded=0):
    kinds = (_KINDS if only is None
             else [k for k in _KINDS if k[0] in only])
    via = " via the Wayback Machine" if mode == "wayback" else ""
    lines = [f"[+] fetched {page_url} ({script_count} script file(s)){via}"]
    if errors:
        lines.append("[!] fetch errors:")
        lines.extend(f"    - {e}" for e in errors)
    if excluded:
        lines.append(f"[i] {excluded} script(s) excluded by --exclude")
    if dropped:
        lines.append(f"[i] {dropped} endpoint(s) hidden by --min-score "
                     f"{min_score}")
    secrets = [f for f in findings if f["kind"] == "secret"]
    if secrets:
        counts = {sev: sum(1 for f in secrets if f.get("severity") == sev)
                  for sev in ("HIGH", "MED", "LOW")}
        lines.append("[i] Secrets: {} (HIGH: {}, MED: {}, LOW: {})".format(
            len(secrets), counts["HIGH"], counts["MED"], counts["LOW"]))
    for kind, title, marker in kinds:
        group = [f for f in findings if f["kind"] == kind]
        lines.append("")
        lines.append(f"== {title} ({len(group)}) ==")
        if not group:
            lines.append("  (none)")
        if kind == "endpoint" and group:
            # Absolute URLs group under their host; relative paths stay
            # flat on top. A relative-only report renders as before.
            for label, block in group_endpoints(group, page_url):
                if label is not None:
                    lines.append(f"  {label}:")
                for f in block:
                    _append_finding(lines, f, marker,
                                    indent="    " if label is not None
                                    else "  ")
            continue
        for f in group:
            _append_finding(lines, f, marker)
    if only is None or "endpoint" in only:
        params = collect_params(findings)
        if params:
            lines.append("")
            lines.append(f"== PARAMS ({len(params)}) ==")
            for p in params:
                lines.append(f"  {p['param']} ({p['count']} endpoint(s)): "
                             f"{p['example']}")
    return "\n".join(lines)


def render_html(findings, page_url, script_count, errors, only=None,
                mode="live", min_score=0, dropped=0, excluded=0):
    """Single-file HTML report: one collapsible section per script file.

    Findings are grouped by their first source file, so each
    ``<details>`` block reads as one file's harvest. Every value is
    HTML-escaped (harvested strings can contain markup), and the page
    needs no external resources — it is one self-contained file.
    """
    kinds = (_KINDS if only is None
             else [k for k in _KINDS if k[0] in only])
    shown = [f for f in findings
             if any(f["kind"] == k[0] for k in kinds)]
    by_source = {}
    for f in shown:
        src = f["sources"][0] if f["sources"] else "(unknown)"
        by_source.setdefault(src, []).append(f)
    esc = html.escape
    via = " via the Wayback Machine" if mode == "wayback" else ""
    parts = ["<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
             f"<title>jsrecon report: {esc(page_url)}</title>\n"
             "<style>body{font-family:system-ui,sans-serif;max-width:900px;"
             "margin:2em auto;padding:0 1em}details{border:1px solid #ccc;"
             "border-radius:6px;padding:.5em 1em;margin:.75em 0}"
             "summary{cursor:pointer;font-weight:600}li{word-break:break-all}"
             ".meta{color:#555}</style>\n</head>\n<body>\n"
             f"<h1>jsrecon report</h1>\n<p class=\"meta\">Target: {esc(page_url)}"
             f"{esc(via)} — {script_count} script file(s), "
             f"{len(shown)} finding(s)</p>\n"]
    if errors:
        parts.append("<h2>Fetch errors</h2>\n<ul>\n")
        parts.extend(f"<li>{esc(e)}</li>\n" for e in errors)
        parts.append("</ul>\n")
    if excluded:
        parts.append(f"<p class=\"meta\">{excluded} script(s) excluded by "
                     f"--exclude</p>\n")
    if dropped:
        parts.append(f"<p class=\"meta\">{dropped} endpoint(s) hidden by "
                     f"--min-score {min_score}</p>\n")
    parts.append("<h2>Findings by kind</h2>\n<ul>\n")
    for kind, title, _marker in kinds:
        n = sum(1 for f in shown if f["kind"] == kind)
        parts.append(f"<li>{esc(title)}: {n}</li>\n")
    parts.append("</ul>\n")
    params = collect_params(shown)
    if params:
        parts.append("<h2>Query parameters</h2>\n<ul>\n")
        for p in params:
            parts.append(f"<li>{esc(p['param'])} ({p['count']} endpoint(s)): "
                         f"{esc(p['example'])}</li>\n")
        parts.append("</ul>\n")
    for i, (src, group) in enumerate(by_source.items()):
        open_attr = " open" if i == 0 else ""
        parts.append(f"<details{open_attr}>\n"
                     f"<summary>{esc(src)} ({len(group)} finding(s))"
                     f"</summary>\n<ul>\n")
        for f in group:
            sev = f"[{f['severity']}] " if "severity" in f else ""
            label = f"{f['kind']}: {sev}{f['detail'] + ': ' if f['detail'] else ''}{f['value']}"
            if "claims" in f:
                label += f" (claims: {', '.join(f['claims'])})"
            if "verified" in f:
                label += _verify_suffix(f)
            parts.append(f"<li>{esc(label)}")
            extra = [s for s in f["sources"][1:]]
            if extra:
                parts.append(f"<br><span class=\"meta\">also in: "
                             + ", ".join(esc(s) for s in extra)
                             + "</span>")
            parts.append("</li>\n")
        parts.append("</ul>\n</details>\n")
    if not by_source:
        parts.append("<p>(no findings)</p>\n")
    parts.append("</body>\n</html>")
    return "".join(parts)


def build_stats(findings, script_count, duration=None):
    """Summarise a scan for pipeline consumers.

    Per-kind finding counts cover every known kind (zero when absent),
    plus the total, the number of script files fetched, and the scan
    duration in seconds (``None`` when the caller did not measure one).
    """
    counts = {kind: sum(1 for f in findings if f["kind"] == kind)
              for kind, _title, _marker in _KINDS}
    stats = {"total_findings": len(findings),
             "scripts_fetched": script_count,
             "findings_by_kind": counts,
             "duration_seconds": (round(duration, 3) if duration is not None
                                  else None)}
    return stats


def _verify_suffix(f):
    state = f["verified"]
    status = f.get("http_status")
    if status is not None:
        return f" [{state} {status}]"
    return f" [{state}]"


def _short(value, limit=90):
    return value if len(value) <= limit else value[:limit] + "..."


def render_json(findings, page_url, script_count, errors, mode="live",
                min_score=0, dropped=0, excluded=0, duration=None):
    return json.dumps({
        "target": page_url,
        "mode": mode,
        "scripts_fetched": script_count,
        "fetch_errors": errors,
        "min_score": min_score,
        "endpoints_dropped": dropped,
        "scripts_excluded": excluded,
        "query_params": collect_params(findings),
        "stats": build_stats(findings, script_count, duration),
        "findings": findings,
    }, indent=2)
