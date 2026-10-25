"""Render findings as human-readable text or JSON."""
import json


_KINDS = (("endpoint", "ENDPOINTS", "  "),
          ("framework", "FRAMEWORKS", "[#] "),
          ("secret", "SECRETS", "[!] "),
          ("interesting", "INTERESTING", "[~] "),
          ("comment", "COMMENTS", "[c] "),
          ("sourcemap", "SOURCE MAPS", "[*] "))


def render_text(findings, page_url, script_count, errors, only=None,
                mode="live", min_score=0, dropped=0):
    kinds = (_KINDS if only is None
             else [k for k in _KINDS if k[0] in only])
    via = " via the Wayback Machine" if mode == "wayback" else ""
    lines = [f"[+] fetched {page_url} ({script_count} script file(s)){via}"]
    if errors:
        lines.append("[!] fetch errors:")
        lines.extend(f"    - {e}" for e in errors)
    if dropped:
        lines.append(f"[i] {dropped} endpoint(s) hidden by --min-score "
                     f"{min_score}")
    for kind, title, marker in kinds:
        group = [f for f in findings if f["kind"] == kind]
        lines.append("")
        lines.append(f"== {title} ({len(group)}) ==")
        if not group:
            lines.append("  (none)")
        for f in group:
            label = f"{marker}{f['detail'] + ': ' if f['detail'] else ''}{_short(f['value'])}"
            lines.append(label)
            for src in f["sources"]:
                lines.append(f"      <- {src}")
    return "\n".join(lines)


def _short(value, limit=90):
    return value if len(value) <= limit else value[:limit] + "..."


def render_json(findings, page_url, script_count, errors, mode="live",
                min_score=0, dropped=0):
    return json.dumps({
        "target": page_url,
        "mode": mode,
        "scripts_fetched": script_count,
        "fetch_errors": errors,
        "min_score": min_score,
        "endpoints_dropped": dropped,
        "findings": findings,
    }, indent=2)
