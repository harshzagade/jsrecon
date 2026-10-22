"""Render findings as human-readable text or JSON."""
import json


def render_text(findings, page_url, script_count, errors, only=None):
    kinds = ([("endpoint", "ENDPOINTS", "  "),
              ("secret", "SECRETS", "[!] "),
              ("interesting", "INTERESTING", "[~] ")] if only is None
             else [k for k in (("endpoint", "ENDPOINTS", "  "),
                               ("secret", "SECRETS", "[!] "),
                               ("interesting", "INTERESTING", "[~] "))
                   if k[0] in only])
    lines = [f"[+] fetched {page_url} ({script_count} script file(s))"]
    if errors:
        lines.append("[!] fetch errors:")
        lines.extend(f"    - {e}" for e in errors)
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


def render_json(findings, page_url, script_count, errors):
    return json.dumps({
        "target": page_url,
        "scripts_fetched": script_count,
        "fetch_errors": errors,
        "findings": findings,
    }, indent=2)
