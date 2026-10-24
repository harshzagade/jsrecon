"""Fingerprint the front-end framework(s) behind a site's JavaScript.

Each entry maps a framework name to (pattern, evidence-label) pairs. A
framework is reported when at least one of its markers matches; matched
markers become the finding's evidence. ``ng-version``-style matches also
carry the detected version into the evidence.
"""
import re

# (framework, pattern, evidence label). Version captures use a named
# group ``version``; plain markers have none.
_FRAMEWORK_MARKERS = [
    ("React", r"__REACT_DEVTOOLS_GLOBAL_HOOK__", "__REACT_DEVTOOLS_GLOBAL_HOOK__"),
    ("React", r"\breact-dom\b", "react-dom"),
    ("React", r"\bReactDOM\b", "ReactDOM"),
    ("React", r"react\.production\.min\.js", "react.production.min.js"),
    ("React", r"\buseSyncExternalStore\b", "useSyncExternalStore"),
    ("Vue", r"__VUE__", "__VUE__"),
    ("Vue", r"__VUE_OPTIONS_API__", "__VUE_OPTIONS_API__"),
    ("Vue", r"\bcreateApp\s*\(", "createApp("),
    ("Vue", r"\bvue\.runtime\b", "vue.runtime"),
    ("Vue", r"\bVue\.version\b", "Vue.version"),
    ("Angular", r'ng-version="(?P<version>[0-9][^"]*)"', "ng-version"),
    ("Angular", r"@angular/", "@angular/"),
    ("Angular", r"\bplatformBrowserDynamic\b", "platformBrowserDynamic"),
    ("Angular", r"\bzone\.js\b", "zone.js"),
    ("Angular", r"\bngZone\b", "ngZone"),
    ("Next.js", r"__NEXT_DATA__", "__NEXT_DATA__"),
    ("Next.js", r"/_next/static/", "_next/static"),
    ("Next.js", r"\bnext/router\b", "next/router"),
    ("Next.js", r"\bnext/link\b", "next/link"),
    ("Nuxt", r"__NUXT__", "__NUXT__"),
    ("Nuxt", r"/_nuxt/", "_nuxt/"),
    ("Svelte", r"\bsvelte/internal\b", "svelte/internal"),
    ("Svelte", r"\bcreate_ssr_component\b", "create_ssr_component"),
    ("jQuery", r"jQuery v(?P<version>[0-9][0-9.a-z-]*)", "jQuery v<version>"),
]

_COMPILED = [(fw, re.compile(pat), label)
             for fw, pat, label in _FRAMEWORK_MARKERS]


def fingerprint(js_text, source):
    """Detect front-end frameworks in one JS file.

    Returns a list of dicts: {kind: "framework", value, detail, source}
    with at most one finding per framework. ``detail`` lists the matched
    markers (evidence), with any detected version noted.
    """
    hits = {}
    for framework, pattern, label in _COMPILED:
        m = pattern.search(js_text)
        if not m:
            continue
        evidence = hits.setdefault(framework, [])
        note = label
        if "version" in (m.groupdict() or {}):
            note = label.replace("<version>", m.group("version"),
                                 1) if "<version>" in label \
                else f"{label}={m.group('version')}"
        if note not in evidence:
            evidence.append(note)
    findings = []
    for framework in ("React", "Vue", "Angular", "Next.js", "Nuxt", "Svelte",
                      "jQuery"):
        if framework in hits:
            findings.append({"kind": "framework", "value": framework,
                             "detail": ", ".join(hits[framework]),
                             "source": source})
    return findings


def merge_framework_detail(existing, new):
    """Union the evidence notes of two framework findings for the same stack."""
    seen = {n.strip() for n in existing.split(",") if n.strip()}
    for note in (n.strip() for n in new.split(",")):
        if note and note not in seen:
            seen.add(note)
            existing = f"{existing}, {note}" if existing else note
    return existing
