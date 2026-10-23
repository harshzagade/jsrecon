"""CLI: jsrecon <url> [options]."""
import argparse
import sys

from . import __version__, sourcemap
from .extract import dedupe, extract
from .fetch import (DEFAULT_UA, FetchError, fetch_js_sources,
                    fetch_wayback_js)
from .report import render_json, render_text


def build_parser():
    p = argparse.ArgumentParser(
        prog="jsrecon",
        description="Harvest API endpoints, hardcoded secrets and interesting "
                    "strings from a site's JavaScript (stdlib-only).")
    p.add_argument("url", help="page to harvest (e.g. https://target.com)")
    p.add_argument("--include-inline", action="store_true",
                   help="also scan inline <script> blocks, not just src files")
    p.add_argument("--no-sourcemaps", action="store_true",
                   help="skip source-map probing (on by default per JS file)")
    p.add_argument("--wayback", action="store_true",
                   help="pull the target domain's archived JS from the Wayback "
                        "Machine CDX API instead of live-fetching")
    p.add_argument("--wayback-max", type=int, default=50, metavar="N",
                   help="max archived JS files to download (default 50)")
    p.add_argument("--timeout", type=float, default=10.0,
                   help="per-request timeout in seconds (default 10)")
    p.add_argument("--user-agent", default=DEFAULT_UA,
                   help="User-Agent header to send")
    p.add_argument("--secrets-only", action="store_true",
                   help="print only secret findings")
    p.add_argument("--endpoints-only", action="store_true",
                   help="print only endpoint findings")
    p.add_argument("--json", action="store_true",
                   help="machine-readable JSON output")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="write report to FILE instead of stdout")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.secrets_only and args.endpoints_only:
        print("error: --secrets-only and --endpoints-only are mutually exclusive",
              file=sys.stderr)
        return 2
    if args.wayback_max < 1:
        print("error: --wayback-max must be >= 1", file=sys.stderr)
        return 2
    if args.wayback and args.include_inline:
        print("error: --include-inline is not supported with --wayback "
              "(no live page is fetched)", file=sys.stderr)
        return 2
    try:
        if args.wayback:
            scripts, errors = fetch_wayback_js(
                args.url, timeout=args.timeout, user_agent=args.user_agent,
                max_files=args.wayback_max)
            mode = "wayback"
        else:
            scripts, errors = fetch_js_sources(
                args.url, timeout=args.timeout, user_agent=args.user_agent,
                include_inline=args.include_inline)
            mode = "live"
    except FetchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    findings = []
    for source, js_text in scripts:
        findings.extend(extract(js_text, source))
    script_count = len(scripts)
    if not args.no_sourcemaps:
        # Mine source maps: original paths become findings, and any embedded
        # sourcesContent is fed back through the normal extraction pipeline.
        for source, js_text in list(scripts):
            got = sourcemap.fetch_map(source, js_text, args.timeout,
                                      args.user_agent)
            if got is None:
                continue
            map_url, paths, contents = got
            findings.extend(sourcemap.sourcemap_findings(source, map_url, paths))
            for path, text in contents:
                label = f"{source} [source map: {path}]"
                scripts.append((label, text))
                findings.extend(extract(text, label))
    findings = dedupe(findings)
    only = None
    if args.secrets_only:
        findings = [f for f in findings if f["kind"] == "secret"]
        only = ("secret",)
    elif args.endpoints_only:
        findings = [f for f in findings if f["kind"] == "endpoint"]
        only = ("endpoint",)

    if args.json:
        out = render_json(findings, args.url, script_count, errors, mode=mode)
    else:
        out = render_text(findings, args.url, script_count, errors, only=only,
                          mode=mode)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
