"""CLI: jsrecon <url> [options]."""
import argparse
import sys

from . import __version__
from .extract import dedupe, extract
from .fetch import DEFAULT_UA, FetchError, fetch_js_sources
from .report import render_json, render_text


def build_parser():
    p = argparse.ArgumentParser(
        prog="jsrecon",
        description="Harvest API endpoints, hardcoded secrets and interesting "
                    "strings from a site's JavaScript (stdlib-only).")
    p.add_argument("url", help="page to harvest (e.g. https://target.com)")
    p.add_argument("--include-inline", action="store_true",
                   help="also scan inline <script> blocks, not just src files")
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
    try:
        scripts, errors = fetch_js_sources(
            args.url, timeout=args.timeout, user_agent=args.user_agent,
            include_inline=args.include_inline)
    except FetchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    findings = []
    for source, js_text in scripts:
        findings.extend(extract(js_text, source))
    findings = dedupe(findings)
    only = None
    if args.secrets_only:
        findings = [f for f in findings if f["kind"] == "secret"]
        only = ("secret",)
    elif args.endpoints_only:
        findings = [f for f in findings if f["kind"] == "endpoint"]
        only = ("endpoint",)

    if args.json:
        out = render_json(findings, args.url, len(scripts), errors)
    else:
        out = render_text(findings, args.url, len(scripts), errors, only=only)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
