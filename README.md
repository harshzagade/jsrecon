# JsRecon

Harvest a website's JavaScript for recon: **API endpoints**, **hardcoded
secrets**, and **interesting strings**. Stdlib-only Python — no dependencies.

## Install

```bash
git clone https://github.com/harshzagade/jsrecon
cd jsrecon
pip install .
```

## Usage

```bash
jsrecon https://target.com
jsrecon https://target.com --include-inline   # also scan inline <script> blocks
jsrecon https://target.com --secrets-only     # only the secret findings
jsrecon https://target.com --endpoints-only   # only endpoints
jsrecon https://target.com --json -o out.json # machine-readable output
jsrecon https://target.com --timeout 15
jsrecon https://target.com --no-sourcemaps  # skip source-map probing
jsrecon https://target.com --wayback       # archived JS from the Wayback CDX API
jsrecon https://target.com --wayback --wayback-max 20 --json -o archived.json
jsrecon https://target.com --min-score 2   # hide low-value endpoints (noise)
jsrecon https://target.com --headers     # flag wrong JS Content-Type / permissive CORS
```

## Sample output

```
$ jsrecon http://127.0.0.1:8931
[+] fetched http://127.0.0.1:8931 (2 script file(s))

== ENDPOINTS (4) ==
  /api/v1/users
      <- http://127.0.0.1:8931/static/app.js
  /api/v1/login
      <- http://127.0.0.1:8931/static/app.js
  /graphql
      <- http://127.0.0.1:8931/static/app.js
  https://api.payments.example.com/charge
      <- http://127.0.0.1:8931/static/vendor.js

== SECRETS (1) ==
[!] AWS Access Key ID: AKIAIOSFODNN7EXAMPLE
      <- http://127.0.0.1:8931/static/app.js

== INTERESTING (0) ==
  (none)

== SOURCE MAPS (2) ==
[*] original source path: webpack:///./src/admin/panel.js
      <- http://127.0.0.1:8931/static/app.js (map: app.js.map)
[*] original source path: src/utils/auth.js
      <- http://127.0.0.1:8931/static/app.js (map: app.js.map)
```

## How it works

1. Fetches the page, collects every `<script src>` (resolved against the page URL).
2. Downloads each JS file (optionally also inline `<script>` blocks).
3. Fingerprints the front-end stack: React, Vue, Angular, Next.js, Nuxt,
   Svelte and jQuery are detected from bundle markers (e.g.
   `__REACT_DEVTOOLS_GLOBAL_HOOK__`, `ng-version`, `__NEXT_DATA__`), reported
   in the FRAMEWORKS section with the matched evidence and any detected
   version.
4. Pulls every quoted string out of the JS and classifies it:
   - **endpoint** — absolute URL or root-relative path with letters in it
   - **secret** — matches a known credential pattern (AWS keys, tokens, JWTs, ...)
   - **interesting** — long base64/hex blobs that smell like encoded data
5. Harvests comments separately (COMMENTS section): `//` and `/* */`
   comments are pulled by a real scanner, not a regex, so `//` inside
   string literals (`"https://..."`) and regex literals is not mistaken
   for a comment. TODO/FIXME/XXX/HACK tags and comments mentioning a
   URL or path get a detail note — devs leave internal URLs and
   half-finished work in comments. SourceMappingURL directives are
   skipped here (the source-map step mines those).
6. Mines source maps: for every JS file it resolves the
   `//# sourceMappingURL=` comment (or probes `<file>.js.map`), and reports
   the original pre-minification paths — plus scans any embedded
   `sourcesContent` through the same extraction pipeline (framework
   fingerprinting included).
7. Dedupes across files, keeps the source file for every hit.
8. With `--headers`, every fetched JS response is checked (HEADERS
   section): a missing or non-JavaScript Content-Type (e.g. `text/html`
   standing in for a script) and `Access-Control-Allow-Origin: *`
   (stronger note when combined with `Access-Control-Allow-Credentials:
   true`). Accepted types are `application/javascript`,
   `text/javascript` (RFC 9239) and legacy `application/x-javascript`.
   Inline blocks have no response headers and are skipped; in
   `--wayback` mode the archive's response headers are checked.

## `--wayback` mode

Instead of live-fetching, pulls the target domain's archived JavaScript from
the Wayback Machine CDX API: queries `web.archive.org/cdx/search/cdx` for
`*.js` captures under the target's host, keeps the newest capture per URL,
and downloads up to `--wayback-max` snapshots (default 50, newest first)
via `https://web.archive.org/web/<timestamp>id_/<url>`. Source-map probing
applies to archived files too — old maps are often still in the archive.

```
$ jsrecon https://target.com --wayback
[+] fetched https://target.com (12 script file(s)) via the Wayback Machine
...
```

## Endpoint scoring (`--min-score`)

Every endpoint finding carries a score of how recon-worthy it looks:

| Signal | Effect |
|--------|--------|
| `/api/...`, `/v1/...`, `/graphql` | +2 |
| query string (`?id=`) | +1 |
| handler extension (`.json`, `.php`, ...) | +1 |
| `admin` / `login` / `webhook` / ... segment | +1 |
| single-char final segment (`/a`) | -2 |
| very short path | -1 |
| static asset (`.png`, `.css`, `favicon.ico`, ...) | -2 |

`--min-score N` hides endpoints scoring below `N` (default 0 keeps
everything) and reports how many were hidden, so `/favicon.ico` and friends
stay out of the way on noisy bundles.

## Notes

- Passive recon aid: it only GETs the page and its own script files.
- Secret patterns are heuristic — verify before treating a hit as a live credential.
- Respects `--timeout`; fetch failures are reported, not fatal.
- Source-map probing is best-effort and silent: missing maps never fail the scan.
