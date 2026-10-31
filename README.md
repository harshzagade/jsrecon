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
jsrecon https://target.com --verify      # HEAD-check each endpoint: live / dead / unknown
jsrecon https://target.com --html -o report.html  # single-file HTML report
jsrecon https://target.com --exclude vendor --exclude analytics  # skip noisy bundles
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
`--wayback-before DATE` (YYYY-MM-DD) restricts the scan to captures up
to the end of that day, for auditing what a site exposed at a point in
time; it requires `--wayback` and rejects a malformed date.

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

## Secret severity grading

Every secret finding carries a severity, shown as `[HIGH]` / `[MED]` /
`[LOW]` on the line and counted in the report header (`[i] Secrets: N
(HIGH: x, MED: y, LOW: z)`); JSON findings carry a `severity` field.

| Severity | Patterns |
|----------|----------|
| HIGH | AWS access keys and secret assignments, private key blocks, Stripe secret keys, GitHub and Slack tokens — live credentials usable as-is |
| MED | JWTs, Bearer tokens, generic secret assignments — session/context-dependent |
| LOW | Google API keys — commonly embedded in public clients (usually referrer-restricted, still worth a look) |

## Script filter (`--exclude`)

`--exclude REGEX` (repeatable) skips script URLs matching the pattern
before any extraction runs — analytics, tag-manager and other noisy
third-party bundles stay out of the report entirely (including their
source maps and header checks). The report notes how many scripts were
excluded, and `--json` carries the count as `scripts_excluded`. A bad
regex fails fast with exit 2.

## Dead-endpoint checker (`--verify`)

Harvested endpoints go stale, so `--verify` HEAD-fetches each surviving
endpoint (resolved against the scanned page URL) and marks it in the
report and JSON (`verified` / `http_status`):

| Mark | Meaning |
|------|---------|
| `[live 200]` | answered 2xx/3xx, or 401/403/405 (route exists, access or HEAD refused) |
| `[dead 404]` | 404/410 — the route is gone |
| `[unknown 500]` | any other status — the server answered, but the route's state is unclear |
| `[error]` | the request failed (DNS, timeout, connection refused) |

Only 404/410 are called dead, so a 403 or 500 on a real route is never
reported as gone.

## Endpoint hosts

In the text report, absolute-URL endpoints group under their host
(first-seen order), with the scanned site's own host marked
`(this site)` — first-party vs third-party at a glance. Relative
paths stay flat at the top, and a relative-only report renders
exactly as before:

```
== ENDPOINTS (3) ==
  /api/v1/users
  example.com (this site):
    https://example.com/charge
  cdn.example.com:
    https://cdn.example.com/track.js
```

## Query parameters (PARAMS)

Every endpoint's query string is mined for parameter names, summarised
in a PARAMS section (parameter, endpoint count, first example
endpoint) and in the JSON output's `query_params` block — the names a
tester reaches for first when probing for injection points. Most-used
parameters sort first; ties break alphabetically. The section only
appears when endpoints with query strings were found, and it follows
the same filtering as ENDPOINTS (so `--secrets-only` hides it).

```
== PARAMS (2) ==
  id (3 endpoint(s)): /api/users?id=1
  q (1 endpoint(s)): /search?q=x
```

## JSON stats block (`--json`)

`--json` output carries a `stats` block next to the `findings` array
for pipeline consumers: per-kind finding counts (every known kind,
zero when absent), the total, the number of script files fetched, and
the scan duration in seconds.

```json
"stats": {
  "total_findings": 12,
  "scripts_fetched": 2,
  "findings_by_kind": {"endpoint": 8, "secret": 1, "interesting": 0,
                       "framework": 1, "comment": 2, "sourcemap": 0,
                       "header": 0},
  "duration_seconds": 1.423
}
```

## Dynamic imports

Code-split chunks loaded via `import("./chunk.js")` are reported as
endpoints with detail "dynamic import": plain quoted-string extraction
misses `./`-relative paths, so chunks never showed up. Relative and
root-relative specifiers resolve against the script file's URL
(`../lib.js` walks one level up); bare module names (`react`) and
template placeholders (`` `./chunk-${name}.js` ``) are skipped, since
they are not fetchable paths.

## HTML report (`--html`)

`--html` writes a single self-contained HTML file (no external
resources): one collapsible `<details>` section per script file, each
listing that file's findings, with a per-kind count summary up top.
Harvested strings are HTML-escaped, so a payload-looking string in a
bundle cannot break out of the report. `--html` and `--json` are
mutually exclusive; combine with `-o` to write the file, or read it
from stdout.

## JWT claim names

JWT findings carry their payload's top-level claim names, decoded from
the middle segment and shown as `(claims: sub, role, exp)` in text and
HTML reports (and as a `claims` field in JSON). This is decode only:
the signature is never verified, so the claims are what the token
*asserts*, not verified facts. Tokens whose payload is not JSON, or
not a JSON object, are still reported as JWT secrets, just without a
claim list.

## Storage and cookie keys

`localStorage`/`sessionStorage` keys (method calls and bracket access)
and cookie names set via `document.cookie` are reported in a STORAGE
section as `localStorage:auth_token`, `sessionStorage:user_id` or
`cookie:session` — only key names, never stored values. The same key
held in two stores stays two findings. Template-literal keys containing
`${...}` are skipped, since the real key is not knowable from the text.

## Notes

- Passive recon aid: it only GETs the page and its own script files.
- Secret patterns are heuristic — verify before treating a hit as a live credential.
- Respects `--timeout`; fetch failures are reported, not fatal.
- Source-map probing is best-effort and silent: missing maps never fail the scan.
