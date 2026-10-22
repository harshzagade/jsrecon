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
```

## Sample output

```
$ jsrecon http://127.0.0.1:8931
[+] fetched http://127.0.0.1:8931/ (2 script files)

== ENDPOINTS (4) ==
  /api/v1/users            <- http://127.0.0.1:8931/static/app.js
  /api/v1/login            <- http://127.0.0.1:8931/static/app.js
  https://api.payments.example.com/charge
                           <- http://127.0.0.1:8931/static/vendor.js
  /graphql                 <- http://127.0.0.1:8931/static/app.js

== SECRETS (2) ==
  [!] AWS Access Key ID: AKIAIOSFODNN7EXAMPLE
      <- http://127.0.0.1:8931/static/app.js
  [!] Generic API key assignment: api_key = "sk_test_51H..."
      <- http://127.0.0.1:8931/static/app.js

== INTERESTING (1) ==
  [~] long base64 blob (88 chars)
      <- http://127.0.0.1:8931/static/vendor.js
```

## How it works

1. Fetches the page, collects every `<script src>` (resolved against the page URL).
2. Downloads each JS file (optionally also inline `<script>` blocks).
3. Pulls every quoted string out of the JS and classifies it:
   - **endpoint** — absolute URL or root-relative path with letters in it
   - **secret** — matches a known credential pattern (AWS keys, tokens, JWTs, ...)
   - **interesting** — long base64/hex blobs that smell like encoded data
4. Dedupes across files, keeps the source file for every hit.

## Notes

- Passive recon aid: it only GETs the page and its own script files.
- Secret patterns are heuristic — verify before treating a hit as a live credential.
- Respects `--timeout`; fetch failures are reported, not fatal.
