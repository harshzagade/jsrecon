"""Pull comments out of JavaScript, separately from code and strings.

Why a scanner instead of a regex: ``//`` also appears inside string
literals (``"https://..."``) and regex literals (escaped slashes inside
``/.../`` patterns), and a
naive ``//.*`` match would report those as comments. The scanner below
walks the source tracking string/template/regex state, so only real
comments are returned. ``//`` and ``/* */`` are always comments in JS
(the lexer is greedy), so no division-vs-comment ambiguity exists for
adjacent slashes; a lone ``/`` is division or a regex literal.

Skipped: sourceMappingURL directives (``//#`` / ``/*#`` / ``//@``) — the
sourcemap module already mines those — and empty comments.
"""
import re

_TAG_RE = re.compile(r"\b(TODO|FIXME|XXX|HACK)\b", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s\"'<>]+|/[A-Za-z0-9_.\-]+(?:/[A-Za-z0-9_.\-]+)+")
_KEYWORD_BEFORE_REGEX_RE = re.compile(
    r"(return|typeof|case|delete|void|in|of|new|else|do)\s*$")
# A lone "/" starts a regex (not division) after an operator, an opener,
# or a keyword — otherwise it is division.
_REGEX_OK_PREV = set("=(:,!&|?{};<>+-*%~^")

_MAX_VALUE = 200


def _tag_or_url(text):
    """Detail for a comment: its TODO-style tag, an internal-URL note, or ""."""
    m = _TAG_RE.search(text)
    if m:
        return m.group(1).upper()
    if _URL_RE.search(text):
        return "internal URL"
    return ""


def _clean_block(raw):
    """Collapse a block comment: strip one leading '*' per line, join lines."""
    lines = []
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("*"):
            line = line[1:].strip()
        if line:
            lines.append(line)
    return " ".join(lines)


def _skip_regex(text, i):
    """Skip a regex literal starting at text[i] == '/'. Returns end index.

    Handles escapes and character classes (where '/' does not terminate).
    """
    n = len(text)
    i += 1
    in_class = False
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            in_class = True
        elif c == "]":
            in_class = False
        elif c == "/" and not in_class:
            i += 1
            while i < n and text[i].isalpha():  # flags: g, i, m, s, u, y
                i += 1
            return i
        elif c == "\n":
            return i  # unterminated regex; bail out rather than swallowing
        i += 1
    return i


def extract_comments(js_text, source):
    """Return comment findings: {kind, value, detail, source}.

    *value* is the comment text (whitespace-collapsed, truncated);
    *detail* is a TODO-style tag (TODO/FIXME/XXX/HACK), "internal URL"
    when the comment mentions a URL/path, or "".
    """
    findings = []
    n = len(js_text)
    i = 0
    # Stack of frames: ("string", quote) | ("template",) | ("code", braces)
    # A "code" frame with braces != None is a ${...} interpolation inside a
    # template; its braces count closes back to the template.
    stack = [("code", None)]
    prev_sig = ""  # last significant char seen in code (for regex checks)

    def _emit(raw, block):
        text = _clean_block(raw) if block else raw.strip()
        if not text or text.startswith(("#", "@")):
            return
        if len(text) > _MAX_VALUE:
            text = text[:_MAX_VALUE] + "..."
        findings.append({"kind": "comment", "value": text,
                         "detail": _tag_or_url(text), "source": source})

    while i < n:
        frame, arg = stack[-1]
        c = js_text[i]
        if frame == "string":
            if c == "\\":
                i += 2
                continue
            if c == arg:
                stack.pop()
                prev_sig = c
            i += 1
            continue
        if frame == "template":
            if c == "\\":
                i += 2
                continue
            if c == "`":
                stack.pop()
                prev_sig = c
                i += 1
                continue
            if c == "$" and i + 1 < n and js_text[i + 1] == "{":
                stack.append(("code", 1))
                i += 2
                continue
            i += 1
            continue
        # frame == "code"
        if c in ("'", '"'):
            stack.append(("string", c))
            i += 1
            continue
        if c == "`":
            stack.append(("template", None))
            i += 1
            continue
        if c == "{":
            if arg is not None:
                stack[-1] = ("code", arg + 1)
            i += 1
            prev_sig = c
            continue
        if c == "}":
            if arg is not None:
                if arg == 1:
                    stack.pop()
                    prev_sig = c
                    i += 1
                    continue
                stack[-1] = ("code", arg - 1)
            i += 1
            prev_sig = c
            continue
        if c == "/":
            nxt = js_text[i + 1] if i + 1 < n else ""
            if nxt == "/":
                end = js_text.find("\n", i)
                end = n if end == -1 else end
                _emit(js_text[i + 2:end], block=False)
                i = end
                prev_sig = ""
                continue
            if nxt == "*":
                end = js_text.find("*/", i + 2)
                end = n if end == -1 else end
                _emit(js_text[i + 2:end], block=True)
                i = end + 2 if end < n else n
                prev_sig = ""
                continue
            # Lone slash: regex or division.
            before = js_text[:i].rstrip()
            if (not prev_sig or prev_sig in _REGEX_OK_PREV
                    or _KEYWORD_BEFORE_REGEX_RE.search(before)):
                i = _skip_regex(js_text, i)
            else:
                i += 1
            prev_sig = "/"
            continue
        if not c.isspace():
            prev_sig = c
        i += 1
    return findings
