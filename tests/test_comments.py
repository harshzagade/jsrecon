"""Comment harvester tests — pure unit tests, no network."""
from jsrecon.comments import extract_comments


def _comments(js):
    return extract_comments(js, "app.js")


def test_line_comment():
    hits = _comments("// hello world\nvar a = 1;")
    assert len(hits) == 1
    assert hits[0]["kind"] == "comment"
    assert hits[0]["value"] == "hello world"
    assert hits[0]["detail"] == ""


def test_block_comment_collapsed():
    js = "/* first line\n * second line\n * third */\nvar a = 1;"
    hits = _comments(js)
    assert len(hits) == 1
    assert hits[0]["value"] == "first line second line third"


def test_todo_tag_and_internal_url():
    hits = _comments("// TODO: remove before prod\n"
                     "// see https://internal.corp/api/debug for details\n"
                     "// FIXME later\n")
    by_value = {h["value"]: h["detail"] for h in hits}
    assert by_value["TODO: remove before prod"] == "TODO"
    assert by_value["see https://internal.corp/api/debug for details"] == "internal URL"
    assert by_value["FIXME later"] == "FIXME"


def test_slashes_in_strings_are_not_comments():
    js = ('var u = "https://api.example.com/charge";\n'
          "var v = 'http://cdn.example.com/lib.js';\n"
          "var t = `https://x.example/a`;\n")
    assert _comments(js) == []


def test_slashes_in_regex_are_not_comments():
    js = "var re = /https:\\/\\//;\nvar ok = re.test(u); // real comment\n"
    hits = _comments(js)
    assert [h["value"] for h in hits] == ["real comment"]


def test_division_not_a_comment():
    js = "var q = a / b / c;\nvar r = x / 2; // trailing note\n"
    hits = _comments(js)
    assert [h["value"] for h in hits] == ["trailing note"]


def test_sourcemap_directives_skipped():
    js = ("//# sourceMappingURL=app.js.map\n"
          "/*# sourceMappingURL=app.js.map */\n"
          "//@ sourceMappingURL=app.js.map\n"
          "// kept\n")
    hits = _comments(js)
    assert [h["value"] for h in hits] == ["kept"]


def test_template_interpolation_comment():
    js = "var s = `value ${f(1)} end`; // after template\n"
    hits = _comments(js)
    assert [h["value"] for h in hits] == ["after template"]


def test_empty_and_long_comments():
    assert _comments("//\n/**/\nvar a = 1;") == []
    hits = _comments("// " + "x" * 300 + "\n")
    assert hits[0]["value"].endswith("...")
    assert len(hits[0]["value"]) == 203
