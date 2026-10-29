"""Dynamic-import specifiers become endpoints, resolved vs the script URL."""
from jsrecon import extract as ex

SRC = "https://example.com/static/app.js"


def _endpoints(js, source=SRC):
    return [f for f in ex.extract(js, source) if f["kind"] == "endpoint"]


def test_relative_chunk_resolves_against_script_url():
    hits = _endpoints('const m = await import("./chunk-abc.js");')
    assert hits == [{"kind": "endpoint",
                     "value": "https://example.com/static/chunk-abc.js",
                     "detail": "dynamic import", "source": SRC,
                     "score": ex.score_endpoint(
                         "https://example.com/static/chunk-abc.js")}]


def test_parent_relative_resolves_one_level_up():
    hits = _endpoints('import("../lib/utils.js");')
    assert [h["value"] for h in hits] == ["https://example.com/lib/utils.js"]


def test_root_relative_and_absolute_kept():
    hits = _endpoints('import("/static/lazy.js"); import("https://cdn.example.com/x.js");')
    assert [h["value"] for h in hits] == [
        "https://example.com/static/lazy.js", "https://cdn.example.com/x.js"]


def test_bare_module_names_skipped():
    assert _endpoints('import("react"); import("lodash/fp");') == []


def test_template_placeholder_skipped():
    assert _endpoints('import(`./chunk-${name}.js`);') == []


def test_non_url_source_keeps_raw_specifier():
    # Source-map labels are not URLs, so no resolution is possible;
    # the chunk name itself is still reported.
    hits = _endpoints('import("./chunk.js");',
                      source="https://example.com/app.js [source map: src/a.js]")
    assert [h["value"] for h in hits] == ["./chunk.js"]


def test_dedupe_keeps_dynamic_import_detail():
    # The same path quoted elsewhere is claimed by the import pass, so
    # it appears once, resolved, with the "dynamic import" detail —
    # not twice (once relative, once resolved).
    js = 'var p = "/static/lazy.js"; import("/static/lazy.js");'
    hits = ex.dedupe(ex.extract(js, SRC))
    lazy = [f for f in hits if "lazy.js" in f["value"]]
    assert len(lazy) == 1
    assert lazy[0]["value"] == "https://example.com/static/lazy.js"
    assert lazy[0]["detail"] == "dynamic import"


def test_plain_quoted_relative_path_still_not_an_endpoint():
    # Only import() specifiers gain relative-path treatment; a bare
    # "./x.js" string elsewhere is unchanged behaviour.
    assert _endpoints('var p = "./not-imported.js";') == []
