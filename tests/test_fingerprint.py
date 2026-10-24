"""Framework fingerprinting tests — pure unit tests, no network."""
from jsrecon import fingerprint as fp
from jsrecon.extract import dedupe

SRC = "https://target.com/app.js"


def _frameworks(js):
    return {f["value"]: f for f in fp.fingerprint(js, SRC)}


def test_react_detected():
    found = _frameworks("var x = window.__REACT_DEVTOOLS_GLOBAL_HOOK__;")
    assert found["React"]["kind"] == "framework"
    assert "__REACT_DEVTOOLS_GLOBAL_HOOK__" in found["React"]["detail"]


def test_vue_detected():
    found = _frameworks("const app = createApp({}); app.mount('#x')")
    assert found["Vue"]["value"] == "Vue"


def test_angular_detected_with_version():
    found = _frameworks('<app-root ng-version="17.2.0"></app-root>')
    assert found["Angular"]["value"] == "Angular"
    assert "17.2.0" in found["Angular"]["detail"]


def test_next_detected():
    found = _frameworks("var d = document.getElementById('__NEXT_DATA__');")
    assert found["Next.js"]["value"] == "Next.js"


def test_jquery_version_captured():
    found = _frameworks("/*! jQuery v3.7.1 | (c) OpenJS Foundation */")
    assert found["jQuery"]["value"] == "jQuery"
    assert "3.7.1" in found["jQuery"]["detail"]


def test_multiple_stacks_one_finding_each():
    js = "__REACT_DEVTOOLS_GLOBAL_HOOK__; var d = __NEXT_DATA__;"
    found = _frameworks(js)
    assert set(found) == {"React", "Next.js"}
    assert found["React"]["source"] == SRC


def test_no_markers_no_findings():
    assert fp.fingerprint("var x = 1; function f() { return x; }", SRC) == []


def test_plain_word_does_not_match():
    # "react" in prose should not fingerprint; markers are specific.
    assert fp.fingerprint("var reaction = 'slow';", SRC) == []


def test_dedupe_merges_framework_evidence():
    f1 = {"kind": "framework", "value": "React",
          "detail": "__REACT_DEVTOOLS_GLOBAL_HOOK__", "source": "a.js"}
    f2 = {"kind": "framework", "value": "React",
          "detail": "react-dom", "source": "b.js"}
    merged = dedupe([f1, f2])
    assert len(merged) == 1
    assert "__REACT_DEVTOOLS_GLOBAL_HOOK__" in merged[0]["detail"]
    assert "react-dom" in merged[0]["detail"]
    assert merged[0]["sources"] == ["a.js", "b.js"]


def test_merge_framework_detail_idempotent():
    assert fp.merge_framework_detail("a, b", "b, c") == "a, b, c"
