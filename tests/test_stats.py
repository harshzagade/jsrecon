"""JSON stats block: per-kind counts, scripts fetched, scan duration."""
import json

from jsrecon.report import build_stats, render_json


def _finding(kind):
    return {"kind": kind, "value": f"v-{kind}", "detail": "",
            "sources": ["s.js"]}


def test_build_stats_counts_every_kind():
    findings = [_finding("endpoint"), _finding("endpoint"),
                _finding("secret")]
    stats = build_stats(findings, 3, duration=1.23456)
    assert stats["total_findings"] == 3
    assert stats["scripts_fetched"] == 3
    assert stats["findings_by_kind"]["endpoint"] == 2
    assert stats["findings_by_kind"]["secret"] == 1
    # Known kinds with no hits still appear, at zero.
    assert stats["findings_by_kind"]["framework"] == 0
    assert stats["findings_by_kind"]["header"] == 0
    assert stats["duration_seconds"] == 1.235  # rounded to 3 decimals


def test_render_json_stats_block():
    findings = [_finding("endpoint"), _finding("comment")]
    data = json.loads(render_json(findings, "https://example.com", 2, [],
                                  duration=0.5))
    assert data["stats"]["total_findings"] == 2
    assert data["stats"]["scripts_fetched"] == 2
    assert data["stats"]["findings_by_kind"]["comment"] == 1
    assert data["stats"]["duration_seconds"] == 0.5
    # Existing top-level fields are untouched.
    assert data["scripts_fetched"] == 2
    assert len(data["findings"]) == 2


def test_render_json_stats_without_duration():
    # Direct render_json callers that never measured a duration get a
    # stable schema with an explicit null instead of a missing key.
    data = json.loads(render_json([], "https://example.com", 0, []))
    assert data["stats"]["duration_seconds"] is None
    assert data["stats"]["total_findings"] == 0
    assert data["stats"]["findings_by_kind"]["endpoint"] == 0
