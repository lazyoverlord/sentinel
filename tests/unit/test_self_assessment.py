"""Unit tests for eval.self_assessment — no Gemini, no downloads, fixture JSON only."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from eval.self_assessment import build

CLAIM_MD = """\
# Claim

D2

- using 'full_test' (n=80) as the full-firewall recall/FPR result
- (a) all 11 sources pass end-to-end: see pytest
- (b) overall recall 46/54 = 85% (95% CI 73%–92%): BELOW target; per-carrier ≥80% with n≥30: not measured
- (c) benign FPR 0/26 = 0% (95% CI 0%–13%): insufficient sample (n=26, need ≥300)
- (d) reliability (50/50 items × 3 runs): schema-valid 100%, agreement 50/50 = 100%: meets
"""

FULL_TEST = {
    "name": "full_test", "baseline": "full", "split": "test",
    "summary": {
        "n": 80,
        "recall": {"k": 46, "n": 54, "rate": 0.8519, "ci95": [0.734, 0.923]},
        "benign_fpr": {"k": 0, "n": 26, "rate": 0.0, "ci95": [0.0, 0.1287]},
        "per_type": {
            "1": {"k": 19, "n": 20, "rate": 0.95, "ci95": [0.7639, 0.9911]},
            "4": {"k": 2, "n": 4, "rate": 0.5, "ci95": [0.15, 0.85]},
            "7": {"k": 2, "n": 5, "rate": 0.4, "ci95": [0.1176, 0.7693]},
        },
        "p50_ms": 301.4,
        "llm_calls_per_1k": 462.5,
        "misses": ["seed-t7-05", "seed-t4-06"],
        "false_positives": [],
    },
}

RELIABILITY = {
    "n_requested": 50, "runs": 3, "n_scored": 50,
    "schema_valid_rate": 1.0,
    "agreement": {"k": 50, "n": 50, "rate": 1.0},
    "rescan_pass_rate": None, "rescan_n": 0, "complete": True,
}

METRICS = {"full_test": FULL_TEST["summary"]}


@pytest.fixture()
def results_dir(tmp_path: Path) -> Path:
    d = tmp_path / "results"
    d.mkdir()
    (d / "claim.md").write_text(CLAIM_MD)
    (d / "full_test.json").write_text(json.dumps(FULL_TEST))
    (d / "reliability.json").write_text(json.dumps(RELIABILITY))
    (d / "metrics.json").write_text(json.dumps(METRICS))
    return d


def test_complete_files(results_dir: Path):
    sa = build(results_dir)
    assert sa["d_claim"] == "D2"
    assert sa["claim"] == "F3 · D2"
    assert "46/54" in sa["evidence"]["recall"]
    assert "0/26" in sa["evidence"]["benign_fpr"]
    assert sa["evidence"]["p50_ms"] == "301.4 ms"
    assert sa["evidence"]["llm_calls_per_1k"] == "462.5"
    assert "50/50" in sa["evidence"]["reliability"]
    assert len(sa["evidence"]["per_type"]) == 3
    assert "below 80%" in sa["evidence"]["per_type"][1]["flags"]  # type 4 at 50%
    assert "below 80%" in sa["evidence"]["per_type"][2]["flags"]  # type 7 at 40%
    assert "low n" in sa["evidence"]["per_type"][1]["flags"]  # type 4 n=4
    assert len(sa["why_not_d3"]) >= 1
    assert any("BELOW" in w for w in sa["why_not_d3"])
    assert "Experimental" in sa["markdown"]
    assert "seed-t7-05" in sa["markdown"]
    assert "F evidence" in sa["markdown"]
    assert "D evidence" in sa["markdown"]


def test_missing_files(tmp_path: Path):
    d = tmp_path / "empty"
    d.mkdir()
    sa = build(d)
    assert "D2" in sa["d_claim"]
    assert sa["evidence"]["recall"] == "not generated"
    assert sa["evidence"]["benign_fpr"] == "not generated"
    assert sa["evidence"]["p50_ms"] == "not generated"
    assert sa["evidence"]["reliability"] == "not generated"
    assert sa["evidence"]["per_type"] == []
    assert sa["evidence"]["f_evidence"]["types_detected"] == "0/9"


def test_rescan_not_exercised(results_dir: Path):
    sa = build(results_dir)
    assert "not exercised (n=0)" in sa["evidence"]["reliability"]


def test_per_type_below_80_flagged(results_dir: Path):
    sa = build(results_dir)
    types = {r["type"]: r for r in sa["evidence"]["per_type"]}
    assert "below 80%" in types["4"]["flags"]
    assert "below 80%" in types["7"]["flags"]
    assert "below 80%" not in types["1"]["flags"]


def test_low_n_flagged(results_dir: Path):
    sa = build(results_dir)
    types = {r["type"]: r for r in sa["evidence"]["per_type"]}
    assert "low n" in types["4"]["flags"]  # n=4
    assert "low n" in types["7"]["flags"]  # n=5
    assert "low n" not in types["1"]["flags"]  # n=20


def test_types_detected_count(results_dir: Path):
    sa = build(results_dir)
    assert sa["evidence"]["f_evidence"]["types_detected"] == "3/9"
    assert "3/9" in sa["markdown"]
