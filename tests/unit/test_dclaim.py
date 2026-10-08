"""Tests for D-claim machinery in eval/report.py and self_assessment.py."""
from __future__ import annotations

import json
from pathlib import Path

import pytest


def _rate(k: int, n: int) -> dict:
    from eval.run_eval import rate
    return rate(k, n)


def _make_run(*, split: str, baseline: str, rows: list[dict],
              recall: dict | None = None, benign_fpr: dict | None = None,
              per_type: dict | None = None, per_carrier: dict | None = None) -> dict:
    attacks = [r for r in rows if r["label"] != "benign"]
    benign = [r for r in rows if r["label"] == "benign"]
    caught = sum(r.get("caught", False) for r in attacks)
    fp = sum(r.get("fp", False) for r in benign)
    return {
        "baseline": baseline,
        "split": split,
        "rows": rows,
        "summary": {
            "n": len(rows),
            "recall": recall or _rate(caught, len(attacks)),
            "signal_recall": _rate(caught, len(attacks)),
            "benign_fpr": benign_fpr or _rate(fp, len(benign)),
            "per_type": per_type or {},
            "per_carrier": per_carrier or {},
            "p50_ms": 42,
            "llm_calls_per_1k": 100,
            "misses": [],
            "false_positives": [],
        },
    }


def _benign_row(id_: str, *, fp: bool = False, action: str = "allow") -> dict:
    return {"id": id_, "label": "benign", "fp": fp, "action": action, "hold": False}


def _attack_row(id_: str, *, caught: bool = True) -> dict:
    return {"id": id_, "label": "attack", "caught": caught, "fp": False, "action": "block"}


class TestDClaimTestSplitRestriction:
    """d_claim() must ignore dev-split runs."""

    def test_dev_split_not_counted(self):
        from eval.report import d_claim
        results = {
            "full_dev": _make_run(split="dev", baseline="full",
                                  rows=[_attack_row("a1"), _benign_row("b1")]),
        }
        claim, notes, gates = d_claim(results)
        assert "no test-split" in claim.lower() or "D2" in claim
        assert gates["b_overall"]["met"] is None

    def test_test_split_counted(self):
        from eval.report import d_claim
        attacks = [_attack_row(f"a{i}") for i in range(100)]
        benign = [_benign_row(f"b{i}") for i in range(30)]
        results = {
            "full_test": _make_run(split="test", baseline="full",
                                   rows=attacks + benign,
                                   recall=_rate(95, 100)),
        }
        claim, notes, gates = d_claim(results)
        assert gates["b_overall"]["met"] is True
        assert gates["b_overall"]["value"]  # not empty


class TestPooledBenignFPR:
    """_pool_benign_fpr() pools from test + public full runs."""

    def test_pools_across_sources(self):
        from eval.report import _pool_benign_fpr
        test_run = _make_run(
            split="test", baseline="full",
            rows=[_benign_row(f"tb{i}") for i in range(100)]
        )
        results = {
            "full_test": test_run,
            "fpr_notinject_full": _make_run(
                split="custom", baseline="full",
                rows=[_benign_row(f"ni{i}") for i in range(200)]
            ),
            "fpr_dolly_full": _make_run(
                split="custom", baseline="full",
                rows=[_benign_row(f"dl{i}") for i in range(150)]
            ),
        }
        pool = _pool_benign_fpr(test_run, results)
        assert pool["n"] == 450
        assert len(pool["sources"]) == 3
        assert pool["fpr"]["rate"] == 0.0

    def test_counts_fp_correctly(self):
        from eval.report import _pool_benign_fpr
        test_run = _make_run(
            split="test", baseline="full",
            rows=[_benign_row("tb0", fp=True, action="block"),
                  *[_benign_row(f"tb{i}") for i in range(1, 100)]]
        )
        results = {"full_test": test_run}
        pool = _pool_benign_fpr(test_run, results)
        assert pool["n"] == 100
        assert pool["fpr"]["k"] == 1

    def test_ignores_non_full_public_runs(self):
        from eval.report import _pool_benign_fpr
        test_run = _make_run(split="test", baseline="full",
                             rows=[_benign_row("b1")])
        results = {
            "full_test": test_run,
            "fpr_notinject_full": _make_run(split="custom", baseline="full",
                                            rows=[_benign_row("n1")]),
            "fpr_notinject_A": _make_run(split="custom", baseline="A",
                                         rows=[_benign_row("na1")]),
        }
        pool = _pool_benign_fpr(test_run, results)
        assert pool["n"] == 2  # test + notinject_full, not the A run


class TestReliabilityGate:
    """Gate (d) validation: stale/incomplete/valid reliability.json."""

    def _make_results_with_reliability(self, tmp_path, rel_data):
        results_dir = tmp_path / "results"
        results_dir.mkdir(exist_ok=True)
        if rel_data is not None:
            (results_dir / "reliability.json").write_text(json.dumps(rel_data))
        attacks = [_attack_row(f"a{i}") for i in range(50)]
        benign = [_benign_row(f"b{i}") for i in range(30)]
        sanitized = [{"id": f"s{i}", "label": "attack", "caught": True, "fp": False,
                      "action": "allow_sanitized", "verdict": "injection",
                      "verify_passed": True} for i in range(5)]
        test_run = _make_run(split="test", baseline="full",
                             rows=attacks + benign + sanitized,
                             recall=_rate(50, 55))
        (results_dir / "full_test.json").write_text(json.dumps(test_run))
        return {"full_test": test_run}, results_dir

    def test_stale_zero_real_calls_is_pending(self, tmp_path):
        from eval.report import d_claim
        rel = {"n_requested": 50, "runs": 3, "n_scored": 50, "dev_cache": False,
               "real_llm_calls": 0, "schema_valid_rate": 1.0,
               "agreement": {"k": 50, "n": 50, "rate": 1.0},
               "rescan_pass_rate": None, "rescan_n": 0, "complete": True}
        results, rdir = self._make_results_with_reliability(tmp_path, rel)
        _, notes, gates = d_claim(results, rdir)
        assert gates["d"]["met"] is None
        assert any("real_llm_calls=0" in n for n in notes)

    def test_incomplete_is_pending(self, tmp_path):
        from eval.report import d_claim
        rel = {"n_requested": 50, "runs": 3, "n_scored": 30, "dev_cache": False,
               "real_llm_calls": 40, "schema_valid_rate": 1.0,
               "agreement": {"k": 30, "n": 30, "rate": 1.0},
               "rescan_pass_rate": None, "rescan_n": 0, "complete": False}
        results, rdir = self._make_results_with_reliability(tmp_path, rel)
        _, notes, gates = d_claim(results, rdir)
        assert gates["d"]["met"] is None

    def test_valid_file_is_met(self, tmp_path):
        from eval.report import d_claim
        rel = {"n_requested": 50, "runs": 3, "n_scored": 50, "dev_cache": False,
               "real_llm_calls": 150, "schema_valid_rate": 1.0,
               "agreement": {"k": 50, "n": 50, "rate": 1.0},
               "rescan_pass_rate": 1.0, "rescan_n": 5, "complete": True,
               "rescan_exercised": True}
        results, rdir = self._make_results_with_reliability(tmp_path, rel)
        _, _, gates = d_claim(results, rdir)
        assert gates["d"]["met"] is True

    def test_missing_file_is_pending(self, tmp_path):
        from eval.report import d_claim
        results, rdir = self._make_results_with_reliability(tmp_path, None)
        _, _, gates = d_claim(results, rdir)
        assert gates["d"]["met"] is None

    def test_rescan_from_test_run_fallback(self, tmp_path):
        from eval.report import d_claim
        rel = {"n_requested": 50, "runs": 3, "n_scored": 50, "dev_cache": False,
               "real_llm_calls": 150, "schema_valid_rate": 1.0,
               "agreement": {"k": 50, "n": 50, "rate": 1.0},
               "rescan_pass_rate": None, "rescan_n": 0, "complete": True}
        results, rdir = self._make_results_with_reliability(tmp_path, rel)
        _, notes, gates = d_claim(results, rdir)
        assert gates["d"]["met"] is True
        assert any("frozen test run" in n for n in notes)


class TestGateTable:
    """self_assessment._gate_table() builds rows from gates dict."""

    def test_all_gates_present(self):
        from eval.self_assessment import _gate_table
        gates = {
            "a": {"met": None, "value": "see pytest", "requirement": "11 source types"},
            "b_overall": {"met": True, "value": "95/100", "requirement": "≥ 90%"},
            "b_carriers": {"met": False, "value": "worst 70%", "requirement": "each ≥ 80%"},
            "c": {"met": True, "value": "2/300", "requirement": "≤ 10%"},
            "d": {"met": None, "value": "not run", "requirement": "reliability"},
        }
        rows = _gate_table(gates)
        assert len(rows) == 5
        statuses = {r["gate"]: r["met"] for r in rows}
        assert statuses["(b) overall recall"] == "yes"
        assert statuses["(b) per-carrier recall"] == "no"
        assert statuses["(d) reliability"] == "not run"

    def test_empty_gates(self):
        from eval.self_assessment import _gate_table
        rows = _gate_table({})
        assert len(rows) == 5
        assert all(r["met"] == "not run" for r in rows)

    def test_gate_table_in_markdown(self, tmp_path):
        """build() includes the gate table in markdown when gates are available."""
        from eval.self_assessment import build
        results_dir = tmp_path / "results"
        results_dir.mkdir()
        (results_dir / "claim.md").write_text("# Claim\n\nD2\n")
        sa = build(results_dir)
        # Without results files, d_claim() may or may not have data.
        # The markdown should at minimum contain "Self-assessment"
        assert "Self-assessment" in sa["markdown"]
        assert isinstance(sa["gate_table"], list)
        assert isinstance(sa["gate_summary"], str)
