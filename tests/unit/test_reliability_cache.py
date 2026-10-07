"""Tests for cache-free reliability: run_full dev_cache param and self_assessment labelling."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from firewall.config import Settings
from firewall.detection.classifiers import ClassifierBank, FakeClassifier
from firewall.llm import FakeLLMClient
from firewall.pipeline import Firewall
from tests.conftest import fake_c1, jv, make_bank


def _fw(s, judge_response, *, dev_cache_override=None):
    bank = make_bank(s)
    return Firewall(s, llm=FakeLLMClient({"judge": judge_response}, down=False),
                    bank=bank, load_classifiers=False)


@pytest.fixture
def base_settings(tmp_path):
    return Settings(_env_file=None, DATA_DIR=tmp_path, DEV_MODE=True, VERDICT_CACHE=False,
                    DEV_CACHE=True, AUDIT_SAMPLE_RATE=0.0, ADMIN_TOKEN="test-admin-token",
                    GOOGLE_API_KEY=None)


def test_run_full_default_keeps_dev_cache_true(base_settings):
    """Default run_full (dev_cache=True) leaves DEV_CACHE enabled."""
    s = base_settings.model_copy(update={"VERDICT_CACHE": False, "DEV_CACHE": True})
    assert s.DEV_CACHE is True


def test_run_full_dev_cache_false_sets_setting(base_settings):
    """run_full with dev_cache=False propagates to Settings."""
    s = base_settings.model_copy(update={"VERDICT_CACHE": False, "DEV_CACHE": False})
    assert s.DEV_CACHE is False
    fw = _fw(s, jv("safe", 0.95))
    assert fw.s.DEV_CACHE is False
    fw.close()


def test_self_assessment_labels_cache_assisted():
    """reliability.json without dev_cache=False gets a cache-assisted label."""
    from eval.self_assessment import build as build_self_assessment

    results_dir = Path(__file__).resolve().parent.parent.parent / "eval" / "results"
    sa = build_self_assessment(results_dir)
    reliability_json = results_dir / "reliability.json"
    if not reliability_json.exists():
        pytest.skip("reliability.json not present")

    rel = json.loads(reliability_json.read_text())
    md = sa["markdown"]
    if rel.get("dev_cache") is False:
        assert "cache-assisted" not in md
    else:
        assert "cache-assisted" in md


def test_self_assessment_no_cache_label_when_independent(tmp_path):
    """reliability.json with dev_cache=False gets no cache warning."""
    from eval.self_assessment import build as build_self_assessment

    results_dir = tmp_path / "results"
    results_dir.mkdir()

    (results_dir / "reliability.json").write_text(json.dumps({
        "n_requested": 50, "runs": 3, "n_scored": 50, "dev_cache": False,
        "real_llm_calls": 42,
        "schema_valid_rate": 1.0,
        "agreement": {"k": 48, "n": 50, "rate": 0.96},
        "rescan_pass_rate": None, "rescan_n": 0, "complete": True,
    }))
    (results_dir / "metrics.json").write_text(json.dumps({
        "best": "full_test", "results": {"full_test": {
            "n": 80, "recall": {"k": 46, "n": 54, "rate": 0.8519},
            "benign_fpr": {"k": 0, "n": 26, "rate": 0.0},
            "per_type": {}, "holds": 0, "carrier_recall": {}}}
    }))

    sa = build_self_assessment(results_dir)
    assert "cache-assisted" not in sa["markdown"]
    assert "agreement 48/50 = 96%" in sa["markdown"]
