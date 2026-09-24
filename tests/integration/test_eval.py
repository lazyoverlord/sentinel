"""Evaluation harness: splits are deterministic and locked; Run A produces sane metrics offline."""
import pytest

from eval.datasets import coverage, load, validate
from eval.perturb import char_noise, homoglyph, typo
from eval.run_eval import run_a, summarize
from eval.splits import get_split, split
from firewall.config import ROOT


def test_core_set_valid_and_covered():
    items = load(ROOT / "data" / "samples" / "core.jsonl")
    assert validate(items) == []
    for k, (got, target) in coverage(items).items():
        assert got >= target, (k, got, target)


def test_split_deterministic_and_test_locked():
    items = load(ROOT / "data" / "samples" / "core.jsonl")
    a, b = split(items), split(items)
    assert {i["id"] for i in a["dev"]} == {i["id"] for i in b["dev"]}
    assert not ({i["id"] for i in a["dev"]} & {i["id"] for i in a["test"]})
    assert 0.5 < len(a["dev"]) / len(items) < 0.7
    with pytest.raises(PermissionError):
        get_split("test", ROOT / "data" / "samples" / "core.jsonl")
    assert get_split("test", ROOT / "data" / "samples" / "core.jsonl", allow_test=True)


def test_run_a_no_benign_false_positives():
    items = get_split("dev", ROOT / "data" / "samples" / "core.jsonl")
    rows = run_a(items)
    sm = summarize(rows)
    assert sm["benign_fpr"]["k"] == 0                       # deterministic layer must not fast-block benign
    assert sm["recall"]["rate"] >= 0.6                      # rules alone catch the obvious ones
    assert all(r["llm_calls"] == 0 for r in rows)          # Run A spends no quota


def test_perturbations_deterministic():
    assert typo("ignore instructions", seed=1) == typo("ignore instructions", seed=1)
    assert homoglyph("ignore", rate=1.0) != "ignore"
    assert "." in char_noise("attack" * 5, rate=1.0)
