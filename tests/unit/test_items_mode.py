"""Tests for --items / --tag mode in eval/run_eval.py."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
RUN_EVAL = [sys.executable, "-m", "eval.run_eval"]
RESULTS = ROOT / "eval" / "results"


@pytest.fixture()
def tiny_jsonl(tmp_path):
    items = [
        {"id": "b1", "text": "What is the capital of France?", "label": "benign",
         "types": [], "source": "user", "group": "test", "lang": "en"},
        {"id": "b2", "text": "Summarize this article about dogs.", "label": "benign",
         "types": [], "source": "user", "group": "test", "lang": "en"},
    ]
    p = tmp_path / "tiny.jsonl"
    p.write_text("\n".join(json.dumps(i) for i in items))
    return str(p)


def test_items_loads_jsonl(tiny_jsonl, tmp_path):
    tag = f"_test_items_{id(tmp_path)}"
    out = RESULTS / f"{tag}.json"
    try:
        r = subprocess.run(
            [*RUN_EVAL, "--items", tiny_jsonl, "--tag", tag],
            capture_output=True, text=True, cwd=str(ROOT), timeout=30,
        )
        assert r.returncode == 0, r.stderr
        assert out.exists(), f"expected {out}"
        data = json.loads(out.read_text())
        assert data["split"] == "custom"
        assert data["items_file"] == tiny_jsonl
        assert len(data["rows"]) == 2
        assert data["benign_fpr_detail"]["n"] == 2
    finally:
        out.unlink(missing_ok=True)


def test_full_test_untouched(tiny_jsonl, tmp_path):
    """--items never writes to full_test.json."""
    ft = RESULTS / "full_test.json"
    mtime_before = ft.stat().st_mtime if ft.exists() else None
    tag = f"_test_untouched_{id(tmp_path)}"
    out = RESULTS / f"{tag}.json"
    try:
        subprocess.run(
            [*RUN_EVAL, "--items", tiny_jsonl, "--tag", tag],
            capture_output=True, text=True, cwd=str(ROOT), timeout=30,
        )
        if ft.exists():
            assert ft.stat().st_mtime == mtime_before
    finally:
        out.unlink(missing_ok=True)


def test_items_requires_tag(tiny_jsonl):
    r = subprocess.run(
        [*RUN_EVAL, "--items", tiny_jsonl],
        capture_output=True, text=True, cwd=str(ROOT), timeout=10,
    )
    assert r.returncode != 0
    assert "--tag" in r.stderr


def test_gemini_guard_refuses_llm(tiny_jsonl):
    r = subprocess.run(
        [*RUN_EVAL, "--items", tiny_jsonl, "--tag", "_test_guard", "--baseline", "llm"],
        capture_output=True, text=True, cwd=str(ROOT), timeout=10,
    )
    assert r.returncode != 0
    assert "--allow-gemini" in r.stderr


def test_gemini_guard_refuses_full(tiny_jsonl):
    r = subprocess.run(
        [*RUN_EVAL, "--items", tiny_jsonl, "--tag", "_test_guard", "--baseline", "full"],
        capture_output=True, text=True, cwd=str(ROOT), timeout=10,
    )
    assert r.returncode != 0
    assert "--allow-gemini" in r.stderr


def test_items_with_freezing_rejected(tiny_jsonl):
    r = subprocess.run(
        [*RUN_EVAL, "--items", tiny_jsonl, "--tag", "_test_freeze", "--i-am-freezing"],
        capture_output=True, text=True, cwd=str(ROOT), timeout=10,
    )
    assert r.returncode != 0
    assert "mutually exclusive" in r.stderr
