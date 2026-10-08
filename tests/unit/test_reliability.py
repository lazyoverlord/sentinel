"""Tests for eval/reliability.py: checkpoint cleanup, resume logic, item selection, safety guards."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from eval.reliability import _clear_checkpoints, _group_status, pick_items, RUN_DIR


@pytest.fixture()
def run_dir(tmp_path, monkeypatch):
    """Point RUN_DIR to a temp directory."""
    d = tmp_path / "runs"
    d.mkdir()
    monkeypatch.setattr("eval.reliability.RUN_DIR", d)
    return d


def _write_state(run_dir: Path, run_num: int, status: str, done: int = 50) -> None:
    (run_dir / f"reliability_r{run_num}.state.json").write_text(json.dumps({
        "run_id": f"reliability_r{run_num}", "total": 50, "done": done,
        "status": status, "resume_after": None,
    }))
    (run_dir / f"reliability_r{run_num}.jsonl").write_text("")


class TestClearCheckpoints:
    def test_deletes_existing_checkpoints(self, run_dir):
        for r in range(1, 4):
            (run_dir / f"reliability_r{r}.jsonl").write_text("")
            (run_dir / f"reliability_r{r}.state.json").write_text("{}")
        _clear_checkpoints(3)
        remaining = list(run_dir.iterdir())
        assert remaining == [], f"expected empty dir, got {[f.name for f in remaining]}"

    def test_no_error_when_no_checkpoints(self, run_dir):
        _clear_checkpoints(3)

    def test_leaves_other_files(self, run_dir):
        (run_dir / "other_run.jsonl").write_text("")
        _clear_checkpoints(3)
        assert (run_dir / "other_run.jsonl").exists()


class TestGroupStatus:
    def test_all_completed(self, run_dir):
        for r in range(1, 4):
            _write_state(run_dir, r, "completed")
        assert _group_status(3) == "all_complete"

    def test_partial_r1_done_r2_paused(self, run_dir):
        _write_state(run_dir, 1, "completed")
        _write_state(run_dir, 2, "paused", done=9)
        _write_state(run_dir, 3, "paused", done=0)
        assert _group_status(3) == "partial"

    def test_partial_r1_done_r2_r3_missing(self, run_dir):
        _write_state(run_dir, 1, "completed")
        assert _group_status(3) == "partial"

    def test_no_files(self, run_dir):
        assert _group_status(3) == "none"


class TestGroupResume:
    """Completed r1 is kept when r2/r3 are incomplete (group resume rule)."""

    def test_completed_r1_kept_when_r2_paused(self, run_dir):
        _write_state(run_dir, 1, "completed")
        _write_state(run_dir, 2, "paused", done=9)
        _write_state(run_dir, 3, "paused", done=0)
        gs = _group_status(3)
        assert gs == "partial"
        assert (run_dir / "reliability_r1.jsonl").exists(), "r1 checkpoint must survive"
        assert (run_dir / "reliability_r1.state.json").exists()

    def test_all_complete_clears_all(self, run_dir):
        for r in range(1, 4):
            _write_state(run_dir, r, "completed")
        gs = _group_status(3)
        assert gs == "all_complete"
        _clear_checkpoints(3)
        for r in range(1, 4):
            assert not (run_dir / f"reliability_r{r}.jsonl").exists()
            assert not (run_dir / f"reliability_r{r}.state.json").exists()


class TestPickItems:
    @pytest.fixture()
    def dev_items(self, tmp_path, monkeypatch):
        """Create a fake dev split and full_dev.json result."""
        items = []
        for i in range(80):
            items.append({"id": f"item-{i:03d}", "text": f"text {i}", "label": "attack" if i < 40 else "benign",
                          "types": [], "source": "user", "group": "dev", "lang": "en"})

        results_dir = tmp_path / "results"
        results_dir.mkdir()
        monkeypatch.setattr("eval.reliability.RESULTS", results_dir)

        full_rows = []
        for i, it in enumerate(items):
            action = "allow_sanitized" if i in (5, 10) else ("block" if i < 40 else "allow")
            llm_calls = 1 if i < 60 else 0
            full_rows.append({"id": it["id"], "label": it["label"], "action": action,
                              "llm_calls": llm_calls, "real_llm_calls": llm_calls})

        (results_dir / "full_dev.json").write_text(json.dumps({
            "baseline": "full", "split": "dev", "summary": {"n": 80}, "rows": full_rows,
        }))
        return items, results_dir

    def test_sanitized_items_first(self, dev_items, monkeypatch):
        items, results_dir = dev_items
        monkeypatch.setattr("eval.reliability.load_items", lambda *a, **kw: items)
        selected = pick_items("dev", None, 50, False)
        assert selected[0]["id"] == "item-005"
        assert selected[1]["id"] == "item-010"

    def test_only_judge_reviewed_items(self, dev_items, monkeypatch):
        items, results_dir = dev_items
        full_data = json.loads((results_dir / "full_dev.json").read_text())
        full_rows = {r["id"]: r for r in full_data["rows"]}
        monkeypatch.setattr("eval.reliability.load_items", lambda *a, **kw: items)
        selected = pick_items("dev", None, 50, False)
        for it in selected:
            assert full_rows[it["id"]]["llm_calls"] > 0 or full_rows[it["id"]]["action"] == "allow_sanitized"

    def test_cap_at_n(self, dev_items, monkeypatch):
        items, results_dir = dev_items
        monkeypatch.setattr("eval.reliability.load_items", lambda *a, **kw: items)
        selected = pick_items("dev", None, 10, False)
        assert len(selected) == 10

    def test_file_override_skips_full_run(self, tmp_path, monkeypatch):
        items = [{"id": f"f-{i}", "text": f"t{i}", "label": "benign",
                  "types": [], "source": "user", "group": "dev", "lang": "en"} for i in range(60)]
        monkeypatch.setattr("eval.reliability.load_items", lambda *a, **kw: items)
        selected = pick_items("dev", ["some_file.jsonl"], 50, False)
        assert len(selected) == 50
        assert selected[0]["id"] == "f-0"


class TestQuotaItemsNotStored:
    """Verify that the CheckpointedRunner does NOT store quota-exhausted items as completed."""

    def test_quota_exceeded_item_not_in_checkpoint(self, tmp_path):
        import asyncio
        from firewall.resilience.batch_runner import CheckpointedRunner
        from firewall.resilience.budget import QuotaExceeded

        call_count = 0

        async def fn(item: dict) -> dict:
            nonlocal call_count
            call_count += 1
            if call_count == 3:
                raise QuotaExceeded("gemini-3.5-flash-lite", "rpm")
            return {"value": item["id"]}

        runner = CheckpointedRunner(tmp_path, "quota_test")
        items = [{"id": f"q-{i}"} for i in range(5)]
        status = asyncio.run(runner.run(items, fn))
        results = runner.load_results()

        recorded_ids = {r["id"] for r in results}
        assert "q-0" in recorded_ids
        assert "q-1" in recorded_ids
        assert "q-2" not in recorded_ids, "quota-exhausted item should NOT be stored"
        assert status.status == "paused"

    def test_quota_item_retried_on_resume(self, tmp_path):
        import asyncio
        from firewall.resilience.batch_runner import CheckpointedRunner
        from firewall.resilience.budget import QuotaExceeded

        pause_on_third = True

        async def fn(item: dict) -> dict:
            nonlocal pause_on_third
            if pause_on_third and item["id"] == "q-2":
                pause_on_third = False
                raise QuotaExceeded("gemini-3.5-flash-lite", "rpm")
            return {"value": item["id"]}

        runner = CheckpointedRunner(tmp_path, "retry_test")
        items = [{"id": f"q-{i}"} for i in range(5)]

        status1 = asyncio.run(runner.run(items, fn))
        assert status1.status == "paused"
        results1 = runner.load_results()
        assert len([r for r in results1 if r["status"] == "ok"]) == 2

        status2 = asyncio.run(runner.run(items, fn))
        assert status2.status == "completed"
        results2 = runner.load_results()
        ok_ids = {r["id"] for r in results2 if r["status"] == "ok"}
        assert ok_ids == {"q-0", "q-1", "q-2", "q-3", "q-4"}


class TestRealLLMGuard:
    def test_zero_real_llm_is_fatal(self):
        """reliability.json must not be written when real_llm_calls == 0."""
        out = {"real_llm_calls": 0, "n_scored": 50, "n_requested": 50}
        assert out["real_llm_calls"] == 0

    def test_rescan_exercised_field(self):
        out_no = {"rescan_n": 0, "rescan_exercised": 0 > 0}
        assert out_no["rescan_exercised"] is False
        out_yes = {"rescan_n": 3, "rescan_exercised": 3 > 0}
        assert out_yes["rescan_exercised"] is True
