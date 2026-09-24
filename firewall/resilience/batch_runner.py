"""Checkpointed batch runner (SPEC §12) for eval and red-team runs on the free tier.

- Every finished item is appended to `run_dir/<run_id>.jsonl` right away (flush + fsync), so a
  crash, Ctrl-C or quota stop loses at most the items in flight.
- Re-running with the same run_id skips ids already in the file: finished work is never redone.
- `QuotaExceeded` (a pinned model ran out of RPM/daily quota) pauses the run: in-flight items
  finish, nothing new starts, and `run_dir/<run_id>.state.json` records status "paused" plus
  `resume_after` (e.g. midnight Pacific for the daily quota). Run again after that time.
- Any other exception is recorded as a failed item and the run continues.

Result lines: {"id", "status": "ok", "result": {...}, "ts"} or {"id", "status": "error", "error", "ts"}.
"""
from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
import re
from collections import deque
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel

from firewall.resilience.budget import QuotaExceeded, atomic_write_text

log = logging.getLogger(__name__)

_RUN_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


class RunStatus(BaseModel):
    run_id: str
    total: int
    done: int
    failed: int
    status: Literal["completed", "paused", "failed"]
    resume_after: datetime | None = None
    results_path: str
    error: str | None = None          # why the run paused or failed


class CheckpointedRunner:
    def __init__(self, run_dir: Path | str, run_id: str) -> None:
        if not isinstance(run_id, str) or not _RUN_ID_RE.fullmatch(run_id) or ".." in run_id:
            raise ValueError("run_id must be 1-128 chars of [A-Za-z0-9._-] (no path separators)")
        self.run_dir = Path(run_dir)
        self.run_id = run_id

    @property
    def results_path(self) -> Path:
        return self.run_dir / f"{self.run_id}.jsonl"

    @property
    def state_path(self) -> Path:
        return self.run_dir / f"{self.run_id}.state.json"

    def load_results(self) -> list[dict]:
        """Records from the results file, one per id (the latest line wins, e.g. a retried failure).
        Malformed lines (a torn last line after a crash) are skipped."""
        by_id: dict[str, dict] = {}
        if not self.results_path.exists():
            return []
        with open(self.results_path, encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    log.warning("%s:%d: skipping malformed line", self.results_path, lineno)
                    continue
                if isinstance(rec, dict) and "id" in rec:
                    by_id[str(rec["id"])] = rec
        return list(by_id.values())

    def load_state(self) -> dict | None:
        try:
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, ValueError):
            return None

    async def run(self, items: list[dict], fn: Callable[[dict], Awaitable[dict]], *,
                  id_key: str = "id", concurrency: int = 1, retry_failed: bool = False,
                  max_consecutive_failures: int | None = None) -> RunStatus:
        """Process `items` with `fn`, skipping ids already recorded.

        retry_failed: also re-run ids whose latest record is an error.
        max_consecutive_failures: stop with status "failed" after this many failures in a row
        (e.g. a bug or a dead endpoint), instead of recording an error for every remaining item.
        """
        ordered: list[tuple[str, dict]] = []
        seen: set[str] = set()
        for item in items:
            if not isinstance(item, dict) or id_key not in item:
                raise ValueError(f"every item needs an {id_key!r} key")
            key = str(item[id_key])
            if key not in seen:
                seen.add(key)
                ordered.append((key, item))

        self.run_dir.mkdir(parents=True, exist_ok=True)
        prior = {str(r["id"]): r for r in self.load_results()}
        queue = deque((k, it) for k, it in ordered
                      if k not in prior or (retry_failed and prior[k].get("status") == "error"))

        pause: QuotaExceeded | None = None
        abort: str | None = None
        consecutive = 0
        fh = self._open_for_append()

        def write(record: dict) -> None:
            fh.write(json.dumps(record, ensure_ascii=False, default=_json_default) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

        async def worker() -> None:
            nonlocal pause, abort, consecutive
            while queue and pause is None and abort is None:
                key, item = queue.popleft()
                try:
                    result = fn(item)
                    if inspect.isawaitable(result):
                        result = await result
                except QuotaExceeded as e:
                    if pause is None:
                        pause = e
                    return   # this item is not recorded: it runs again on resume
                except Exception as e:
                    write({"id": item[id_key], "status": "error",
                           "error": f"{type(e).__name__}: {e}"[:2000], "ts": _now_iso()})
                    consecutive += 1
                    log.warning("run %s: item %s failed: %s: %s", self.run_id, key, type(e).__name__, e)
                    if max_consecutive_failures and consecutive >= max_consecutive_failures and abort is None:
                        abort = f"{consecutive} consecutive failures; last: {type(e).__name__}: {e}"[:2000]
                    continue
                if result is None:
                    result = {}
                elif not isinstance(result, dict):
                    result = {"value": result}
                write({"id": item[id_key], "status": "ok", "result": result, "ts": _now_iso()})
                consecutive = 0

        try:
            tasks = [asyncio.create_task(worker()) for _ in range(max(1, int(concurrency)))]
            try:
                await asyncio.gather(*tasks)
            except BaseException:
                for t in tasks:
                    t.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                raise
        finally:
            fh.close()

        if pause is not None:
            status, resume_after, error = "paused", pause.resume_after, str(pause)
        elif abort is not None:
            status, resume_after, error = "failed", None, abort
        else:
            status, resume_after, error = "completed", None, None
        return self._finish(ordered, status, resume_after, error)

    # ---- internals ----
    def _open_for_append(self):
        path = self.results_path
        needs_newline = False
        if path.exists() and path.stat().st_size > 0:
            with open(path, "rb") as fh:
                fh.seek(-1, os.SEEK_END)
                needs_newline = fh.read(1) != b"\n"   # torn last line from a crash
        fh = open(path, "a", encoding="utf-8")
        if needs_newline:
            fh.write("\n")
            fh.flush()
        return fh

    def _finish(self, ordered: list[tuple[str, dict]], status: str, resume_after: datetime | None,
                error: str | None) -> RunStatus:
        latest = {str(r["id"]): r for r in self.load_results()}
        done = sum(1 for k, _ in ordered if k in latest and latest[k].get("status") != "error")
        failed = sum(1 for k, _ in ordered if k in latest and latest[k].get("status") == "error")
        run_status = RunStatus(run_id=self.run_id, total=len(ordered), done=done, failed=failed,
                               status=status, resume_after=resume_after,
                               results_path=str(self.results_path), error=error)
        state = run_status.model_dump(mode="json")
        state.update(remaining=len(ordered) - done - failed, updated_at=_now_iso())
        atomic_write_text(self.state_path, json.dumps(state, indent=1))
        return run_status


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_default(obj: Any) -> Any:
    if isinstance(obj, BaseModel):
        return obj.model_dump(mode="json")
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, (set, frozenset, tuple)):
        return list(obj)
    return str(obj)


def load_results(run_dir: Path | str, run_id: str) -> list[dict]:
    """Module-level helper: `CheckpointedRunner(run_dir, run_id).load_results()`."""
    return CheckpointedRunner(run_dir, run_id).load_results()


__all__ = ["RunStatus", "CheckpointedRunner", "load_results"]
