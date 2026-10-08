"""Reliability check (SPEC §1(d), §17): run the same fixed set of items through the full firewall
3 times, both verdict cache and dev cache off (independent judge calls each run), and measure:
  - verdict agreement: fraction of items whose verdict was identical across all runs (target >= 95%)
  - schema-valid rate: fraction of calls that returned a schema-valid response, not an error (target 100%)
  - re-scan pass rate: of items released as allow_sanitized, the fraction whose output passed the
    post-sanitize re-scan (target 100%)

SPEC §17 calls this "50 reviewed items". The default selection picks the first 50 dev-split items
(by id) that reached the judge in the dev full run (llm_calls > 0), preferring allow_sanitized
items. Pass --file to point at a specific reviewed set, or --i-am-freezing --split test at freeze.

  python -m eval.reliability                         # resume paused runs or start fresh
  python -m eval.reliability --fresh                 # force clear all checkpoints and restart
  python -m eval.reliability --n 50 --runs 3 --file data/samples/core.jsonl

Writes eval/results/reliability.json, which eval/report.py's d_claim() reads for the (d) check.
Each run makes real Gemini calls (VERDICT_CACHE and DEV_CACHE are both forced off) -- budget ~n * runs calls.
Inter-item pacing keeps calls under the judge model's RPM limit.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time

from eval.run_eval import RESULTS, load_items, run_full
from firewall.config import get_settings

RUN_DIR = RESULTS / "runs"


def _clear_checkpoints(runs: int) -> int:
    """Delete prior reliability checkpoint files. Returns count of files removed."""
    removed = 0
    for r in range(runs):
        for suffix in (".jsonl", ".state.json"):
            p = RUN_DIR / f"reliability_r{r + 1}{suffix}"
            if p.exists():
                p.unlink()
                removed += 1
    return removed


def _group_status(runs: int) -> str:
    """Return the group status across all runs: 'none', 'partial', or 'all_complete'."""
    has_any = False
    all_complete = True
    for r in range(runs):
        state_path = RUN_DIR / f"reliability_r{r + 1}.state.json"
        if not state_path.exists():
            all_complete = False
            continue
        has_any = True
        state = json.loads(state_path.read_text())
        if state.get("status") != "completed":
            all_complete = False
    if not has_any:
        return "none"
    return "all_complete" if all_complete else "partial"


def pick_items(split: str, files: list[str] | None, n: int, allow_test: bool) -> list[dict]:
    items = load_items(split, files, allow_test)

    if files is not None:
        items = sorted(items, key=lambda it: it["id"])
        if len(items) < n:
            raise SystemExit(f"only {len(items)} items available — widen --file or lower --n")
        return items[:n]

    full_run_path = RESULTS / f"full_{split}.json"
    if full_run_path.exists():
        full_data = json.loads(full_run_path.read_text())
        full_rows = {r["id"]: r for r in full_data.get("rows", [])}
        sanitized = sorted(
            [it for it in items if full_rows.get(it["id"], {}).get("action") == "allow_sanitized"],
            key=lambda it: it["id"],
        )
        reviewed = sorted(
            [it for it in items
             if full_rows.get(it["id"], {}).get("llm_calls", 0) > 0
             and full_rows.get(it["id"], {}).get("action") != "allow_sanitized"],
            key=lambda it: it["id"],
        )
        selected_ids: set[str] = set()
        selected: list[dict] = []
        for it in sanitized:
            if len(selected) >= n:
                break
            selected.append(it)
            selected_ids.add(it["id"])
        for it in reviewed:
            if len(selected) >= n:
                break
            if it["id"] not in selected_ids:
                selected.append(it)
                selected_ids.add(it["id"])
        if len(selected) < n:
            print(f"warning: only {len(selected)} judge-reviewed items in full_{split}.json "
                  f"(need {n}); using all available", file=sys.stderr)
        if not selected:
            raise SystemExit(f"no judge-reviewed items in full_{split}.json — run the full eval first")
        return selected

    items = sorted(items, key=lambda it: it["id"])
    if len(items) < n:
        raise SystemExit(f"only {len(items)} items available on split={split!r} — widen --file or lower --n")
    return items[:n]


def _judge_rpm() -> int:
    s = get_settings()
    return s.RPM_LIMITS.get(s.JUDGE_MODEL, 10)


async def main_async(split: str, files: list[str] | None, n: int, runs: int,
                     allow_test: bool, fresh: bool) -> None:
    items = pick_items(split, files, n, allow_test)

    if fresh:
        removed = _clear_checkpoints(runs)
        if removed:
            print(f"--fresh: cleared {removed} checkpoint files", file=sys.stderr)
    else:
        gs = _group_status(runs)
        if gs == "all_complete":
            removed = _clear_checkpoints(runs)
            if removed:
                print(f"prior runs all completed; cleared {removed} checkpoint files for fresh start",
                      file=sys.stderr)
        elif gs == "partial":
            print("resuming from prior checkpoints (use --fresh to force restart)", file=sys.stderr)
        # gs == "none": nothing to clear or resume

    rpm = _judge_rpm()
    interval = 60.0 / rpm if rpm > 0 else 5.0

    passes: list[dict[str, dict]] = []
    for r in range(runs):
        t0 = time.monotonic()
        rows, status = await run_full(items, run_id=f"reliability_r{r + 1}", dev_cache=False)
        passes.append({row["id"]: row for row in rows})
        elapsed = time.monotonic() - t0
        print(f"run {r + 1}/{runs}: {status['status']} ({len(rows)} items, {elapsed:.0f}s)",
              file=sys.stderr)
        if status["status"] != "completed":
            print(f"  resume_after={status.get('resume_after')} -- re-run this exact command later; "
                  f"finished items are checkpointed under eval/results/runs/reliability_r{r + 1}.jsonl",
                  file=sys.stderr)
        if r < runs - 1:
            print(f"  pacing: sleeping {interval:.1f}s before next run", file=sys.stderr)
            await asyncio.sleep(interval)

    common_ids = set.intersection(*(set(p) for p in passes)) if passes else set()
    requested_calls = n * runs
    finished_calls = sum(len(p) for p in passes)

    unanimous = 0
    verify_total = verify_passed = 0
    for iid in common_ids:
        verdicts = [p[iid]["verdict"] for p in passes]
        if len(set(verdicts)) == 1:
            unanimous += 1
        for p in passes:
            row = p[iid]
            if row.get("action") == "allow_sanitized":
                verify_total += 1
                verify_passed += int(bool(row.get("verify_passed")))

    real_llm_total = sum(p[iid].get("real_llm_calls", 0) for p in passes for iid in common_ids)
    n_scored = len(common_ids)
    out: dict = {
        "n_requested": n,
        "runs": runs,
        "n_scored": n_scored,
        "dev_cache": False,
        "real_llm_calls": real_llm_total,
        "schema_valid_rate": round(finished_calls / requested_calls, 4) if requested_calls else None,
        "agreement": {"k": unanimous, "n": n_scored,
                      "rate": round(unanimous / n_scored, 4) if n_scored else None},
        "rescan_pass_rate": round(verify_passed / verify_total, 4) if verify_total else None,
        "rescan_n": verify_total,
        "rescan_exercised": verify_total > 0,
        "complete": n_scored == n,
    }

    if real_llm_total == 0:
        print(json.dumps(out, indent=2), file=sys.stderr)
        raise SystemExit("FATAL: real_llm_calls == 0 — judge was never called (stale cache or all items "
                         "fast-pathed). reliability.json NOT written.")

    if n_scored < n:
        print(json.dumps(out, indent=2), file=sys.stderr)
        raise SystemExit(f"FATAL: n_scored={n_scored} < n={n} — not enough items completed. "
                         f"reliability.json NOT written. Re-run to resume.")

    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "reliability.json").write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))
    print(f"\nwritten {RESULTS / 'reliability.json'}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="dev", choices=["dev", "test", "all"])
    ap.add_argument("--file", action="append")
    ap.add_argument("--n", type=int, default=50)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--fresh", action="store_true",
                    help="clear prior checkpoints and start from scratch")
    ap.add_argument("--i-am-freezing", action="store_true", dest="allow_test",
                     help="required to point this at the test split")
    a = ap.parse_args()
    asyncio.run(main_async(a.split, a.file, a.n, a.runs, a.allow_test, a.fresh))


if __name__ == "__main__":
    main()
