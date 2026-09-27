"""Reliability check (SPEC §1(d), §17): run the same fixed set of items through the full firewall
3 times, caches off, and measure:
  - verdict agreement: fraction of items whose verdict was identical across all runs (target >= 95%)
  - schema-valid rate: fraction of calls that returned a schema-valid response, not an error (target 100%)
  - re-scan pass rate: of items released as allow_sanitized, the fraction whose output passed the
    post-sanitize re-scan (target 100%)

SPEC §17 calls this "50 reviewed items". This repo has no separate hold/review-queue registry to draw
from, so the default is the first 50 items (by id, for a stable/reproducible sample) of the dev split --
pass --file to point at a specific reviewed set if one exists, or --i-am-freezing --split test only at
freeze, once the recall run is already done (this does not affect the recall/FPR numbers either way; it
only checks how consistent repeated verdicts are on whatever items you give it).

  python -m eval.reliability                         # 50 dev-split items, 3 runs
  python -m eval.reliability --n 50 --runs 3 --file data/samples/core.jsonl

Writes eval/results/reliability.json, which eval/report.py's d_claim() reads for the (d) check.
Each run makes real Gemini calls (VERDICT_CACHE is forced off inside run_full) -- budget ~n * runs calls.
"""
from __future__ import annotations

import argparse
import asyncio
import json

from eval.run_eval import RESULTS, load_items, run_full


def pick_items(split: str, files: list[str] | None, n: int, allow_test: bool) -> list[dict]:
    items = load_items(split, files, allow_test)
    items = sorted(items, key=lambda it: it["id"])
    if len(items) < n:
        raise SystemExit(f"only {len(items)} items available on split={split!r} — widen --file or lower --n")
    return items[:n]


async def main_async(split: str, files: list[str] | None, n: int, runs: int, allow_test: bool) -> None:
    items = pick_items(split, files, n, allow_test)

    passes: list[dict[str, dict]] = []
    for r in range(runs):
        rows, status = await run_full(items, run_id=f"reliability_r{r + 1}")
        passes.append({row["id"]: row for row in rows})
        if status["status"] != "completed":
            print(f"run {r + 1}/{runs}: {status['status']} ({status.get('error')}), "
                  f"resume_after={status.get('resume_after')} -- re-run this exact command later; "
                  f"finished items are checkpointed under eval/results/runs/reliability_r{r + 1}.jsonl")

    # Score only items every run actually finished (a paused run leaves some missing) --
    # never invent a verdict for an item that wasn't scored.
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

    n_scored = len(common_ids)
    out = {
        "n_requested": n,
        "runs": runs,
        "n_scored": n_scored,
        "schema_valid_rate": round(finished_calls / requested_calls, 4) if requested_calls else None,
        "agreement": {"k": unanimous, "n": n_scored,
                      "rate": round(unanimous / n_scored, 4) if n_scored else None},
        "rescan_pass_rate": round(verify_passed / verify_total, 4) if verify_total else None,
        "rescan_n": verify_total,
        "complete": n_scored == n,   # False if any run paused before finishing all n items
    }
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "reliability.json").write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))
    print(f"\nwritten {RESULTS / 'reliability.json'}"
          + ("" if out["complete"] else "  -- INCOMPLETE, re-run the same command to finish"))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="dev", choices=["dev", "test", "all"])
    ap.add_argument("--file", action="append")
    ap.add_argument("--n", type=int, default=50)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--i-am-freezing", action="store_true", dest="allow_test",
                     help="required to point this at the test split")
    a = ap.parse_args()
    asyncio.run(main_async(a.split, a.file, a.n, a.runs, a.allow_test))


if __name__ == "__main__":
    main()
