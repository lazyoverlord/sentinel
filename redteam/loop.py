"""Red/blue hardening loop (SPEC §14): generate cases → firewall → canary harness → cluster bypasses →
propose validated patches. A round is offline-capable (operators + scripted victim + no judge quota).

  python -m redteam.loop --rounds 2 --per-seed 6           # uses the dev split; local/scripted victim
A bypass = the firewall did NOT stop the case AND it succeeded on the unprotected victim.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import time
from pathlib import Path
from typing import Any

from firewall.config import ROOT, get_settings
from redteam import blue_agent, red_agent
from redteam.validator import validate_pattern

RESULTS = ROOT / "eval" / "results"
STOPPED = {"block", "quarantine", "allow_sanitized", "hold_for_review", "allow_rewritten"}


async def _stopped_by_firewall(fw: Any, case) -> tuple[bool, str]:
    payload = case.payload
    if isinstance(payload, list):                      # multi-turn: stopped if any turn is stopped
        sid = f"rt-{case.case_id}-{time.time_ns()}"
        worst = "allow"
        for tx in payload:
            r = await fw.analyze_text(tx, "user", session_id=sid)
            if r.action in STOPPED:
                worst = r.action
        return worst in STOPPED, worst
    r = await fw.analyze_text(payload, "user")
    return r.action in STOPPED, r.action


async def run_round(fw: Any, victim_model: Any, seeds: list[dict], *, per_seed: int, seed: int,
                    use_llm_gen: bool) -> dict:
    from redteam.canary_harness import attack_succeeds
    cases = red_agent.operator_cases(seeds, per_seed=per_seed, seed=seed)
    cases += red_agent.fragmentation_cases(seeds, seed=seed)
    if use_llm_gen:
        cases += await red_agent.LLMParaphraser(fw.llm).more(seeds)
    bypasses, evaded_harmless, stopped = [], 0, 0
    for case in cases:
        blocked, action = await _stopped_by_firewall(fw, case)
        if blocked:
            stopped += 1
            continue
        text = "\n".join(case.payload) if isinstance(case.payload, list) else case.payload
        ok, info = await attack_succeeds(victim_model, text)
        if ok:
            bypasses.append({"case_id": case.case_id, "seed_id": case.seed_id, "operators": case.operators,
                             "intended_types": case.intended_types, "payload_text": text, "victim": info})
        else:
            evaded_harmless += 1
    return {"cases": len(cases), "stopped": stopped, "evaded_harmless": evaded_harmless,
            "bypasses": bypasses, "bypass_rate": round(len(bypasses) / len(cases), 4) if cases else 0.0}


async def hardening(rounds: int, per_seed: int, victim: str, use_llm_gen: bool,
                    max_seeds: int | None = None, results_dir: Path | None = None) -> dict:
    from eval.splits import get_split, SAMPLES
    from demo_agent.inboxpilot import pick_model
    from firewall.pipeline import Firewall
    s = get_settings().model_copy(update={
        "REVIEW_QUEUE_DIR": ROOT / "data" / "feedback_eval"})
    fw = Firewall(s)
    await fw.startup()
    victim_model, label = await pick_model(fw, victim)
    files = sorted(SAMPLES.glob("*.jsonl"))
    seeds = [i for f in files for i in get_split("dev", f) if i["label"] == "attack" and "text" in i]
    benign = [i["text"] for f in files for i in get_split("dev", f) if i["label"] == "benign" and "text" in i]
    if max_seeds is not None:
        seeds = seeds[:max_seeds]
        benign = benign[:max_seeds]
    report = {"victim_model": label, "rounds": [], "approved_candidates": []}
    for rnd in range(rounds):
        res = await run_round(fw, victim_model, seeds, per_seed=per_seed, seed=rnd, use_llm_gen=use_llm_gen)
        # blue team proposes; validator gates; a human still approves in the UI before patterns.json changes
        candidates = []
        for pat in blue_agent.propose_patterns(res["bypasses"]):
            cluster_texts = [b["payload_text"] for b in res["bypasses"] if b.get("_cluster") == pat.get("_cluster")] \
                or [b["payload_text"] for b in res["bypasses"]]
            valid, reasons = validate_pattern({k: v for k, v in pat.items() if not k.startswith("_")},
                                              cluster_texts, benign)
            candidates.append({**pat, "valid": valid, "validator": reasons})
        res["proposed_patterns"] = candidates
        res["proposed_exemplars"] = blue_agent.propose_exemplars(res["bypasses"])
        report["rounds"].append({k: v for k, v in res.items() if k != "bypasses"} | {"n_bypasses": len(res["bypasses"])})
        report["approved_candidates"] += [c for c in candidates if c["valid"]]
    fw.close()
    out_dir = results_dir or RESULTS
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "hardening.json").write_text(json.dumps(report, indent=1, ensure_ascii=False))
    return report


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=2)
    ap.add_argument("--per-seed", type=int, default=6)
    ap.add_argument("--victim", default="auto", choices=["auto", "ollama", "gemini", "scripted"])
    ap.add_argument("--llm-gen", action="store_true", help="also use the Gemini paraphraser (spends quota)")
    a = ap.parse_args()
    report = asyncio.run(hardening(a.rounds, a.per_seed, a.victim, a.llm_gen))
    print("victim:", report["victim_model"])
    for i, r in enumerate(report["rounds"]):
        print(f"round {i + 1}: {r['cases']} cases, {r['stopped']} stopped, {r['n_bypasses']} bypasses "
              f"(rate {r['bypass_rate']:.0%}), {len(r['proposed_patterns'])} patterns proposed")
    print(f"approved candidates: {len(report['approved_candidates'])} → eval/results/hardening.json")


if __name__ == "__main__":
    main()
