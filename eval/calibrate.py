"""Threshold calibration (SPEC §14, Should) — DEV SPLIT ONLY (CLAUDE.md rule 5).

Sweeps C_REVIEW / H_REVIEW on the deterministic layer and reports recall vs benign fast-block for each,
so you can pick thresholds before the expensive judge runs. Never reads the test split.

  python -m eval.calibrate
"""
from __future__ import annotations

import json

from firewall.config import ROOT, get_settings
from firewall.detection.ensemble import signals
from firewall.gate import Thresholds, gate

RESULTS = ROOT / "eval" / "results"


def main() -> None:
    from eval.run_eval import to_request
    from eval.splits import SAMPLES, get_split
    from firewall.pipeline import Firewall
    s = get_settings()
    fw = Firewall(s)
    if fw.bank:
        fw.bank.load()
    items = [i for f in sorted(SAMPLES.glob("*.jsonl")) for i in get_split("dev", f)]
    # precompute detector signals once
    precomputed = []
    for it in items:
        text = (it.get("turns") or [it.get("text")])[-1]
        parsed, _ = fw._parse(to_request(it, text))
        ens = fw.ensemble.run(parsed, it["source"])
        precomputed.append((it, signals(ens, it["source"])))
    fw.close()

    grid = []
    for cr in (0.2, 0.3, 0.4, 0.5):
        for hr in (0.2, 0.3, 0.4):
            t = Thresholds.from_settings(s.model_copy(update={"C_REVIEW": cr, "H_REVIEW": hr}))
            atk = ben = caught = fp = 0
            for it, sig in precomputed:
                g = gate(sig, False, untrusted_always_review=s.UNTRUSTED_ALWAYS_REVIEW, t=t)
                if it["label"] == "attack":
                    atk += 1
                    caught += g.route != "pass_fast"
                else:
                    ben += 1
                    fp += g.route == "block_fast"
            grid.append({"C_REVIEW": cr, "H_REVIEW": hr, "recall": round(caught / atk, 3) if atk else None,
                         "benign_fast_block": round(fp / ben, 3) if ben else None})
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "calibration.json").write_text(json.dumps(grid, indent=1))
    print(f"{'C_REVIEW':>9} {'H_REVIEW':>9} {'recall':>8} {'benign_fast_block':>18}")
    for g in grid:
        print(f"{g['C_REVIEW']:>9} {g['H_REVIEW']:>9} {g['recall']:>8} {g['benign_fast_block']:>18}")
    print(f"\nwritten {RESULTS / 'calibration.json'} (dev split only)")


if __name__ == "__main__":
    main()
