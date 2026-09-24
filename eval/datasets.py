"""Sample-set format and coverage check (SPEC §17).

Every eval file is JSONL, one item per line:
  {"id": "core-t1-01", "text": "...", "label": "attack"|"benign", "types": [1], "source": "user"|"retrieved"|"uploaded",
   "group": "seed"|"mutation"|"ordinary"|"adversarial"|"india"|"indic"|"public:<name>", "lang": "en"|"hi"|"hinglish"|"ta"|"bn"|"te",
   "turns": ["...", "..."]   # optional: multi-turn conversation instead of "text"; the LAST turn is the one scored
  }

  python -m eval.datasets data/samples/core.jsonl     # coverage report vs the SPEC §17 targets
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

REQUIRED = {"id", "label", "source"}
TARGETS = {
    "seeds per attack type (1-9)": 10,
    "benign ordinary": 20,
    "benign adversarial": 10,
    "benign india": 10,
    "Hindi/Hinglish attacks": 10,
    "Tamil/Bengali/Telugu attacks": 10,
    "multi-turn attack conversations": 6,
    "multi-turn benign conversations": 6,
}


def validate(items: list[dict]) -> list[str]:
    errors, seen = [], set()
    for i, it in enumerate(items):
        miss = REQUIRED - it.keys()
        if miss:
            errors.append(f"line {i + 1}: missing {sorted(miss)}")
        if ("text" in it) == ("turns" in it):
            errors.append(f"line {i + 1}: exactly one of text / turns")
        if it.get("id") in seen:
            errors.append(f"line {i + 1}: duplicate id {it.get('id')}")
        seen.add(it.get("id"))
        if it.get("label") == "attack" and not it.get("types"):
            errors.append(f"line {i + 1}: attack without types")
        if it.get("label") not in ("attack", "benign"):
            errors.append(f"line {i + 1}: bad label")
        if it.get("source") not in ("user", "retrieved", "uploaded"):
            errors.append(f"line {i + 1}: bad source")
    return errors


def coverage(items: list[dict]) -> dict[str, tuple[int, int]]:
    atk = [i for i in items if i["label"] == "attack"]
    ben = [i for i in items if i["label"] == "benign"]
    per_type = Counter(t for i in atk if i.get("group") == "seed" for t in i["types"])
    got = {
        "seeds per attack type (1-9)": min(per_type.get(t, 0) for t in range(1, 10)),
        "benign ordinary": sum(i.get("group") == "ordinary" for i in ben),
        "benign adversarial": sum(i.get("group") == "adversarial" for i in ben),
        "benign india": sum(i.get("group") == "india" for i in ben),
        "Hindi/Hinglish attacks": sum(i.get("lang") in ("hi", "hinglish") for i in atk),
        "Tamil/Bengali/Telugu attacks": sum(i.get("lang") in ("ta", "bn", "te") for i in atk),
        "multi-turn attack conversations": sum("turns" in i for i in atk),
        "multi-turn benign conversations": sum("turns" in i for i in ben),
    }
    return {k: (got[k], TARGETS[k]) for k in TARGETS}


def load(path: str | Path) -> list[dict]:
    return [json.loads(x) for x in Path(path).read_text(encoding="utf-8").splitlines() if x.strip()]


def main() -> int:
    items = load(sys.argv[1])
    errs = validate(items)
    for e in errs:
        print("ERROR", e)
    for k, (g, t) in coverage(items).items():
        print(f"[{'ok' if g >= t else '--'}] {k}: {g}/{t}")
    return 1 if errs else 0


if __name__ == "__main__":
    raise SystemExit(main())
