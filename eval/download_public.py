"""Public evaluation sets (SPEC §17) → data/public/<name>.jsonl in the eval format (eval/datasets.py).

  python -m eval.download_public            # all
  python -m eval.download_public dolly      # one

UNVERIFIED: written in a sandbox without HuggingFace access. Before the first run, Claude Code must check
each dataset id, split, column names and license on its card, and update SOURCES + docs/DECISIONS.md.
BIPIA is distributed via GitHub (microsoft/BIPIA), not the Hub, so it has a separate loader stub.
Samples are deterministic (seed 7). data/public/ is gitignored.
"""
from __future__ import annotations

import json
import random
import sys

from firewall.config import ROOT

OUT = ROOT / "data" / "public"

# name: (hub id, split, text column, label, types, source, sample size)   ← verify every field
SOURCES = {
    "gandalf": ("Lakera/gandalf_ignore_instructions", "train", "text", "attack", [1, 3], "user", 300),
    "notinject": ("leolee99/NotInject", "train", "prompt", "benign", [], "user", 339),
    "dolly": ("databricks/databricks-dolly-15k", "train", "instruction", "benign", [], "user", 300),
}


def fetch(name: str) -> int:
    from datasets import load_dataset   # 'eval' dependency group
    hub_id, split, col, label, types, source, n = SOURCES[name]
    ds = load_dataset(hub_id, split=split)
    if col not in ds.column_names:
        raise SystemExit(f"{name}: column {col!r} not in {ds.column_names}; update SOURCES")
    idx = list(range(len(ds)))
    random.Random(7).shuffle(idx)
    OUT.mkdir(parents=True, exist_ok=True)
    kept = 0
    with open(OUT / f"{name}.jsonl", "w", encoding="utf-8") as f:
        for i in idx:
            text = str(ds[i][col] or "").strip()
            if not text or len(text) > 4000:
                continue
            f.write(json.dumps({"id": f"{name}-{i}", "text": text, "label": label, "types": types, "source": source,
                                "group": f"public:{name}", "lang": "en"}, ensure_ascii=False) + "\n")
            kept += 1
            if kept >= n:
                break
    print(f"{name}: {kept} items → {OUT / (name + '.jsonl')}")
    return kept


def fetch_bipia() -> None:
    raise SystemExit("BIPIA: clone github.com/microsoft/BIPIA, check its license, then map ~200 email/web "
                     "items (attack + clean context) into data/public/bipia.jsonl with source='retrieved'.")


def main() -> None:
    names = sys.argv[1:] or list(SOURCES)
    for n in names:
        fetch_bipia() if n == "bipia" else fetch(n)
    print("Contamination check: C1 (protectai v2) lists its training sources on the model card; exclude any "
          "overlapping set from C1-only claims and note it in the report.")


if __name__ == "__main__":
    main()
