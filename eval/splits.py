"""Stratified dev/test split (SPEC §17). The test split is locked until Slice 7 (CLAUDE.md rule 5).

Deterministic: an item's split depends only on sha256(id), stratified by (label, group), 60/40.
"""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path

from firewall.config import ROOT

SAMPLES = ROOT / "data" / "samples"
DEV_FRACTION = 0.60


def load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def split(items: list[dict], dev_fraction: float = DEV_FRACTION) -> dict[str, list[dict]]:
    strata: dict[tuple, list[dict]] = defaultdict(list)
    for it in items:
        strata[(it.get("label"), it.get("group"))].append(it)
    out: dict[str, list[dict]] = {"dev": [], "test": []}
    for _, group in sorted(strata.items(), key=lambda kv: str(kv[0])):
        group = sorted(group, key=lambda it: hashlib.sha256(it["id"].encode()).hexdigest())
        n_dev = round(len(group) * dev_fraction)
        out["dev"] += group[:n_dev]
        out["test"] += group[n_dev:]
    return out


def get_split(name: str, path: Path | None = None, *, allow_test: bool = False) -> list[dict]:
    if name == "test" and not allow_test:
        raise PermissionError("the test split is locked until Slice 7 (pass allow_test=True at freeze)")
    items = load(path or SAMPLES / "smoke.jsonl")
    if name == "all":
        return items
    return split(items)[name]
