"""Blue-team patch validator (SPEC §14): a proposed pattern is accepted only if it compiles, is
ReDoS-safe, catches its cluster, and matches ZERO benign dev items.
"""
from __future__ import annotations

import regex

from firewall.detection.heuristics import CATEGORIES, CATEGORY_FLAGS  # noqa: F401

REDOS_PROBES = ["a" * 20000, " " * 20000, "<|" * 8000, "ignore " * 3000, "[" * 20000]
REDOS_BUDGET_S = 0.05


def validate_pattern(pat: dict, cluster_texts: list[str], benign_texts: list[str]) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    for key in ("id", "category", "types", "weight", "regex", "example_positive", "example_negative"):
        if key not in pat:
            reasons.append(f"missing field {key}")
    if reasons:
        return False, reasons
    if pat["category"] not in CATEGORIES:
        reasons.append(f"unknown category {pat['category']}")
    if not (0.1 <= pat["weight"] <= 0.9):
        reasons.append("weight out of range 0.1-0.9")
    try:
        rx = regex.compile(pat["regex"], regex.IGNORECASE | regex.V1)
    except regex.error as e:
        return False, [f"invalid regex: {e}"]
    for probe in REDOS_PROBES:
        try:
            rx.search(probe, timeout=REDOS_BUDGET_S)
        except TimeoutError:
            return False, ["ReDoS: pattern too slow on adversarial input"]
    if not rx.search(pat["example_positive"]):
        reasons.append("does not match its example_positive")
    if rx.search(pat["example_negative"]):
        reasons.append("matches its example_negative")
    caught = sum(bool(rx.search(t, timeout=REDOS_BUDGET_S)) for t in cluster_texts)
    if cluster_texts and caught == 0:
        reasons.append("catches none of its cluster")
    fp = [t for t in benign_texts if rx.search(t, timeout=REDOS_BUDGET_S)]
    if fp:
        reasons.append(f"matches {len(fp)} benign dev item(s) — must be zero")
    return (not reasons), reasons or [f"ok: catches {caught}/{len(cluster_texts)} of the cluster, 0 benign"]
