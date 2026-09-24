"""Unicode script detection for the uncovered_script rule (SPEC §7.4)."""
from __future__ import annotations

import unicodedata
from functools import lru_cache
from typing import Iterable

_NAME_MAP = {"CJK": "Han", "ORIYA": "Oriya"}


@lru_cache(maxsize=65536)
def script_of(ch: str) -> str | None:
    if not unicodedata.category(ch).startswith("L"):
        return None
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return None
    words = name.split()
    if words[0] in ("FULLWIDTH", "HALFWIDTH", "MATHEMATICAL") or "LATIN" in words[:3]:
        if "LATIN" in words or words[0] == "MATHEMATICAL":
            return "Latin"
        if words[0] in ("HALFWIDTH", "FULLWIDTH") and len(words) > 1:
            return words[1].title()
    first = words[0]
    if first in _NAME_MAP:
        return _NAME_MAP[first]
    return first.title()


def script_counts(text: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for ch in text:
        s = script_of(ch)
        if s:
            out[s] = out.get(s, 0) + 1
    return out


def scripts_present(texts: Iterable[str], min_letters: int = 20) -> list[str]:
    total: dict[str, int] = {}
    for t in texts:
        for k, v in script_counts(t).items():
            total[k] = total.get(k, 0) + v
    return sorted(k for k, v in total.items() if v >= min_letters)


def covered_scripts(setting: str, loaded_classifiers: Iterable[str]) -> set[str]:
    if setting.strip().lower() == "auto":
        cov = {"Latin"}
        if "c2_86m" in set(loaded_classifiers):
            cov.add("Devanagari")
        return cov
    return {s.strip() for s in setting.split(",") if s.strip()}


def uncovered(scripts: Iterable[str], covered: set[str]) -> list[str]:
    return sorted(s for s in scripts if s not in covered)
