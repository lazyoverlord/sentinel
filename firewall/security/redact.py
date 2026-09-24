"""Log/audit redaction (SPEC §13): replace DLP hits (API keys, tokens, PII, canaries) with
"[REDACTED:<kind>]" before anything is written to logs, the audit trail or session excerpts.

The detector is pluggable: `finder(text, canaries) -> [{"kind", "start", "end"}, ...]`. The default
is `firewall.detection.dlp.find`, imported lazily so this module has no hard dependency on it.
Fail closed: if the detector is missing or raises, the text is withheld entirely rather than
logged raw.
"""
from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from pydantic import BaseModel

log = logging.getLogger(__name__)

WITHHELD = "[REDACTED:unavailable]"
MIN_LITERAL_CANARY = 8   # registered canaries shorter than this aren't literal-replaced
MAX_DEPTH = 64           # redact_obj recursion limit (hostile nesting)
_KIND_UNSAFE = re.compile(r"[^A-Za-z0-9_.-]+")
_PLACEHOLDER = "[REDACTED:"

Finder = Callable[[str, tuple[str, ...]], Iterable[Any]]


def redact(text: str, *, canaries: Iterable[str] = (), finder: Finder | None = None) -> str:
    """Replace each DLP hit in `text` with "[REDACTED:<kind>]". Overlapping hits are merged."""
    if not text or not isinstance(text, str):
        return text
    cans = _canaries(canaries)
    find = finder if finder is not None else _default_finder()
    if find is None:
        return WITHHELD
    try:
        hits = list(find(text, cans) or [])
    except Exception:  # never log raw text because the detector broke
        log.warning("DLP finder raised; withholding text from logs", exc_info=True)
        return WITHHELD

    spans: list[tuple[int, int, str]] = []
    for hit in hits:
        try:
            start, end = int(_field(hit, "start")), int(_field(hit, "end"))
        except (TypeError, ValueError):
            continue
        start, end = max(0, start), min(len(text), end)
        if start < end:
            spans.append((start, end, _kind(_field(hit, "kind"))))
    spans.sort(key=lambda s: (s[0], -s[1]))

    merged: list[tuple[int, int, str]] = []
    for start, end, kind in spans:
        if merged and start < merged[-1][1]:
            prev_start, prev_end, prev_kind = merged[-1]
            merged[-1] = (prev_start, max(prev_end, end), prev_kind)
        else:
            merged.append((start, end, kind))

    parts: list[str] = []
    pos = 0
    for start, end, kind in merged:
        parts.append(text[pos:start])
        parts.append(f"{_PLACEHOLDER}{kind}]")
        pos = end
    parts.append(text[pos:])
    result = "".join(parts)

    # Belt and braces: registered canaries are replaced literally even if the finder missed them.
    for token in sorted(cans, key=len, reverse=True):
        if len(token) >= MIN_LITERAL_CANARY and token in result:
            result = result.replace(token, f"{_PLACEHOLDER}canary]")
    return result


def excerpt(text: str, n: int = 200, **kw: Any) -> str:
    """Redact, then truncate to at most n characters (ending in "…" when cut).

    Redaction runs on the full text first, so a secret straddling the cut is still caught.
    A cut never splits a "[REDACTED:...]" placeholder.
    """
    if not text or n <= 0:
        return ""
    red = redact(text, **kw)
    if len(red) <= n:
        return red
    cut = n - 1
    open_at = red.rfind(_PLACEHOLDER, 0, cut)
    if open_at != -1:
        close_at = red.find("]", open_at)
        if close_at == -1 or close_at >= cut:
            cut = open_at
    return red[:cut].rstrip() + "…"


def redact_obj(obj: Any, **kw: Any) -> Any:
    """Recursively redact every string value in dicts / lists / tuples / sets / pydantic models.

    Returns new containers (the input is not mutated); dict keys and non-string leaves are kept.
    """
    kw = dict(kw)
    kw["canaries"] = _canaries(kw.get("canaries", ()))
    if kw.get("finder") is None:
        kw["finder"] = _default_finder() or _withhold
    return _walk(obj, kw, 0)


# ---------------- internals ----------------

def _walk(obj: Any, kw: dict[str, Any], depth: int) -> Any:
    if isinstance(obj, str):
        return redact(obj, **kw)
    if depth >= MAX_DEPTH:
        return f"{_PLACEHOLDER}depth]"
    if isinstance(obj, BaseModel):
        obj = obj.model_dump(mode="json")
    if isinstance(obj, Mapping):
        return {k: _walk(v, kw, depth + 1) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_walk(v, kw, depth + 1) for v in obj]
    if isinstance(obj, tuple):
        return tuple(_walk(v, kw, depth + 1) for v in obj)
    if isinstance(obj, (set, frozenset)):
        return type(obj)(_walk(v, kw, depth + 1) for v in obj)
    return obj


def _default_finder() -> Finder | None:
    try:
        from firewall.detection.dlp import find  # lazy: dlp is optional at import time
    except Exception:
        log.warning("firewall.detection.dlp unavailable; withholding text from logs", exc_info=True)
        return None
    return find


def _withhold(text: str, canaries: tuple[str, ...]) -> list[dict]:
    """Finder used when no detector is importable: one hit covering the whole text."""
    return [{"kind": "unavailable", "start": 0, "end": len(text)}]


def _canaries(canaries: Iterable[str] | None) -> tuple[str, ...]:
    if not canaries:
        return ()
    if isinstance(canaries, str):
        canaries = (canaries,)
    return tuple(c for c in canaries if isinstance(c, str) and c)


def _field(hit: Any, name: str) -> Any:
    if isinstance(hit, Mapping):
        return hit.get(name)
    return getattr(hit, name, None)


def _kind(kind: Any) -> str:
    return _KIND_UNSAFE.sub("_", str(kind or "secret"))[:40] or "secret"


__all__ = ["redact", "excerpt", "redact_obj", "WITHHELD"]
